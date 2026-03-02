"""
FastAPI main application with all endpoints.
"""
from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import List, Optional
from datetime import timedelta
import csv
import json
import xml.etree.ElementTree as ET
import io

from .database import engine, get_db
from .models import Base, User
from .schemas import (
    RegistrationCheckRequest, RegistrationCheckResponse, RegistrationResponse,
    RegistrationListResponse, LoginRequest, TokenResponse, UserResponse,
    OverrideRequest, OverrideResponse, StatsResponse, FlaggedListResponse,
    BulkBlockRequest, BulkBlockResponse, AuditLogResponse, AuditLogListResponse,
    APIKeyResponse, ManualUpdateRequest, ManualUpdateResponse,
    BulkRegistrationRequest, BulkRegistrationResponse, BulkRegistrationResult
)
from .crud import (
    get_registration_by_email, get_registration_by_id, create_registration, get_registrations,
    get_flagged_registrations as get_flagged_registrations_crud, update_registration_status,
    bulk_update_registration_status, get_user_by_username, get_stats,
    create_audit_log, get_audit_logs, count_registrations_by_phone,
    hash_phone, normalize_phone, get_phone_registrations, get_blocked_registrations,
    generate_api_key, update_registration_flags
)
from .auth import verify_password, get_password_hash, create_access_token
from .dependencies import get_current_user, get_current_admin_user, get_current_user_or_api_key, limiter
from .utils import initialize_disposable_domains

# Create tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Email Abuse Detection API",
    description="Middleware API for detecting and preventing email abuse",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize on startup: load disposable domains and seed admin user."""
    initialize_disposable_domains()
    
    # Seed admin user if not exists
    db = next(get_db())
    admin_user = get_user_by_username(db, "admin")
    if not admin_user:
        admin_user = User(
            username="admin",
            hashed_password=get_password_hash("adminpass"),
            is_admin=True
        )
        db.add(admin_user)
        db.commit()
        print("Created default admin user: admin/adminpass")
    db.close()


# Public endpoints
@app.post("/check_registration", response_model=RegistrationCheckResponse)
@limiter.limit("10/minute")
async def check_registration(
    request: Request,
    registration_data: RegistrationCheckRequest,
    db: Session = Depends(get_db)
):
    """
    Check if a registration is allowed.
    
    Rules:
    - Max 3 registrations per phone number
    - Temporary emails are blocked
    - High spam score (>70) flags the registration
    """
    phone_normalized = normalize_phone(registration_data.phone)
    phone_hash_value = hash_phone(phone_normalized)
    
    # Check if email already exists
    existing = get_registration_by_email(db, registration_data.email)
    if existing:
        return RegistrationCheckResponse(
            allowed=False,
            email=registration_data.email,
            phone_hash=phone_hash_value,
            status=existing.status,
            is_temporary=existing.is_temporary,
            spam_score=existing.spam_score,
            is_flagged=existing.is_flagged,
            detection_notes=existing.detection_notes,
            message="Email already registered",
            registration_id=existing.id
        )
    
    # Check phone limit (max 3)
    count = count_registrations_by_phone(db, phone_hash_value)
    if count >= 3:
        # Create registration even if blocked to log it in dashboard
        registration = create_registration(
            db=db,
            email=registration_data.email,
            phone=registration_data.phone,
            status="blocked",
            detection_notes="Phone number limit exceeded (max 3 registrations)"
        )
        
        return RegistrationCheckResponse(
            allowed=False,
            email=registration.email,
            phone_hash=registration.phone_hash,
            status=registration.status,
            is_temporary=registration.is_temporary,
            spam_score=registration.spam_score,
            is_flagged=registration.is_flagged,
            detection_notes=registration.detection_notes,
            message="Maximum registrations (3) reached for this phone number",
            registration_id=registration.id
        )
    
    # Create registration (will detect temp/spam)
    registration = create_registration(
        db=db,
        email=registration_data.email,
        phone=registration_data.phone,
        status="approved" if count < 3 else "pending"
    )
    
    allowed = registration.status != "blocked"
    message = "Registration allowed" if allowed else "Registration blocked"
    if registration.is_temporary:
        message = "Temporary email detected and blocked"
    elif registration.is_flagged:
        message = f"Registration flagged (spam score: {registration.spam_score})"
    
    return RegistrationCheckResponse(
        allowed=allowed,
        email=registration.email,
        phone_hash=registration.phone_hash,
        status=registration.status,
        is_temporary=registration.is_temporary,
        spam_score=registration.spam_score,
        is_flagged=registration.is_flagged,
        detection_notes=registration.detection_notes,
        message=message,
        registration_id=registration.id
    )


# Authentication
@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT token."""
    user = get_user_by_username(db, login_data.username)
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    return TokenResponse(access_token=access_token)


# Protected endpoints
@app.get("/registrations", response_model=RegistrationListResponse)
async def list_registrations(
    page: int = 1,
    page_size: int = 50,
    phone_hash: str = None,
    status: str = None,
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get paginated list of registrations with optional filters."""
    try:
        skip = (page - 1) * page_size
        items, total = get_registrations(
            db=db,
            skip=skip,
            limit=page_size,
            phone_hash=phone_hash,
            status=status
        )
        
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        
        # Convert to response models safely
        registration_responses = []
        for item in items:
            try:
                registration_responses.append(RegistrationResponse.model_validate(item))
            except Exception as e:
                print(f"Error validating registration {item.id}: {str(e)}")
                continue
        
        return RegistrationListResponse(
            items=registration_responses,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in list_registrations: {str(e)}")
        print(error_details)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/override", response_model=OverrideResponse)
async def override_registration(
    override_data: OverrideRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Override registration status (admin only)."""
    # Get existing registration to capture old status
    existing_reg = get_registration_by_id(db, override_data.registration_id)
    if not existing_reg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Registration not found"
        )
    
    old_status = existing_reg.status
    
    registration = update_registration_status(
        db=db,
        registration_id=override_data.registration_id,
        status=override_data.status,
        detection_notes=f"Manual override by {current_user.username}: {override_data.reason}"
    )
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="override_status",
        details={
            "registration_id": override_data.registration_id,
            "old_status": old_status,
            "new_status": override_data.status,
            "reason": override_data.reason
        }
    )
    
    return OverrideResponse(
        success=True,
        registration=RegistrationResponse.model_validate(registration),
        message=f"Status updated to {override_data.status}"
    )


@app.post("/manual-update", response_model=ManualUpdateResponse)
async def manual_update_registration(
    update_data: ManualUpdateRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Manually update registration flags (spam, temporary, etc.) - admin only."""
    registration = get_registration_by_id(db, update_data.registration_id)
    if not registration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Registration not found"
        )
    
    # Build detection notes
    notes_parts = []
    if update_data.detection_notes:
        notes_parts.append(update_data.detection_notes)
    notes_parts.append(f"Manual update by {current_user.username}: {update_data.reason}")
    detection_notes = " | ".join(notes_parts)
    
    # Update registration flags
    registration = update_registration_flags(
        db=db,
        registration_id=update_data.registration_id,
        is_temporary=update_data.is_temporary,
        is_flagged=update_data.is_flagged,
        spam_score=update_data.spam_score,
        detection_notes=detection_notes,
        status=update_data.status
    )
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="manual_update",
        details={
            "registration_id": update_data.registration_id,
            "is_temporary": update_data.is_temporary,
            "is_flagged": update_data.is_flagged,
            "spam_score": update_data.spam_score,
            "status": update_data.status,
            "reason": update_data.reason
        }
    )
    
    return ManualUpdateResponse(
        success=True,
        registration=RegistrationResponse.model_validate(registration),
        message="Registration updated successfully"
    )


@app.get("/stats", response_model=StatsResponse)
async def get_statistics(
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get statistics about registrations."""
    try:
        stats = get_stats(db)
        return StatsResponse(**stats)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_statistics: {str(e)}")
        print(error_details)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/flagged", response_model=FlaggedListResponse)
async def get_flagged_registrations(
    page: int = 1,
    page_size: int = 50,
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get paginated list of flagged registrations."""
    try:
        skip = (page - 1) * page_size
        items, total = get_flagged_registrations_crud(db=db, skip=skip, limit=page_size)
        
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        
        # Convert to response models safely
        registration_responses = []
        for item in items:
            try:
                registration_responses.append(RegistrationResponse.model_validate(item))
            except Exception as e:
                # Log the error but continue with other items
                print(f"Error validating registration {item.id}: {str(e)}")
                continue
        
        return FlaggedListResponse(
            items=registration_responses,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
    except Exception as e:
        # Log the full error for debugging
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_flagged_registrations: {str(e)}")
        print(error_details)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/bulk_block", response_model=BulkBlockResponse)
async def bulk_block_registrations(
    bulk_data: BulkBlockRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Bulk block registrations (admin only)."""
    count = bulk_update_registration_status(
        db=db,
        registration_ids=bulk_data.registration_ids,
        status="blocked",
        detection_notes=f"Bulk blocked by {current_user.username}: {bulk_data.reason}"
    )
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="bulk_block",
        details={
            "registration_ids": bulk_data.registration_ids,
            "count": count,
            "reason": bulk_data.reason
        }
    )
    
    return BulkBlockResponse(
        success=True,
        blocked_count=count,
        message=f"Blocked {count} registration(s)"
    )


@app.post("/bulk_import", response_model=BulkRegistrationResponse)
async def bulk_import_registrations(
    bulk_data: BulkRegistrationRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Bulk import registrations (admin only).
    
    This endpoint bypasses rate limiting for bulk imports.
    Maximum 1000 registrations per request.
    """
    import time
    start_time = time.time()
    
    results = []
    successful = 0
    failed = 0
    
    for reg_data in bulk_data.registrations:
        try:
            phone_normalized = normalize_phone(reg_data.phone)
            phone_hash_value = hash_phone(phone_normalized)
            
            # Check if email already exists
            existing = get_registration_by_email(db, reg_data.email)
            if existing:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status=existing.status,
                    message="Email already registered",
                    registration_id=existing.id
                ))
                failed += 1
                continue
            
            # Check phone limit (max 3)
            count = count_registrations_by_phone(db, phone_hash_value)
            if count >= 3:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status="blocked",
                    message="Maximum registrations (3) reached for this phone number",
                    registration_id=None
                ))
                failed += 1
                continue
            
            # Create registration
            registration = create_registration(
                db=db,
                email=reg_data.email,
                phone=reg_data.phone,
                status="approved" if count < 3 else "pending"
            )
            
            allowed = registration.status != "blocked"
            message = "Registration allowed" if allowed else "Registration blocked"
            if registration.is_temporary:
                message = "Temporary email detected and blocked"
            elif registration.is_flagged:
                message = f"Registration flagged (spam score: {registration.spam_score})"
            
            results.append(BulkRegistrationResult(
                email=registration.email,
                phone=reg_data.phone,
                success=True,
                allowed=allowed,
                status=registration.status,
                message=message,
                registration_id=registration.id
            ))
            successful += 1
            
        except Exception as e:
            results.append(BulkRegistrationResult(
                email=reg_data.email,
                phone=reg_data.phone,
                success=False,
                allowed=False,
                status="error",
                message="Failed to process",
                error=str(e)
            ))
            failed += 1
    
    processing_time = time.time() - start_time
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="bulk_import",
        details={
            "total": len(bulk_data.registrations),
            "successful": successful,
            "failed": failed,
            "processing_time": processing_time
        }
    )
    
    return BulkRegistrationResponse(
        success=True,
        total=len(bulk_data.registrations),
        successful=successful,
        failed=failed,
        results=results,
        processing_time_seconds=round(processing_time, 2)
    )


def parse_csv_data(csv_content: str) -> List[RegistrationCheckRequest]:
    """Parse CSV content and return list of RegistrationCheckRequest."""
    registrations = []
    try:
        reader = csv.DictReader(io.StringIO(csv_content))
        for row in reader:
            if 'email' in row and 'phone' in row:
                email = row['email'].strip()
                phone = row['phone'].strip()
                if email and phone:
                    registrations.append(RegistrationCheckRequest(email=email, phone=phone))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSV format: {str(e)}")
    return registrations


def parse_json_data(json_content: str) -> List[RegistrationCheckRequest]:
    """Parse JSON content and return list of RegistrationCheckRequest."""
    try:
        data = json.loads(json_content)
        registrations = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'email' in item and 'phone' in item:
                    registrations.append(RegistrationCheckRequest(
                        email=item['email'].strip(),
                        phone=item['phone'].strip()
                    ))
        elif isinstance(data, dict):
            if 'registrations' in data:
                for item in data['registrations']:
                    if isinstance(item, dict) and 'email' in item and 'phone' in item:
                        registrations.append(RegistrationCheckRequest(
                            email=item['email'].strip(),
                            phone=item['phone'].strip()
                        ))
            else:
                # Single registration object
                if 'email' in data and 'phone' in data:
                    registrations.append(RegistrationCheckRequest(
                        email=data['email'].strip(),
                        phone=data['phone'].strip()
                    ))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing JSON: {str(e)}")
    return registrations


def parse_xml_data(xml_content: str) -> List[RegistrationCheckRequest]:
    """Parse XML content and return list of RegistrationCheckRequest."""
    registrations = []
    try:
        root = ET.fromstring(xml_content)
        
        # Try different XML structures
        # Format 1: <registration><email>...</email><phone>...</phone></registration>
        for registration in root.findall('.//registration'):
            email_elem = registration.find('email')
            phone_elem = registration.find('phone')
            if email_elem is not None and phone_elem is not None:
                email = email_elem.text.strip() if email_elem.text else ''
                phone = phone_elem.text.strip() if phone_elem.text else ''
                if email and phone:
                    registrations.append(RegistrationCheckRequest(email=email, phone=phone))
        
        # Format 2: <item email="..." phone="..."/>
        if not registrations:
            for item in root.findall('.//item'):
                email = item.get('email', '').strip()
                phone = item.get('phone', '').strip()
                if email and phone:
                    registrations.append(RegistrationCheckRequest(email=email, phone=phone))
        
        # Format 3: Any element with email/phone attributes
        if not registrations:
            for elem in root.iter():
                email = elem.get('email', '').strip()
                phone = elem.get('phone', '').strip()
                if email and phone:
                    registrations.append(RegistrationCheckRequest(email=email, phone=phone))
        
        # Format 4: <registration email="..." phone="..."/>
        if not registrations:
            for registration in root.findall('.//registration'):
                email = registration.get('email', '').strip()
                phone = registration.get('phone', '').strip()
                if email and phone:
                    registrations.append(RegistrationCheckRequest(email=email, phone=phone))
        
        if not registrations:
            raise HTTPException(
                status_code=400,
                detail="No registrations found in XML. Expected format: <registrations><registration><email>...</email><phone>...</phone></registration></registrations>"
            )
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML format: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing XML: {str(e)}")
    return registrations


@app.post("/bulk_import_file", response_model=BulkRegistrationResponse)
async def bulk_import_file(
    file: UploadFile = File(...),
    file_type: Optional[str] = Form(None),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Bulk import registrations from CSV, JSON, or XML file upload.
    
    Supports:
    - CSV files (Content-Type: text/csv)
    - JSON files (Content-Type: application/json)
    - XML files (Content-Type: application/xml or text/xml)
    
    Maximum 1000 registrations per file.
    Admin only.
    """
    import time
    start_time = time.time()
    
    # Determine file type
    content_type = file.content_type or ""
    filename = file.filename or ""
    
    if file_type:
        detected_type = file_type.lower()
    elif filename.endswith('.csv') or 'csv' in content_type:
        detected_type = 'csv'
    elif filename.endswith('.json') or 'json' in content_type:
        detected_type = 'json'
    elif filename.endswith('.xml') or 'xml' in content_type:
        detected_type = 'xml'
    else:
        raise HTTPException(
            status_code=400,
            detail="Could not determine file type. Please specify file_type parameter or use .csv, .json, or .xml extension."
        )
    
    # Read file content
    try:
        content = await file.read()
        content_str = content.decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")
    
    # Parse based on type
    try:
        if detected_type == 'csv':
            registrations = parse_csv_data(content_str)
        elif detected_type == 'json':
            registrations = parse_json_data(content_str)
        elif detected_type == 'xml':
            registrations = parse_xml_data(content_str)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {detected_type}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing file: {str(e)}")
    
    if not registrations:
        raise HTTPException(status_code=400, detail="No registrations found in file")
    
    if len(registrations) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 registrations allowed per file")
    
    # Process registrations (reuse existing bulk import logic)
    results = []
    successful = 0
    failed = 0
    
    for reg_data in registrations:
        try:
            phone_normalized = normalize_phone(reg_data.phone)
            phone_hash_value = hash_phone(phone_normalized)
            
            # Check if email already exists
            existing = get_registration_by_email(db, reg_data.email)
            if existing:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status=existing.status,
                    message="Email already registered",
                    registration_id=existing.id
                ))
                failed += 1
                continue
            
            # Check phone limit (max 3)
            count = count_registrations_by_phone(db, phone_hash_value)
            if count >= 3:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status="blocked",
                    message="Maximum registrations (3) reached for this phone number",
                    registration_id=None
                ))
                failed += 1
                continue
            
            # Create registration
            registration = create_registration(
                db=db,
                email=reg_data.email,
                phone=reg_data.phone,
                status="approved" if count < 3 else "pending"
            )
            
            allowed = registration.status != "blocked"
            message = "Registration allowed" if allowed else "Registration blocked"
            if registration.is_temporary:
                message = "Temporary email detected and blocked"
            elif registration.is_flagged:
                message = f"Registration flagged (spam score: {registration.spam_score})"
            
            results.append(BulkRegistrationResult(
                email=registration.email,
                phone=reg_data.phone,
                success=True,
                allowed=allowed,
                status=registration.status,
                message=message,
                registration_id=registration.id
            ))
            successful += 1
            
        except Exception as e:
            results.append(BulkRegistrationResult(
                email=reg_data.email,
                phone=reg_data.phone,
                success=False,
                allowed=False,
                status="error",
                message="Failed to process",
                error=str(e)
            ))
            failed += 1
    
    processing_time = time.time() - start_time
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="bulk_import_file",
        details={
            "filename": filename,
            "file_type": detected_type,
            "total": len(registrations),
            "successful": successful,
            "failed": failed,
            "processing_time": processing_time
        }
    )
    
    return BulkRegistrationResponse(
        success=True,
        total=len(registrations),
        successful=successful,
        failed=failed,
        results=results,
        processing_time_seconds=round(processing_time, 2)
    )


@app.post("/bulk_import_raw", response_model=BulkRegistrationResponse)
async def bulk_import_raw(
    request: Request,
    file_type: str = Form(...),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Bulk import registrations from raw CSV, JSON, or XML data in request body.
    
    Send data as form field 'data' with Content-Type: application/x-www-form-urlencoded
    or multipart/form-data.
    
    Parameters:
    - file_type: 'csv', 'json', or 'xml'
    - data: Raw file content as string
    
    Maximum 1000 registrations per request.
    Admin only.
    """
    import time
    start_time = time.time()
    
    # Get content type
    content_type = request.headers.get("content-type", "")
    
    # Read request body
    try:
        if "multipart/form-data" in content_type:
            form = await request.form()
            data = form.get("data", "")
            if isinstance(data, UploadFile):
                content_str = (await data.read()).decode('utf-8')
            else:
                content_str = str(data)
        else:
            body = await request.body()
            content_str = body.decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading request body: {str(e)}")
    
    if not content_str:
        raise HTTPException(status_code=400, detail="No data provided in request body")
    
    # Parse based on type
    file_type_lower = file_type.lower()
    try:
        if file_type_lower == 'csv':
            registrations = parse_csv_data(content_str)
        elif file_type_lower == 'json':
            registrations = parse_json_data(content_str)
        elif file_type_lower == 'xml':
            registrations = parse_xml_data(content_str)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {file_type}. Use 'csv', 'json', or 'xml'")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing data: {str(e)}")
    
    if not registrations:
        raise HTTPException(status_code=400, detail="No registrations found in data")
    
    if len(registrations) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 registrations allowed per request")
    
    # Process registrations (reuse existing bulk import logic)
    results = []
    successful = 0
    failed = 0
    
    for reg_data in registrations:
        try:
            phone_normalized = normalize_phone(reg_data.phone)
            phone_hash_value = hash_phone(phone_normalized)
            
            # Check if email already exists
            existing = get_registration_by_email(db, reg_data.email)
            if existing:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status=existing.status,
                    message="Email already registered",
                    registration_id=existing.id
                ))
                failed += 1
                continue
            
            # Check phone limit (max 3)
            count = count_registrations_by_phone(db, phone_hash_value)
            if count >= 3:
                results.append(BulkRegistrationResult(
                    email=reg_data.email,
                    phone=reg_data.phone,
                    success=True,
                    allowed=False,
                    status="blocked",
                    message="Maximum registrations (3) reached for this phone number",
                    registration_id=None
                ))
                failed += 1
                continue
            
            # Create registration
            registration = create_registration(
                db=db,
                email=reg_data.email,
                phone=reg_data.phone,
                status="approved" if count < 3 else "pending"
            )
            
            allowed = registration.status != "blocked"
            message = "Registration allowed" if allowed else "Registration blocked"
            if registration.is_temporary:
                message = "Temporary email detected and blocked"
            elif registration.is_flagged:
                message = f"Registration flagged (spam score: {registration.spam_score})"
            
            results.append(BulkRegistrationResult(
                email=registration.email,
                phone=reg_data.phone,
                success=True,
                allowed=allowed,
                status=registration.status,
                message=message,
                registration_id=registration.id
            ))
            successful += 1
            
        except Exception as e:
            results.append(BulkRegistrationResult(
                email=reg_data.email,
                phone=reg_data.phone,
                success=False,
                allowed=False,
                status="error",
                message="Failed to process",
                error=str(e)
            ))
            failed += 1
    
    processing_time = time.time() - start_time
    
    # Create audit log
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="bulk_import_raw",
        details={
            "file_type": file_type_lower,
            "total": len(registrations),
            "successful": successful,
            "failed": failed,
            "processing_time": processing_time
        }
    )
    
    return BulkRegistrationResponse(
        success=True,
        total=len(registrations),
        successful=successful,
        failed=failed,
        results=results,
        processing_time_seconds=round(processing_time, 2)
    )


@app.get("/audit_logs", response_model=AuditLogListResponse)
async def get_audit_logs_endpoint(
    page: int = 1,
    page_size: int = 50,
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get paginated audit logs."""
    skip = (page - 1) * page_size
    items, total = get_audit_logs(db=db, skip=skip, limit=page_size)
    
    total_pages = (total + page_size - 1) // page_size
    
    # Include username in response
    log_responses = []
    for item in items:
        log_dict = {
            "id": item.id,
            "user_id": item.user_id,
            "username": item.user.username,
            "action": item.action,
            "details": item.details,
            "timestamp": item.timestamp
        }
        log_responses.append(AuditLogResponse(**log_dict))
    
    return AuditLogListResponse(
        items=log_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@app.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user_or_api_key)):
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        is_admin=current_user.is_admin,
        has_api_key=current_user.api_key is not None,
        created_at=current_user.created_at
    )


@app.post("/generate-api-key", response_model=APIKeyResponse)
async def generate_api_key_endpoint(
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Generate API key for current user."""
    api_key = generate_api_key(db, current_user.id)
    if api_key:
        return APIKeyResponse(
            api_key=api_key,
            message="API key generated successfully. Save it securely - it won't be shown again!"
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate API key"
        )


@app.get("/phone-registrations")
async def get_phone_registrations_endpoint(
    page: int = 1,
    page_size: int = 50,
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get phone numbers with their associated emails."""
    try:
        skip = (page - 1) * page_size
        items, total = get_phone_registrations(db=db, skip=skip, limit=page_size)
        
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages
        }
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_phone_registrations: {str(e)}")
        print(error_details)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/blocked-registrations")
async def get_blocked_registrations_endpoint(
    page: int = 1,
    page_size: int = 50,
    current_user: User = Depends(get_current_user_or_api_key),
    db: Session = Depends(get_db)
):
    """Get blocked phone numbers and their blocked emails."""
    try:
        skip = (page - 1) * page_size
        items, total = get_blocked_registrations(db=db, skip=skip, limit=page_size)
        
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages
        }
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_blocked_registrations: {str(e)}")
        print(error_details)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

