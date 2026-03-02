"""
Streamlit dashboard for Email Abuse Detection System.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import io
import os
import time
import json

from utils import (
    login, signup, logout, is_authenticated, login_with_token, get_oauth_providers,
    get_stats, get_registrations, get_flagged_registrations, override_registration,
    bulk_block_registrations, get_audit_logs, get_phone_registrations,
    get_blocked_registrations_list, check_registration, manual_update_registration,
    get_model_info, whitelist_phone,
    restore_session_from_cookie, save_auth_cookie, clear_auth_cookie,
)

# Page config - centered layout works better on mobile
st.set_page_config(
    page_title="Email Abuse Detection Dashboard",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="auto",  # Collapses on small screens
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': None
    }
)

# Mobile-responsive CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    /* Hide Deploy button and menu */
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none;}
    div[data-testid="stToolbar"] {visibility: hidden;}
    
    /* Mobile & tablet responsive */
    @media (max-width: 768px) {
        .main-header { font-size: 1.5rem; margin-bottom: 1rem; }
        /* Stack metric columns on mobile - 2 per row */
        div[data-testid="column"] { min-width: 45% !important; flex: 1 1 45% !important; }
        /* Full-width form inputs */
        .stTextInput input, .stSelectbox > div { width: 100% !important; }
        /* Touch-friendly buttons - min 44px tap target */
        .stButton > button { min-height: 44px; padding: 0.5rem 1rem; font-size: 1rem; }
        /* Reduce padding */
        .main .block-container { padding: 1rem 1rem 2rem; max-width: 100%; }
        /* Horizontally scrollable tables */
        div[data-testid="stDataFrame"] { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        /* Smaller charts on mobile */
        .js-plotly-plot { min-height: 280px !important; }
    }
    @media (max-width: 480px) {
        .main-header { font-size: 1.25rem; }
        /* Single column metrics on very small screens */
        div[data-testid="column"] { min-width: 100% !important; flex: 1 1 100% !important; }
        .main .block-container { padding: 0.75rem; }
    }
    @media (min-width: 769px) and (max-width: 1024px) {
        .main-header { font-size: 2rem; }
        /* Tablet: 3-4 columns for metrics */
        div[data-testid="column"] { min-width: 30% !important; flex: 1 1 30% !important; }
        .main .block-container { padding: 1.5rem 2rem; }
    }
    /* Horizontal scroll wrapper for dataframes */
    @media (max-width: 768px) {
        .stDataFrame { overflow-x: auto !important; display: block !important; }
        .stDataFrame > div { min-width: max-content; }
    }
    /* Tabs - wrap on small screens */
    @media (max-width: 768px) {
        [data-baseweb="tab-list"] { flex-wrap: wrap !important; }
        [data-baseweb="tab"] { min-width: 120px; padding: 0.5rem 0.75rem; }
    }
    
    /* Modern auth page styling */
    .auth-container {
        max-width: 420px;
        margin: 2rem auto;
        padding: 2.5rem;
        background: linear-gradient(145deg, #1a1d29 0%, #252836 100%);
        border-radius: 16px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        border: 1px solid rgba(255,255,255,0.06);
    }
    .auth-title {
        font-size: 1.75rem;
        font-weight: 700;
        color: #fff;
        margin-bottom: 0.5rem;
        letter-spacing: -0.02em;
    }
    .auth-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-bottom: 2rem;
    }
    .oauth-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        padding: 12px 20px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(255,255,255,0.05);
        color: #e2e8f0;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    .oauth-btn:hover {
        background: rgba(255,255,255,0.08);
    }
    .divider {
        display: flex;
        align-items: center;
        margin: 1.5rem 0;
        color: #64748b;
        font-size: 0.8rem;
    }
    .divider::before, .divider::after {
        content: '';
        flex: 1;
        height: 1px;
        background: rgba(255,255,255,0.08);
    }
    .divider span { padding: 0 1rem; }
    .logout-btn {
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 999;
    }
    </style>
""", unsafe_allow_html=True)


# Login/logout functions removed - authentication is now automatic


def tab_overview():
    """Overview tab with metrics and charts."""
    st.header("📊 Overview")

    # ML Model info (academic demo)
    model_info = get_model_info()
    if model_info and model_info.get("total_samples", 0) > 0:
        total = model_info.get("total_samples", 0)
        ham = model_info.get("total_ham", 0)
        spam = model_info.get("total_spam", 0)
        datasets = model_info.get("datasets", {})
        training_date = model_info.get("training_date", "")
        if training_date:
            try:
                dt = datetime.fromisoformat(training_date.replace("Z", "+00:00"))
                training_date = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass
        st.info(
            f"**🤖 ML Model (Academic Demo)** — Trained on **{total:,}** emails "
            f"({ham:,} ham, {spam:,} spam) from SpamAssassin + Enron-Spam datasets. "
            f"Last trained: {training_date}"
        )
    
    # Add Registration Form
    with st.expander("➕ Add New Registration", expanded=False):
        st.subheader("Test Registration")
        test_col1, test_col2 = st.columns([1, 1])
        with test_col1:
            test_email = st.text_input("Email Address", placeholder="user@example.com", key="test_email")
        with test_col2:
            test_phone = st.text_input("Phone Number", placeholder="+1234567890", key="test_phone")
        
        if st.button("Check Registration", type="primary", key="check_reg_btn"):
            if test_email and test_phone:
                with st.spinner("Checking registration..."):
                    result = check_registration(test_email, test_phone)
                    if result:
                        if result.get("allowed"):
                            st.success(f"✅ {result.get('message', 'Registration allowed')}")
                        else:
                            st.warning(f"⚠️ {result.get('message', 'Registration blocked')}")
            else:
                st.error("Please enter both email and phone number")
        
        st.caption("💡 Tip: Use this form to test the system. Try temporary emails (tempmail.com) or spam emails (spam123@test.com) to see blocking in action!")
    
    st.markdown("---")
    
    # Get stats
    stats = get_stats()
    if not stats:
        st.error("Failed to load statistics. Please check your connection.")
        return
    
    # Calculate not allowed (blocked + temporary blocked)
    not_allowed = stats["blocked_registrations"] + stats["temporary_blocked"]
    allowed = stats["total_registrations"] - not_allowed
    
    # Metrics - two rows for better mobile stacking
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total", stats["total_registrations"])
    with m2:
        st.metric("✅ Allowed", allowed)
    with m3:
        st.metric("🚫 Not Allowed", not_allowed, delta_color="inverse")
    with m4:
        st.metric("Blocked", stats["blocked_registrations"])
    
    m5, m6, m7, _ = st.columns(4)
    with m5:
        st.metric("Temp Blocked", stats["temporary_blocked"])
    with m6:
        st.metric("Flagged", stats["flagged_registrations"])
    with m7:
        st.metric("Avg Spam Score", f"{stats['avg_spam_score']:.1f}")
    
    st.markdown("---")
    
    # Get all registrations for charts (fetch multiple pages if needed)
    all_registrations = []
    page = 1
    page_size = 1000
    total_fetched = 0
    
    while True:
        registrations_data = get_registrations(page=page, page_size=page_size)
        if not registrations_data or not registrations_data.get("items"):
            break
        
        all_registrations.extend(registrations_data["items"])
        total_fetched += len(registrations_data["items"])
        
        # Check if we've fetched all records
        total_records = registrations_data.get("total", 0)
        if total_fetched >= total_records:
            break
        
        page += 1
        if page > 10:  # Safety limit
            break
    
    if all_registrations:
        df = pd.DataFrame(all_registrations)
        
        # Chart 1: Registrations per phone (histogram)
        phone_counts = df.groupby("phone_hash").size().reset_index(name="count")
        fig1 = px.histogram(
            phone_counts,
            x="count",
            nbins=20,
            title="Distribution of Emails per Phone Number",
            labels={"count": "Number of Emails", "value": "Frequency"}
        )
        fig1.update_layout(height=400, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig1, use_container_width=True)
        
        # Chart 2: Spam score distribution
        fig2 = px.histogram(
            df,
            x="spam_score",
            nbins=50,
            title="Spam Score Distribution",
            labels={"spam_score": "Spam Score", "count": "Frequency"}
        )
        fig2.update_layout(height=400, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig2, use_container_width=True)
        
        # Chart 3: Status breakdown (pie chart) - Use stats data for accuracy
        # Calculate status counts from stats (more accurate than counting dataframe)
        approved_count = stats["total_registrations"] - stats["blocked_registrations"] - stats.get("pending_registrations", 0)
        pending_count = stats.get("pending_registrations", 0)
        blocked_count = stats["blocked_registrations"]
        
        # Use actual dataframe counts if available, otherwise use stats
        status_counts_df = df["status"].value_counts()
        if len(df) == stats["total_registrations"]:
            # Use dataframe counts if we have all records
            status_counts = {
                "approved": status_counts_df.get("approved", 0),
                "pending": status_counts_df.get("pending", 0),
                "blocked": status_counts_df.get("blocked", 0)
            }
        else:
            # Use stats data for accuracy
            status_counts = {
                "approved": approved_count,
                "pending": pending_count,
                "blocked": blocked_count
            }
        
        # Filter out zero values
        status_counts = {k: v for k, v in status_counts.items() if v > 0}
        
        # Create color map to highlight blocked status
        color_map = {
            "blocked": "#FF4444",  # Red for blocked
            "pending": "#FFA500",   # Orange for pending
            "approved": "#00AA00"   # Green for approved
        }
        
        fig3 = px.pie(
            values=list(status_counts.values()),
            names=list(status_counts.keys()),
            title=f"Registration Status Breakdown (Total: {stats['total_registrations']})",
            color=list(status_counts.keys()),
            color_discrete_map=color_map
        )
        fig3.update_traces(
            textposition='inside',
            textinfo='percent+label+value',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
        fig3.update_layout(height=400, showlegend=True)
        st.plotly_chart(fig3, use_container_width=True)
        
        # Chart 4: Allowed vs Not Allowed breakdown - Use stats data
        allowed_vs_blocked = {
            "✅ Allowed": allowed,
            "🚫 Not Allowed": not_allowed
        }
        
        fig4 = px.pie(
            values=list(allowed_vs_blocked.values()),
            names=list(allowed_vs_blocked.keys()),
            title=f"Allowed vs Not Allowed Registrations (Total: {stats['total_registrations']})",
            color=list(allowed_vs_blocked.keys()),
            color_discrete_map={
                "✅ Allowed": "#00AA00",
                "🚫 Not Allowed": "#FF4444"
            }
        )
        fig4.update_traces(
            textposition='inside',
            textinfo='percent+label+value',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
        fig4.update_layout(height=400, showlegend=True)
        st.plotly_chart(fig4, use_container_width=True)
        
        # Summary statistics - Use stats data for accuracy
        st.markdown("### 📊 Summary Statistics")
        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
        with summary_col1:
            st.metric("Approved", allowed)
        with summary_col2:
            st.metric("Blocked", stats["blocked_registrations"])
        with summary_col3:
            pending_total = stats["total_registrations"] - allowed - stats["blocked_registrations"]
            st.metric("Pending", pending_total)
        with summary_col4:
            st.metric("Not Allowed", not_allowed)
    else:
        st.info("No registration data available for charts.")
    
    st.markdown("---")
    
    # Show Blocked Registrations
    st.subheader("🚫 Blocked Registrations")
    
    # Get blocked registrations
    blocked_data = get_blocked_registrations_list(page=1, page_size=50)
    
    if blocked_data and blocked_data.get("items") and len(blocked_data["items"]) > 0:
        blocked_items = blocked_data["items"]
        
        # Create a summary table of blocked phones and their email counts
        blocked_summary = []
        for phone_info in blocked_items:
            blocked_summary.append({
                "Phone Number": phone_info.get("phone_normalized", "N/A"),
                "Phone Hash": phone_info.get("phone_hash", "")[:16] + "..." if len(phone_info.get("phone_hash", "")) > 16 else phone_info.get("phone_hash", ""),
                "Blocked Emails": phone_info.get("blocked_count", 0),
                "Total Emails": phone_info.get("email_count", 0)
            })
        
        if blocked_summary:
            blocked_df = pd.DataFrame(blocked_summary)
            st.dataframe(
                blocked_df,
                use_container_width=True,
                hide_index=True,
                height=300
            )
            
            # Show total blocked
            total_blocked_emails = sum(item.get("blocked_count", 0) for item in blocked_items)
            st.caption(f"📊 Showing {len(blocked_items)} blocked phone number(s) with {total_blocked_emails} total blocked email(s)")
            
            # Expandable section to show blocked emails details
            with st.expander("📋 View Blocked Emails Details", expanded=False):
                for phone_info in blocked_items[:10]:  # Show first 10 phones
                    st.write(f"**Phone:** {phone_info.get('phone_normalized', 'N/A')} (Hash: {phone_info.get('phone_hash', '')[:16]}...)")
                    
                    blocked_emails = phone_info.get("blocked_emails", [])
                    if blocked_emails:
                        emails_df = pd.DataFrame(blocked_emails)
                        
                        # Format datetime columns
                        if "created_at" in emails_df.columns:
                            emails_df["created_at"] = pd.to_datetime(emails_df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Display relevant columns
                        display_cols = ["email", "status", "is_temporary", "is_flagged", "spam_score", "detection_notes"]
                        available_cols = [col for col in display_cols if col in emails_df.columns]
                        
                        st.dataframe(
                            emails_df[available_cols],
                            use_container_width=True,
                            hide_index=True
                        )
                    st.markdown("---")
                
                if len(blocked_items) > 10:
                    st.info(f"Showing first 10 of {len(blocked_items)} blocked phone numbers. Visit the '🚫 Blocked' tab for complete details.")
        else:
            st.info("No blocked registrations found.")
    else:
        st.info("No blocked registrations found.")


def tab_registrations():
    """Registrations tab with paginated table."""
    st.header("📋 Registrations")
    
    # Last update indicator (if manual update was made)
    if 'last_update' in st.session_state:
        try:
            last_update_time = datetime.fromisoformat(st.session_state['last_update'])
            time_ago = (datetime.now() - last_update_time).total_seconds()
            if time_ago < 60:
                st.caption(f"📅 Last manual update: {int(time_ago)}s ago")
            elif time_ago < 3600:
                st.caption(f"📅 Last manual update: {int(time_ago/60)}m ago")
            else:
                st.caption(f"📅 Last manual update: {last_update_time.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            pass
    
    # Filters
    col1, col2 = st.columns(2)
    with col1:
        filter_phone = st.text_input("Filter by Phone Hash (optional)")
    with col2:
        filter_status = st.selectbox(
            "Filter by Status",
            ["All", "approved", "pending", "blocked"]
        )
    
    # Get all registrations (no pagination)
    status_filter = filter_status if filter_status != "All" else None
    registrations_data = get_registrations(
        page=1,
        page_size=10000,
        phone_hash=filter_phone if filter_phone else None,
        status=status_filter
    )
    
    if registrations_data and registrations_data.get("items"):
        df = pd.DataFrame(registrations_data["items"])
        
        # Format datetime columns
        if "created_at" in df.columns:
            df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        if "updated_at" in df.columns:
            df["updated_at"] = pd.to_datetime(df["updated_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Display table
        st.dataframe(df, use_container_width=True, height=400)
        
        # Total count info
        st.info(f"Total: {registrations_data['total']} registrations")
        
        # CSV export
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"registrations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No registrations found.")


def tab_manual_review():
    """Manual review tab for manually managing registrations."""
    st.header("🔍 Manual Review")
    st.info("Manually manage email registrations: mark as spam, temporary, change status, and more.")
    
    # Get all registrations for selection
    st.subheader("📋 Select Registration")
    registrations_data = get_registrations(page=1, page_size=10000)
    
    if not registrations_data or not registrations_data.get("items"):
        st.warning("No registrations found. Add some registrations first.")
        return
    
    # Create selection dropdown
    registrations = registrations_data["items"]
    reg_options = {f"ID {r['id']}: {r['email']} ({r['status']})": r['id'] for r in registrations}
    
    selected_reg_text = st.selectbox(
        "Select Registration to Manage",
        options=list(reg_options.keys()),
        key="manual_review_select"
    )
    
    selected_reg_id = reg_options[selected_reg_text]
    selected_reg = next((r for r in registrations if r['id'] == selected_reg_id), None)
    
    if not selected_reg:
        st.error("Registration not found")
        return
    
    # Display current registration info
    st.markdown("---")
    st.subheader("📊 Current Registration Details")
    detail_col1, detail_col2, detail_col3 = st.columns(3)
    
    with detail_col1:
        st.write(f"**Email:** {selected_reg['email']}")
        st.write(f"**Phone:** {selected_reg.get('phone_normalized', 'N/A')}")
        st.write(f"**Status:** {selected_reg['status']}")
    
    with detail_col2:
        st.write(f"**Spam Score:** {selected_reg.get('spam_score', 0)}")
        st.write(f"**Is Temporary:** {'Yes' if selected_reg.get('is_temporary') else 'No'}")
        st.write(f"**Is Flagged:** {'Yes' if selected_reg.get('is_flagged') else 'No'}")
    
    with detail_col3:
        st.write(f"**Created:** {selected_reg.get('created_at', 'N/A')}")
        st.write(f"**Updated:** {selected_reg.get('updated_at', 'N/A')}")
        if selected_reg.get('detection_notes'):
            st.write(f"**Notes:** {selected_reg['detection_notes'][:50]}...")
    
    st.markdown("---")
    
    # Manual update form
    st.subheader("✏️ Manual Update")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Mark as Spam/Temporary:**")
        mark_as_spam = st.checkbox("Mark as Spam (Flagged)", value=selected_reg.get('is_flagged', False))
        mark_as_temp = st.checkbox("Mark as Temporary Email", value=selected_reg.get('is_temporary', False))
        
        st.write("**Change Status:**")
        new_status = st.selectbox(
            "New Status",
            ["approved", "pending", "blocked"],
            index=["approved", "pending", "blocked"].index(selected_reg['status']) if selected_reg['status'] in ["approved", "pending", "blocked"] else 0
        )
    
    with col2:
        st.write("**Spam Score:**")
        new_spam_score = st.slider(
            "Spam Score (0-100)",
            min_value=0,
            max_value=100,
            value=selected_reg.get('spam_score', 0),
            help="0 = Normal, 70+ = Spam"
        )
        
        st.write("**Detection Notes:**")
        new_notes = st.text_area(
            "Detection Notes",
            value=selected_reg.get('detection_notes', ''),
            height=100,
            max_chars=1000,
            help="Additional notes about this registration"
        )
    
    reason = st.text_area(
        "Reason for Changes (Required)",
        placeholder="Explain why you're making these changes...",
        height=80,
        max_chars=500
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("💾 Save Changes", type="primary"):
            if reason and len(reason) >= 5:
                with st.spinner("Updating registration..."):
                    result = manual_update_registration(
                        registration_id=selected_reg_id,
                        is_temporary=mark_as_temp,
                        is_flagged=mark_as_spam,
                        spam_score=new_spam_score,
                        status=new_status,
                        detection_notes=new_notes if new_notes else None,
                        reason=reason
                    )
                    if result:
                        st.success("✅ Registration updated successfully!")
                        st.session_state['last_update'] = datetime.now().isoformat()
                        st.rerun()
                    else:
                        st.error("Failed to update registration")
            else:
                st.error("Please provide a reason (min 5 characters)")
    
    with col2:
        if st.button("🔄 Reset"):
            st.rerun()
    
    st.markdown("---")
    
    # Quick actions - 2x2 grid for mobile
    st.subheader("⚡ Quick Actions")
    
    qa1, qa2 = st.columns(2)
    with qa1:
        if st.button("🚨 Mark as Spam", use_container_width=True):
            if reason and len(reason) >= 5:
                result = manual_update_registration(
                    registration_id=selected_reg_id,
                    is_flagged=True,
                    spam_score=85,
                    status="pending",
                    reason=f"Marked as spam: {reason}"
                )
                if result:
                    st.success("✅ Marked as spam!")
                    st.session_state['last_update'] = datetime.now().isoformat()
                    st.rerun()
            else:
                st.error("Enter reason first")
    
    with qa2:
        if st.button("📧 Mark as Temporary", use_container_width=True):
            if reason and len(reason) >= 5:
                result = manual_update_registration(
                    registration_id=selected_reg_id,
                    is_temporary=True,
                    status="blocked",
                    reason=f"Marked as temporary: {reason}"
                )
                if result:
                    st.success("✅ Marked as temporary!")
                    st.session_state['last_update'] = datetime.now().isoformat()
                    st.rerun()
            else:
                st.error("Enter reason first")
    
    qa3, qa4 = st.columns(2)
    with qa3:
        if st.button("✅ Approve", use_container_width=True):
            if reason and len(reason) >= 5:
                result = manual_update_registration(
                    registration_id=selected_reg_id,
                    status="approved",
                    is_flagged=False,
                    reason=f"Manually approved: {reason}"
                )
                if result:
                    st.success("✅ Approved!")
                    st.session_state['last_update'] = datetime.now().isoformat()
                    st.rerun()
            else:
                st.error("Enter reason first")
    
    with qa4:
        if st.button("🚫 Block", use_container_width=True):
            if reason and len(reason) >= 5:
                result = manual_update_registration(
                    registration_id=selected_reg_id,
                    status="blocked",
                    reason=f"Manually blocked: {reason}"
                )
                if result:
                    st.success("✅ Blocked!")
                    st.session_state['last_update'] = datetime.now().isoformat()
                    st.rerun()
            else:
                st.error("Enter reason first")
    
    st.markdown("---")
    
    # Recent audit logs
    st.subheader("Recent Audit Logs")
    audit_logs_data = get_audit_logs(page=1, page_size=50)
    
    if audit_logs_data and audit_logs_data.get("items"):
        df = pd.DataFrame(audit_logs_data["items"])
        
        # Format timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        st.dataframe(df, use_container_width=True, height=300)
    else:
        st.info("No audit logs available.")


def tab_spam_detection():
    """Spam detection tab for flagged registrations."""
    st.header("🚨 Spam Detection")
    
    # Get flagged registrations
    flagged_data = get_flagged_registrations(page=1, page_size=100)
    
    # Handle None or empty data
    if not flagged_data:
        st.info("No flagged registrations found.")
        st.markdown("---")
        # Show sample domains
        st.subheader("Sample Temporary Email Domains")
        temp_domains = [
            "tempmail.com", "guerrillamail.com", "mailinator.com",
            "throwaway.email", "temp-mail.org", "10minutemail.com"
        ]
        st.code("\n".join(temp_domains), language="text")
        return
    
    if flagged_data.get("items") and len(flagged_data.get("items", [])) > 0:
        df = pd.DataFrame(flagged_data["items"])
        
        # Format datetime
        if "created_at" in df.columns:
            df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Display table
        st.dataframe(df, use_container_width=True, height=400)
        
        # Bulk block
        st.subheader("Bulk Block")
        selected_ids = st.multiselect(
            "Select Registrations to Block",
            options=df["id"].tolist(),
            format_func=lambda x: f"ID {x}"
        )
        bulk_reason = st.text_area("Reason for Blocking", height=100, max_chars=500)
        
        if st.button("Block Selected", type="primary"):
            if selected_ids and bulk_reason and len(bulk_reason) >= 5:
                result = bulk_block_registrations(selected_ids, bulk_reason)
                if result:
                    st.success(f"Blocked {result.get('blocked_count', 0)} registration(s)")
                    st.rerun()
                else:
                    st.error("Failed to block registrations")
            else:
                st.error("Please select registrations and provide a reason")
    else:
        st.info("No flagged registrations found.")
    
    st.markdown("---")
    
    # Sample temporary domains
    st.subheader("Sample Temporary Email Domains")
    temp_domains = [
        "tempmail.com", "guerrillamail.com", "mailinator.com",
        "throwaway.email", "temp-mail.org", "10minutemail.com"
    ]
    st.code("\n".join(temp_domains), language="text")


def tab_phone_registrations():
    """Phone registrations tab showing phones and emails separately."""
    st.header("📱 Phone Numbers & Emails")
    
    # Get all phone registrations (no pagination)
    phone_data = get_phone_registrations(page=1, page_size=10000)
    
    if phone_data and phone_data.get("items"):
        items = phone_data["items"]
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Phone Numbers", phone_data.get("total", 0))
        with col2:
            total_emails = sum(item.get("email_count", 0) for item in items)
            st.metric("Total Emails", total_emails)
        with col3:
            avg_emails = total_emails / len(items) if items else 0
            st.metric("Avg Emails per Phone", f"{avg_emails:.1f}")
        
        st.markdown("---")
        
        # Section 1: Phone Numbers Table
        st.subheader("📱 Phone Numbers")
        
        # Prepare phone numbers data
        phones_list = []
        for phone_info in items:
            phones_list.append({
                "Phone Hash": phone_info.get("phone_hash", ""),
                "Phone Number": phone_info.get("phone_normalized", "N/A"),
                "Email Count": phone_info.get("email_count", 0)
            })
        
        if phones_list:
            phones_df = pd.DataFrame(phones_list)
            st.dataframe(
                phones_df,
                use_container_width=True,
                hide_index=True
            )
        
        st.markdown("---")
        
        # Section 2: Emails Table (Separate from phones)
        st.subheader("📧 Emails")
        
        # Prepare all emails data
        all_emails = []
        for phone_info in items:
            phone_hash = phone_info.get("phone_hash", "")
            phone_normalized = phone_info.get("phone_normalized", "N/A")
            
            if phone_info.get("emails"):
                for email_info in phone_info["emails"]:
                    all_emails.append({
                        "Phone Number": phone_normalized,
                        "Phone Hash": phone_hash[:16] + "..." if len(phone_hash) > 16 else phone_hash,
                        "Email": email_info.get("email", ""),
                        "Status": email_info.get("status", ""),
                        "Temporary": "Yes" if email_info.get("is_temporary") else "No",
                        "Flagged": "Yes" if email_info.get("is_flagged") else "No",
                        "Spam Score": email_info.get("spam_score", 0),
                        "Created At": pd.to_datetime(email_info.get("created_at", "")).strftime("%Y-%m-%d %H:%M:%S") if email_info.get("created_at") else ""
                    })
        
        if all_emails:
            emails_df = pd.DataFrame(all_emails)
            st.dataframe(
                emails_df,
                use_container_width=True,
                height=400
            )
            
            # CSV export for emails
            csv = emails_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Emails (CSV)",
                data=csv,
                file_name=f"phone_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No emails found for these phone numbers.")
        
        # Total info
        st.markdown("---")
        st.info(f"Total: {phone_data.get('total', 0)} phone numbers")
    else:
        st.info("No phone registrations found.")


def tab_blocked_registrations():
    """Blocked registrations tab showing blocked phones and emails (paginated for speed)."""
    st.header("🚫 Blocked Phone Numbers & Emails")
    
    # Show one-time success popup if a phone was just whitelisted
    if "last_whitelist_message" in st.session_state:
        st.success(st.session_state["last_whitelist_message"])
        del st.session_state["last_whitelist_message"]
    
    # Pagination: small page size so whitelist + rerun is fast (no 10k load)
    page_size = 50
    if "blocked_page" not in st.session_state:
        st.session_state.blocked_page = 1
    page = st.session_state.blocked_page
    
    blocked_data = get_blocked_registrations_list(page=page, page_size=page_size)
    
    if blocked_data and blocked_data.get("items"):
        items = blocked_data["items"]
        total_regs = blocked_data.get("total", 0)
        total_pages = blocked_data.get("total_pages", 1)
        
        # Summary metrics (total from API; page count for current view)
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Blocked (registrations)", total_regs)
        with col2:
            st.metric("This page (phone groups)", len(items))
        with col3:
            st.metric("Blocked emails on page", sum(item.get("blocked_count", 0) for item in items))
        
        # Pagination controls
        if total_pages > 1:
            prev_col, info_col, next_col, _ = st.columns([1, 2, 1, 2])
            with prev_col:
                if st.button("⬅ Prev", key="blocked_prev", disabled=(page <= 1)):
                    st.session_state.blocked_page = max(1, page - 1)
                    st.rerun()
            with info_col:
                st.caption(f"Page **{page}** of **{total_pages}**")
            with next_col:
                if st.button("Next ➡", key="blocked_next", disabled=(page >= total_pages)):
                    st.session_state.blocked_page = min(total_pages, page + 1)
                    st.rerun()
        
        st.markdown("---")
        
        # Display each blocked phone with its blocked emails (collapsed by default for faster render)
        for idx, phone_info in enumerate(items):
            with st.expander(
                f"🚫 {phone_info.get('phone_normalized', 'N/A')} "
                f"(Hash: {phone_info.get('phone_hash', '')[:16]}...) - "
                f"{phone_info.get('blocked_count', 0)} blocked email(s)",
                expanded=False
            ):
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.write(f"**Phone Hash:** `{phone_info.get('phone_hash', '')}`")
                    st.write(f"**Phone Number:** {phone_info.get('phone_normalized', 'N/A')}")
                    st.write(f"**Blocked Emails Count:** {phone_info.get('blocked_count', 0)}")
                    if phone_info.get("is_whitelisted"):
                        st.success("This phone is whitelisted. Suspicious digit patterns will be ignored for future checks.")
                
                # Blocked emails table
                if phone_info.get("blocked_emails"):
                    emails_df = pd.DataFrame(phone_info["blocked_emails"])
                    
                    # Format datetime
                    if "created_at" in emails_df.columns:
                        emails_df["created_at"] = pd.to_datetime(emails_df["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    if "updated_at" in emails_df.columns:
                        emails_df["updated_at"] = pd.to_datetime(emails_df["updated_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Display blocked emails with reasons
                    display_cols = ["email", "is_temporary", "is_flagged", "spam_score", "detection_notes", "created_at"]
                    available_cols = [col for col in display_cols if col in emails_df.columns]
                    
                    st.dataframe(
                        emails_df[available_cols],
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    # Show detection notes if available
                    if "detection_notes" in emails_df.columns:
                        notes = emails_df["detection_notes"].dropna().unique()
                        if len(notes) > 0:
                            st.write("**Blocking Reasons:**")
                            for note in notes:
                                st.write(f"- {note}")

                # Admin action: whitelist this phone if it's legitimate
                if not phone_info.get("is_whitelisted"):
                    reason_key = f"whitelist_reason_{idx}"
                    btn_key = f"whitelist_btn_{idx}"
                    reason_text = st.text_input(
                        "Reason for allowing this phone",
                        key=reason_key,
                        placeholder="Explain why this phone is legitimate (e.g., real user with repeated digits).",
                    )
                    if st.button("✅ Allow this phone (whitelist)", key=btn_key, type="primary", use_container_width=True):
                        if reason_text and len(reason_text.strip()) >= 5:
                            with st.spinner("Whitelisting phone and approving related registrations. Please wait..."):
                                result = whitelist_phone(
                                    phone_hash=phone_info.get("phone_hash", ""),
                                    phone_normalized=phone_info.get("phone_normalized", "N/A"),
                                    reason=reason_text.strip(),
                                )
                            if result and result.get("success"):
                                # Store message and reset to page 1 so list refreshes fast
                                st.session_state["last_whitelist_message"] = result.get(
                                    "message",
                                    "Phone whitelisted and related registrations approved from blocked list."
                                )
                                st.session_state.blocked_page = 1
                                st.rerun()
                            else:
                                st.error("Failed to whitelist phone. Please try again.")
                        else:
                            st.error("Please provide a reason (at least 5 characters).")
        
        # Total info
        st.markdown("---")
        st.info(f"Total blocked registrations: **{total_regs}**. This page shows up to {page_size} (faster load & whitelist).")
        
        # Export option
        if items:
            all_blocked = []
            for phone_info in items:
                for email_info in phone_info.get("blocked_emails", []):
                    all_blocked.append({
                        "phone_hash": phone_info.get("phone_hash"),
                        "phone_normalized": phone_info.get("phone_normalized"),
                        "email": email_info.get("email"),
                        "is_temporary": email_info.get("is_temporary"),
                        "is_flagged": email_info.get("is_flagged"),
                        "spam_score": email_info.get("spam_score"),
                        "detection_notes": email_info.get("detection_notes"),
                        "created_at": email_info.get("created_at")
                    })
            
            if all_blocked:
                blocked_df = pd.DataFrame(all_blocked)
                csv = blocked_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Blocked List (CSV)",
                    data=csv,
                    file_name=f"blocked_registrations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    else:
        st.info("No blocked registrations found.")


def tab_reports():
    """Comprehensive Reports tab with detailed information."""
    st.header("📄 Comprehensive Reports")
    
    # Get all data
    stats = get_stats()
    if not stats:
        st.error("Failed to load statistics.")
        return
    
    # Calculate additional metrics
    total = stats["total_registrations"]
    blocked = stats["blocked_registrations"]
    temp_blocked = stats["temporary_blocked"]
    flagged = stats["flagged_registrations"]
    unique_phones = stats["unique_phones"]
    not_allowed = blocked + temp_blocked
    allowed = total - not_allowed
    
    # Get all registrations for detailed analysis
    all_regs = []
    page = 1
    while True:
        reg_data = get_registrations(page=page, page_size=1000)
        if not reg_data or not reg_data.get("items"):
            break
        all_regs.extend(reg_data["items"])
        if len(all_regs) >= reg_data.get("total", 0):
            break
        page += 1
        if page > 20:  # Safety limit
            break
    
    df = pd.DataFrame(all_regs) if all_regs else pd.DataFrame()
    
    # Tabs for different report sections
    report_tab1, report_tab2, report_tab3, report_tab4 = st.tabs([
        "📊 Overview Statistics",
        "🔍 Detailed Analysis",
        "📋 Data Breakdowns",
        "💾 Export Reports"
    ])
    
    with report_tab1:
        st.subheader("📊 System Overview Statistics")
        
        # Key Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Registrations", total)
        with col2:
            st.metric("✅ Allowed", allowed, delta=f"{allowed/total*100:.1f}%")
        with col3:
            st.metric("🚫 Not Allowed", not_allowed, delta=f"{not_allowed/total*100:.1f}%", delta_color="inverse")
        with col4:
            st.metric("Unique Phone Numbers", unique_phones)
        
        st.markdown("---")
        
        # Detailed Statistics Table
        st.subheader("📈 Detailed Statistics")
        stats_data = {
            "Category": [
                "Total Registrations",
                "Allowed Registrations",
                "Not Allowed Registrations",
                "Blocked Registrations",
                "Temporary Email Blocked",
                "Flagged as Spam",
                "Unique Phone Numbers",
                "Average Spam Score",
                "Block Rate",
                "Flag Rate",
                "Temporary Email Rate"
            ],
            "Value": [
                total,
                allowed,
                not_allowed,
                blocked,
                temp_blocked,
                flagged,
                unique_phones,
                f"{stats['avg_spam_score']:.2f}",
                f"{(blocked/total*100):.2f}%" if total > 0 else "0%",
                f"{(flagged/total*100):.2f}%" if total > 0 else "0%",
                f"{(temp_blocked/total*100):.2f}%" if total > 0 else "0%"
            ]
        }
        stats_df = pd.DataFrame(stats_data)
        st.dataframe(stats_df, use_container_width=True, hide_index=True)
        
        # Status Distribution
        if not df.empty:
            st.markdown("---")
            st.subheader("📊 Status Distribution")
            status_counts = df["status"].value_counts()
            status_col1, status_col2 = st.columns(2)
            with status_col1:
                st.dataframe(status_counts.reset_index().rename(columns={"index": "Status", "status": "Count"}), use_container_width=True, hide_index=True)
            with status_col2:
                fig_status = px.pie(
                    values=status_counts.values,
                    names=status_counts.index,
                    title="Status Distribution"
                )
                st.plotly_chart(fig_status, use_container_width=True)
    
    with report_tab2:
        st.subheader("🔍 Detailed Analysis")
        
        if df.empty:
            st.info("No registration data available for analysis.")
        else:
            # Spam Score Analysis
            st.markdown("### 📊 Spam Score Analysis")
            spam_col1, spam_col2 = st.columns(2)
            with spam_col1:
                st.write("**Spam Score Statistics:**")
                spam_stats = {
                    "Metric": ["Minimum", "Maximum", "Average", "Median", "Standard Deviation"],
                    "Value": [
                        df["spam_score"].min(),
                        df["spam_score"].max(),
                        f"{df['spam_score'].mean():.2f}",
                        f"{df['spam_score'].median():.2f}",
                        f"{df['spam_score'].std():.2f}"
                    ]
                }
                st.dataframe(pd.DataFrame(spam_stats), use_container_width=True, hide_index=True)
            
            with spam_col2:
                # Spam score distribution
                fig_spam = px.histogram(
                    df,
                    x="spam_score",
                    nbins=50,
                    title="Spam Score Distribution",
                    labels={"spam_score": "Spam Score", "count": "Frequency"}
                )
                st.plotly_chart(fig_spam, use_container_width=True)
            
            # High Risk Registrations
            st.markdown("---")
            st.subheader("🚨 High Risk Registrations")
            high_risk = df[(df["spam_score"] >= 70) | (df["is_flagged"] == True) | (df["is_temporary"] == True)]
            st.write(f"**Total High Risk:** {len(high_risk)} registrations")
            
            if len(high_risk) > 0:
                high_risk_display = high_risk[["email", "status", "spam_score", "is_temporary", "is_flagged", "detection_notes"]].head(50)
                st.dataframe(high_risk_display, use_container_width=True, height=300)
            
            # Phone Number Analysis
            st.markdown("---")
            st.subheader("📱 Phone Number Analysis")
            phone_col1, phone_col2 = st.columns(2)
            with phone_col1:
                phone_counts = df.groupby("phone_hash").size().reset_index(name="email_count")
                st.write("**Emails per Phone Number:**")
                st.write(f"- Average: {phone_counts['email_count'].mean():.2f}")
                st.write(f"- Maximum: {phone_counts['email_count'].max()}")
                st.write(f"- Minimum: {phone_counts['email_count'].min()}")
                st.write(f"- Phones with 3+ emails: {len(phone_counts[phone_counts['email_count'] >= 3])}")
            
            with phone_col2:
                fig_phone = px.histogram(
                    phone_counts,
                    x="email_count",
                    nbins=20,
                    title="Distribution of Emails per Phone",
                    labels={"email_count": "Number of Emails", "count": "Frequency"}
                )
                st.plotly_chart(fig_phone, use_container_width=True)
            
            # Temporary Email Analysis
            st.markdown("---")
            st.subheader("📧 Temporary Email Detection")
            temp_emails = df[df["is_temporary"] == True]
            st.write(f"**Total Temporary Emails Detected:** {len(temp_emails)}")
            if len(temp_emails) > 0:
                temp_domains = temp_emails["email"].str.split("@").str[1].value_counts().head(10)
                st.write("**Top Temporary Email Domains:**")
                st.dataframe(temp_domains.reset_index().rename(columns={"index": "Domain", "email": "Count"}), use_container_width=True, hide_index=True)
            
            # Flagged Registrations Analysis
            st.markdown("---")
            st.subheader("🚩 Flagged Registrations Analysis")
            flagged_regs = df[df["is_flagged"] == True]
            st.write(f"**Total Flagged:** {len(flagged_regs)}")
            if len(flagged_regs) > 0:
                flagged_stats = {
                    "Average Spam Score": f"{flagged_regs['spam_score'].mean():.2f}",
                    "Min Spam Score": flagged_regs['spam_score'].min(),
                    "Max Spam Score": flagged_regs['spam_score'].max(),
                    "Blocked Count": len(flagged_regs[flagged_regs["status"] == "blocked"]),
                    "Pending Count": len(flagged_regs[flagged_regs["status"] == "pending"])
                }
                st.json(flagged_stats)
    
    with report_tab3:
        st.subheader("📋 Detailed Data Breakdowns")
        
        if df.empty:
            st.info("No registration data available.")
        else:
            # Registration Status Breakdown
            st.markdown("### 📊 Registration Status Breakdown")
            status_breakdown = df.groupby("status").agg({
                "id": "count",
                "spam_score": "mean",
                "is_temporary": "sum",
                "is_flagged": "sum"
            }).rename(columns={
                "id": "Count",
                "spam_score": "Avg Spam Score",
                "is_temporary": "Temporary Emails",
                "is_flagged": "Flagged Count"
            })
            status_breakdown["Percentage"] = (status_breakdown["Count"] / total * 100).round(2).astype(str) + "%"
            st.dataframe(status_breakdown, use_container_width=True)
            
            # Blocked Registrations Details
            st.markdown("---")
            st.subheader("🚫 Blocked Registrations Details")
            blocked_data = get_blocked_registrations_list(page=1, page_size=1000)
            if blocked_data and blocked_data.get("items"):
                blocked_items = blocked_data["items"]
                st.write(f"**Total Blocked Phone Numbers:** {blocked_data.get('total', 0)}")
                st.write(f"**Total Blocked Emails:** {sum(item.get('blocked_count', 0) for item in blocked_items)}")
                
                # Blocked reasons summary
                blocked_reasons = []
                for item in blocked_items:
                    for email in item.get("blocked_emails", []):
                        if email.get("detection_notes"):
                            blocked_reasons.append(email["detection_notes"])
                
                if blocked_reasons:
                    st.write("**Common Blocking Reasons:**")
                    reason_counts = pd.Series(blocked_reasons).value_counts().head(10)
                    st.dataframe(reason_counts.reset_index().rename(columns={"index": "Reason", 0: "Count"}), use_container_width=True, hide_index=True)
            
            # Recent Activity
            st.markdown("---")
            st.subheader("📅 Recent Activity")
            if not df.empty:
                df_sorted = df.sort_values("created_at", ascending=False)
                recent = df_sorted[["email", "status", "spam_score", "is_temporary", "is_flagged", "created_at"]].head(20)
                recent["created_at"] = pd.to_datetime(recent["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                st.dataframe(recent, use_container_width=True, height=400)
            
            # Audit Logs Summary
            st.markdown("---")
            st.subheader("📝 Audit Logs Summary")
            audit_logs = get_audit_logs(page=1, page_size=50)
            if audit_logs and audit_logs.get("items"):
                st.write(f"**Total Audit Logs:** {audit_logs.get('total', 0)}")
                audit_df = pd.DataFrame(audit_logs["items"])
                if "timestamp" in audit_df.columns:
                    audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                st.dataframe(audit_df.head(20), use_container_width=True, height=300)
    
    with report_tab4:
        st.subheader("💾 Export Comprehensive Reports")
        
        # Export Options
        export_col1, export_col2, export_col3 = st.columns(3)
        
        with export_col1:
            st.markdown("### 📄 PDF Report")
            if st.button("Generate PDF Report", type="primary", use_container_width=True):
                buffer = io.BytesIO()
                doc = SimpleDocTemplate(buffer, pagesize=letter)
                story = []
                styles = getSampleStyleSheet()
                
                # Title
                title = Paragraph("Email Abuse Detection System - Comprehensive Report", styles["Title"])
                story.append(title)
                story.append(Spacer(1, 0.3 * inch))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
                story.append(Spacer(1, 0.5 * inch))
                
                # Executive Summary
                story.append(Paragraph("Executive Summary", styles["Heading1"]))
                summary_data = [
                    ["Metric", "Value"],
                    ["Total Registrations", str(total)],
                    ["Allowed Registrations", str(allowed)],
                    ["Not Allowed Registrations", str(not_allowed)],
                    ["Blocked Registrations", str(blocked)],
                    ["Temporary Email Blocked", str(temp_blocked)],
                    ["Flagged Registrations", str(flagged)],
                    ["Unique Phone Numbers", str(unique_phones)],
                    ["Average Spam Score", f"{stats['avg_spam_score']:.2f}"],
                    ["Block Rate", f"{(blocked/total*100):.2f}%" if total > 0 else "0%"],
                    ["Flag Rate", f"{(flagged/total*100):.2f}%" if total > 0 else "0%"],
                ]
                summary_table = Table(summary_data)
                summary_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]))
                story.append(summary_table)
                story.append(Spacer(1, 0.5 * inch))
                
                # Status Breakdown
                if not df.empty:
                    story.append(Paragraph("Status Breakdown", styles["Heading2"]))
                    status_data = [["Status", "Count", "Percentage"]]
                    status_counts = df["status"].value_counts()
                    for status, count in status_counts.items():
                        percentage = (count / total * 100) if total > 0 else 0
                        status_data.append([status, str(count), f"{percentage:.2f}%"])
                    
                    status_table = Table(status_data)
                    status_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]))
                    story.append(status_table)
                    story.append(Spacer(1, 0.5 * inch))
                
                # Top Registrations
                if not df.empty:
                    story.append(Paragraph("Top 20 Recent Registrations", styles["Heading2"]))
                    reg_data = [["ID", "Email", "Status", "Spam Score", "Flagged", "Temporary"]]
                    df_sorted = df.sort_values("created_at", ascending=False)
                    for _, reg in df_sorted.head(20).iterrows():
                        reg_data.append([
                            str(reg.get("id", "")),
                            reg.get("email", "")[:30] + "..." if len(str(reg.get("email", ""))) > 30 else reg.get("email", ""),
                            reg.get("status", ""),
                            str(reg.get("spam_score", 0)),
                            "Yes" if reg.get("is_flagged") else "No",
                            "Yes" if reg.get("is_temporary") else "No"
                        ])
                    
                    reg_table = Table(reg_data)
                    reg_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]))
                    story.append(reg_table)
                
                # Build PDF
                doc.build(story)
                buffer.seek(0)
                
                st.download_button(
                    label="📥 Download PDF Report",
                    data=buffer,
                    file_name=f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
                st.success("PDF report generated successfully!")
        
        with export_col2:
            st.markdown("### 📊 CSV Export")
            if not df.empty:
                csv_data = df.to_csv(index=False)
                st.download_button(
                    label="📥 Download All Data (CSV)",
                    data=csv_data,
                    file_name=f"all_registrations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
                
                # Export blocked only
                blocked_df = df[df["status"] == "blocked"]
                if len(blocked_df) > 0:
                    blocked_csv = blocked_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Blocked Only (CSV)",
                        data=blocked_csv,
                        file_name=f"blocked_registrations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
        
        with export_col3:
            st.markdown("### 📋 JSON Export")
            if not df.empty:
                json_data = df.to_json(orient="records", date_format="iso")
                st.download_button(
                    label="📥 Download All Data (JSON)",
                    data=json_data,
                    file_name=f"all_registrations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
                
                # Export stats as JSON
                stats_json = json.dumps(stats, indent=2)
                st.download_button(
                    label="📥 Download Statistics (JSON)",
                    data=stats_json,
                    file_name=f"statistics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )


def render_auth_page(cookie_manager=None):
    """Render modern Sign In / Sign Up page with Google OAuth. Cookie manager persists login across refresh."""
    api_base = os.getenv("API_BASE_URL", "http://localhost:8000")
    oauth_providers = get_oauth_providers()

    # Center the auth form
    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_center, col_right = st.columns([1, 2, 1])
    with col_center:
        st.markdown("### Welcome to Email Abuse Dashboard")
        st.markdown("*Sign in or create an account to continue*")
        st.markdown("---")

        # Tabs: Sign In | Sign Up
        auth_tab1, auth_tab2 = st.tabs(["**Sign In**", "**Sign Up**"])

        with auth_tab1:
            # Google OAuth (only if configured)
            if oauth_providers.get("google"):
                st.link_button("Sign in with Google", f"{api_base}/auth/google", use_container_width=True, type="secondary")
                st.markdown("*— or continue with username —*")

            with st.form("signin_form"):
                sin_user = st.text_input("Username", placeholder="Enter your username", key="sin_user")
                sin_pass = st.text_input("Password", type="password", placeholder="Enter your password", key="sin_pass")
                sin_col1, sin_col2 = st.columns(2)
                with sin_col1:
                    sin_submit = st.form_submit_button("Sign In")
                with sin_col2:
                    demo_btn = st.form_submit_button("Quick Demo")

                if sin_submit and sin_user and sin_pass:
                    err = login(sin_user, sin_pass, cookie_manager)
                    if err:
                        st.error(err)
                    else:
                        st.rerun()
                if demo_btn:
                    err = login("admin", "adminpass", cookie_manager)
                    if err:
                        st.error(err)
                    else:
                        st.rerun()

        with auth_tab2:
            with st.form("signup_form"):
                st.markdown("**Create Admin Account**")
                sup_user = st.text_input("Username", placeholder="Choose a username (min 3 chars)", key="sup_user")
                sup_pass = st.text_input("Password", type="password", placeholder="Choose a password (min 6 chars)", key="sup_pass")
                sup_pass2 = st.text_input("Confirm Password", type="password", placeholder="Confirm password", key="sup_pass2")
                sup_admin = st.checkbox("Register as Admin", value=True, help="Admin users can override registrations, bulk block, and manage settings")
                sup_submit = st.form_submit_button("Create Account")

                if sup_submit:
                    if not sup_user or len(sup_user) < 3:
                        st.error("Username must be at least 3 characters")
                    elif not sup_pass or len(sup_pass) < 6:
                        st.error("Password must be at least 6 characters")
                    elif sup_pass != sup_pass2:
                        st.error("Passwords do not match")
                    else:
                        err = signup(sup_user, sup_pass, is_admin=sup_admin, cookie_manager=cookie_manager)
                        if err:
                            st.error(err)
                        else:
                            st.success("Account created! Signing you in...")
                            st.rerun()
        
        st.markdown("---")
        st.caption("Make sure the backend is running at http://localhost:8000")


def main():
    """Main dashboard application."""
    # Cookie manager: persist login across browser refresh; logout after 1 day (token expiry)
    cookie_manager = None
    try:
        import extra_streamlit_components as stx
        cookie_manager = stx.CookieManager()
    except Exception:
        pass

    # Restore session from cookie so admin is not logged out on every refresh
    if restore_session_from_cookie(cookie_manager):
        st.rerun()

    # Check for OAuth callback token in URL
    try:
        qp = st.query_params
        token = qp.get("token") or (qp.get("token", [None])[0] if isinstance(qp.get("token"), list) else None)
        error_param = qp.get("error") or (qp.get("error", [None])[0] if isinstance(qp.get("error"), list) else None)
    except AttributeError:
        try:
            qp = st.experimental_get_query_params()
            token = qp.get("token", [None])[0]
            error_param = qp.get("error", [None])[0]
        except Exception:
            token = None
            error_param = None

    if token and not is_authenticated():
        if login_with_token(token, cookie_manager):
            # Clear token from URL
            try:
                st.query_params.clear()
            except (AttributeError, Exception):
                pass
            st.rerun()

    if error_param:
        st.error(f"OAuth error: {error_param}")

    # Show auth page if not authenticated
    if not is_authenticated():
        render_auth_page(cookie_manager)
        return
    
    # Initialize real-time change detection
    if 'last_data_state' not in st.session_state:
        st.session_state.last_data_state = None
    if 'check_interval' not in st.session_state:
        st.session_state.check_interval = 2  # Check every 2 seconds
    if 'last_check_time' not in st.session_state:
        st.session_state.last_check_time = datetime.now()
    if 'real_time_enabled' not in st.session_state:
        st.session_state.real_time_enabled = True  # Enabled by default
    
    # Real-time updates work silently in the background - no sidebar UI needed
    
    # Real-time change detection logic
    if st.session_state.real_time_enabled:
        time_since_check = (datetime.now() - st.session_state.last_check_time).total_seconds()
        
        if time_since_check >= st.session_state.check_interval:
            # Check if data has changed
            current_stats = get_stats()
            
            if current_stats:
                # Create a hash/signature of current state
                current_state = (
                    current_stats.get("total_registrations", 0),
                    current_stats.get("blocked_registrations", 0),
                    current_stats.get("flagged_registrations", 0),
                    current_stats.get("temporary_blocked", 0),
                    current_stats.get("unique_phones", 0)
                )
                
                # Compare with last known state
                if st.session_state.last_data_state is not None:
                    if current_state != st.session_state.last_data_state:
                        # Data has changed! Refresh immediately
                        st.session_state.last_data_state = current_state
                        st.session_state.last_change_detected = datetime.now()
                        st.session_state.last_check_time = datetime.now()
                        st.rerun()
                    else:
                        # No change, just update check time
                        st.session_state.last_check_time = datetime.now()
                else:
                    # First time, just store the state
                    st.session_state.last_data_state = current_state
                    st.session_state.last_check_time = datetime.now()
            else:
                # Stats unavailable, still update check time to avoid blocking
                st.session_state.last_check_time = datetime.now()
    
    # Header with user info and Logout button
    header_col1, header_col2, header_col3 = st.columns([2, 1, 1])
    with header_col1:
        st.markdown('<div class="main-header">📧 Email Abuse Detection Dashboard</div>', unsafe_allow_html=True)
    with header_col3:
        username = st.session_state.get("username", "user")
        if st.button("Logout", key="logout_btn", use_container_width=True):
            clear_auth_cookie(cookie_manager)
            logout(cookie_manager)
            st.rerun()
    st.caption(f"Signed in as **{username}**")
    st.markdown("---")
    
    # Tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📊 Overview",
        "📋 Registrations",
        "📱 Phone Numbers",
        "🚫 Blocked",
        "🔍 Manual Review",
        "🚨 Spam Detection",
        "📄 Reports"
    ])
    
    with tab1:
        tab_overview()
    
    with tab2:
        tab_registrations()
    
    with tab3:
        tab_phone_registrations()
    
    with tab4:
        tab_blocked_registrations()
    
    with tab5:
        tab_manual_review()
    
    with tab6:
        tab_spam_detection()
    
    with tab7:
        tab_reports()


if __name__ == "__main__":
    main()

