"""
Script to add api_key column to users table.
Run this once to update the database schema.
"""
import sqlite3
import os
from pathlib import Path

# Find database file
db_path = Path(__file__).parent / "email_abuse.db"
if not db_path.exists():
    # Try alternative location
    db_path = Path(__file__).parent.parent / "email_abuse.db"

print(f"Database path: {db_path}")

if not db_path.exists():
    print("❌ Database file not found. It will be created when the backend starts.")
    exit(0)

try:
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Check if column already exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'api_key' in columns:
        print("✅ api_key column already exists. No changes needed.")
    else:
        print("Adding api_key column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN api_key VARCHAR(255)")
        conn.commit()
        print("✅ Successfully added api_key column!")
    
    conn.close()
    print("✅ Database schema updated successfully!")
    
except Exception as e:
    print(f"❌ Error updating database: {e}")
    print("\nTrying alternative: Delete database to recreate...")
    try:
        if db_path.exists():
            db_path.unlink()
            print("✅ Database deleted. It will be recreated with the correct schema when backend starts.")
    except Exception as e2:
        print(f"❌ Could not delete database: {e2}")


