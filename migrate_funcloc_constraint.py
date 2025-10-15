"""
Database Migration Script - Fix Functional Location Constraints
Run this to allow duplicate names under different parents
"""

import psycopg2
import os

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://maintenance_app_user:krSPjD3SOsgKuLCF17y5MAfjM0oIfu9X@dpg-d3ma6215pdvs73b34img-a.oregon-postgres.render.com/maintenance_app')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Parse the database URL
from urllib.parse import urlparse
result = urlparse(DATABASE_URL)
username = result.username
password = result.password
database = result.path[1:]
hostname = result.hostname
port = result.port

print("Connecting to database...")
conn = psycopg2.connect(
    database=database,
    user=username,
    password=password,
    host=hostname,
    port=port
)

conn.autocommit = True
cursor = conn.cursor()

print("Running migration...")

try:
    # Drop the old unique constraint on name
    print("Removing old unique constraint on 'name' column...")
    cursor.execute("""
        ALTER TABLE functional_locations 
        DROP CONSTRAINT IF EXISTS functional_locations_name_key;
    """)
    print("✓ Old constraint removed")
    
    # Add new composite unique constraint
    print("Adding composite unique constraint on (name, parent_id)...")
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uix_name_parent 
        ON functional_locations (name, parent_id);
    """)
    print("✓ New constraint added")
    
    print("\n✓ Migration completed successfully!")
    print("You can now have locations with the same name under different parents.")
    print("Example: 'Floor 1' under 'Building A' AND 'Floor 1' under 'Building B'")
    
except Exception as e:
    print(f"✗ Error during migration: {e}")
    conn.rollback()

cursor.close()
conn.close()