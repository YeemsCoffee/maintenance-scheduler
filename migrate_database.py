"""
Database Migration Script
Run this to add new columns to existing database
"""

import psycopg2
import os

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://yeems:supersecure@localhost:5432/maintenance_db')
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

print("Running migrations...")

# Migration 1: Add notification columns to users table
try:
    print("Adding notification preferences to users table...")
    cursor.execute("""
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS notify_assigned BOOLEAN DEFAULT TRUE,
        ADD COLUMN IF NOT EXISTS notify_due_soon BOOLEAN DEFAULT TRUE,
        ADD COLUMN IF NOT EXISTS notify_overdue BOOLEAN DEFAULT TRUE,
        ADD COLUMN IF NOT EXISTS notification_days_ahead INTEGER DEFAULT 3;
    """)
    print("✓ User notification columns added")
except Exception as e:
    print(f"✗ Error adding user columns: {e}")

# Migration 2: Add new columns to maintenance_tasks table
try:
    print("Adding new columns to maintenance_tasks table...")
    cursor.execute("""
        ALTER TABLE maintenance_tasks 
        ADD COLUMN IF NOT EXISTS assigned_to INTEGER REFERENCES users(id),
        ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS last_completed TIMESTAMP;
    """)
    print("✓ Task columns added")
except Exception as e:
    print(f"✗ Error adding task columns: {e}")

# Migration 3: Create task_completions table
try:
    print("Creating task_completions table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS task_completions (
            id SERIAL PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES maintenance_tasks(id) ON DELETE CASCADE,
            completed_by INTEGER NOT NULL REFERENCES users(id),
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scheduled_date TIMESTAMP NOT NULL,
            actual_date TIMESTAMP NOT NULL,
            notes TEXT,
            duration_minutes INTEGER,
            parts_used TEXT,
            labor_hours FLOAT,
            status VARCHAR(20) DEFAULT 'completed'
        );
    """)
    print("✓ task_completions table created")
except Exception as e:
    print(f"✗ Error creating task_completions table: {e}")

# Migration 4: Create notifications table
try:
    print("Creating notifications table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            task_id INTEGER REFERENCES maintenance_tasks(id) ON DELETE CASCADE,
            title VARCHAR(200) NOT NULL,
            message TEXT NOT NULL,
            type VARCHAR(50),
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            email_sent BOOLEAN DEFAULT FALSE
        );
    """)
    print("✓ notifications table created")
except Exception as e:
    print(f"✗ Error creating notifications table: {e}")

# Migration 5: Update existing tasks to have status
try:
    print("Updating existing tasks with status...")
    cursor.execute("""
        UPDATE maintenance_tasks 
        SET status = CASE 
            WHEN next_run < CURRENT_TIMESTAMP THEN 'overdue'
            ELSE 'pending'
        END
        WHERE status IS NULL;
    """)
    print("✓ Existing tasks updated")
except Exception as e:
    print(f"✗ Error updating tasks: {e}")

# Migration 6: Create indexes for performance
try:
    print("Creating indexes...")
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON maintenance_tasks(assigned_to);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON maintenance_tasks(status);
        CREATE INDEX IF NOT EXISTS idx_tasks_next_run ON maintenance_tasks(next_run);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_completions_task ON task_completions(task_id);
    """)
    print("✓ Indexes created")
except Exception as e:
    print(f"✗ Error creating indexes: {e}")

print("\nMigration completed!")
print("You can now restart your Flask application.")

cursor.close()
conn.close()