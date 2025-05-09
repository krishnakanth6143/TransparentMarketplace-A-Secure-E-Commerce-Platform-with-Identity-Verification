import sqlite3
import os
import datetime

def update_schema():
    # Find the database file
    db_path = 'instance/marketplace.db'
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if created_at column exists in user table
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [column[1] for column in cursor.fetchall()]
        
        if 'created_at' not in user_columns:
            print("Adding 'created_at' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN created_at TIMESTAMP")
            
            # Set default value for existing records
            current_time = datetime.datetime.utcnow().isoformat()
            cursor.execute(f"UPDATE user SET created_at = '{current_time}'")
            
            conn.commit()
            print("Column added successfully!")
        else:
            print("Column 'created_at' already exists in user table.")
        
        conn.close()
        print("Schema update completed successfully.")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    update_schema()
