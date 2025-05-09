import sqlite3
import os

def add_admin_column():
    # Find the database file
    db_path = 'instance/marketplace.db'
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_admin' not in columns:
            print("Adding 'is_admin' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0")
            conn.commit()
            print("Column added successfully!")
        else:
            print("Column 'is_admin' already exists.")
        
        # Make the first user an admin
        cursor.execute("UPDATE user SET is_admin = 1 WHERE id = 1")
        conn.commit()
        print("First user set as admin.")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    add_admin_column()
