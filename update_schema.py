from app import app, db
import sqlite3

def add_is_admin_column():
    with app.app_context():
        # Check if column already exists using SQLAlchemy
        inspector = db.inspect(db.engine)
        columns = [column['name'] for column in inspector.get_columns('user')]
        
        if 'is_admin' not in columns:
            print("Adding 'is_admin' column to user table...")
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
            print("Column added successfully!")
        else:
            print("Column 'is_admin' already exists.")

def update_schema_with_rating():
    with app.app_context():
        try:
            # Add the rating column to the Product model if it doesn't exist
            inspector = db.inspect(db.engine)
            
            # Check if product table exists
            if inspector.has_table('product'):
                columns = [column['name'] for column in inspector.get_columns('product')]
                
                if 'avg_rating' not in columns:
                    with db.engine.connect() as conn:
                        conn.execute(db.text('ALTER TABLE product ADD COLUMN avg_rating FLOAT DEFAULT 0'))
                    print("Added avg_rating column to Product model")
                else:
                    print("Column 'avg_rating' already exists in Product model")
            else:
                print("Product table does not exist yet. Run the app first to create tables.")
                return
            
            # Create the Rating table if it doesn't exist
            if not inspector.has_table('rating'):
                with db.engine.connect() as conn:
                    conn.execute(db.text('''
                        CREATE TABLE rating (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            product_id INTEGER NOT NULL,
                            rating INTEGER NOT NULL,
                            review TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES user (id),
                            FOREIGN KEY (product_id) REFERENCES product (id),
                            UNIQUE (user_id, product_id)
                        )
                    '''))
                print("Created Rating table")
            else:
                print("Rating table already exists")
            
            print("Database schema updated successfully!")
        except Exception as e:
            print(f"Error updating schema: {e}")
            print("Make sure you've run the app at least once to create the initial database tables.")

if __name__ == "__main__":
    try:
        add_is_admin_column()
        update_schema_with_rating()
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure the database exists and the app has been run at least once.")
