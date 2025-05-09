from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin_user(username, email, password):
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            print(f"User with username '{username}' or email '{email}' already exists.")
            return False
        
        # Create new admin user
        new_admin = User(
            username=username,
            email=email,
            is_verified=True,
            is_admin=True
        )
        new_admin.set_password(password)
        
        db.session.add(new_admin)
        db.session.commit()
        
        print(f"Admin user '{username}' created successfully!")
        return True

if __name__ == "__main__":
    username = "admin"
    email = "admin@example.com"
    password = "admin123"
    
    create_admin_user(username, email, password)
