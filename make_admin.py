from app import app, db, User

def make_user_admin(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"User '{username}' not found.")
            return False
        
        user.is_admin = True
        db.session.commit()
        print(f"User '{username}' has been made an admin successfully!")
        return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    make_user_admin(username)
