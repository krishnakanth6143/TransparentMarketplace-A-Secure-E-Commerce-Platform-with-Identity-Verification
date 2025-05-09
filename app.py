from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import cv2
import numpy as np
import pyotp
from datetime import datetime
from dotenv import load_dotenv
import secrets
import string
import shutil
import json
from utils import format_ist_time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marketplace.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER', 'your_mail')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD', 'your_password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER', 'your_mail')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.context_processor
def utility_processor():
    return {
        'format_ist_time': format_ist_time
    }

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    aadhaar_number = db.Column(db.String(12), unique=True, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_seller = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    face_verification = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(16))
    products = db.relationship('Product', backref='seller', lazy=True)
    complaints = db.relationship('Complaint', backref='user', lazy=True)
    ratings = db.relationship('Rating', backref='user_rating', lazy=True)
    wishlists = db.relationship('Wishlist', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # Generate OTP secret for each user
        self.otp_secret = pyotp.random_base32()
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_otp(self):
        totp = pyotp.TOTP(self.otp_secret, interval=300)  # 5-minute interval
        return totp.now()
    
    def verify_otp(self, otp):
        totp = pyotp.TOTP(self.otp_secret, interval=300)
        return totp.verify(otp)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String(200))
    certificate_path = db.Column(db.String(200))
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    avg_rating = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    complaints = db.relationship('Complaint', backref='product', lazy=True)
    ratings = db.relationship('Rating', backref='product_rating', lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False)
    shipping_address = db.Column(db.String(200), nullable=False)
    shipping_city = db.Column(db.String(100), nullable=False)
    shipping_zip = db.Column(db.String(20), nullable=False)
    shipping_country = db.Column(db.String(100), nullable=False)
    payment_method = db.Column(db.String(100), nullable=False)
    order_total = db.Column(db.Float, nullable=False)
    order_status = db.Column(db.String(20), nullable=False)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product_rating'),)

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product_wishlist'),)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    # Get products from database or create sample products if none exist
    products = Product.query.filter_by(is_verified=True).all()
    
    # If no products exist, create sample products
    if not products:
        # Create sample seller if none exists
        sample_seller = User.query.filter_by(username='sample_seller').first()
        if not sample_seller:
            sample_seller = User(
                username='sample_seller',
                email='sample@example.com',
                password_hash=generate_password_hash('password123'),
                is_verified=True,
                is_seller=True,
                face_verification=True,
                otp_secret=pyotp.random_base32()
            )
            db.session.add(sample_seller)
            db.session.commit()
        
        # Create sample products
        sample_products = [
            {
                'name': 'Premium Smartphone',
                'description': 'Latest model with advanced AI features, 5G connectivity, and a high-resolution camera.',
                'price': 74999.00,
                'image': 'images/products/smartphone.svg',
                'certificate': 'images/products/certificate1.svg'
            },
            {
                'name': 'Wireless Headphones',
                'description': 'Noise-cancelling headphones with premium sound quality and 30-hour battery life.',
                'price': 19999.00,
                'image': 'images/products/headphones.svg',
                'certificate': 'images/products/certificate2.svg'
            },
            {
                'name': 'Smart Watch',
                'description': 'Health tracking, notifications, and apps on your wrist with a beautiful OLED display.',
                'price': 29999.00,
                'image': 'images/products/smartwatch.svg',
                'certificate': 'images/products/certificate3.svg'
            }
        ]
        
        # Add sample products to database
        for product_data in sample_products:
            product = Product(
                name=product_data['name'],
                description=product_data['description'],
                price=product_data['price'],
                image_path=product_data['image'],
                certificate_path=product_data['certificate'],
                seller_id=sample_seller.id,
                is_verified=True
            )
            db.session.add(product)
        
        db.session.commit()
        
        # Get the newly created products
        products = Product.query.filter_by(is_verified=True).all()
    
    return render_template('home.html', products=products)

@app.route('/products')
def browse_products():
    # Get all verified products
    products = Product.query.filter_by(is_verified=True).all()
    return render_template('browse_products.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_seller = 'is_seller' in request.form
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email, is_seller=is_seller)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Send OTP for verification
        send_verification_email(new_user)
        
        flash('Registration successful! Please verify your email.', 'success')
        return redirect(url_for('verify_otp', user_id=new_user.id))
    
    return render_template('register.html')

@app.route('/verify-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        if user.verify_otp(otp):
            user.is_verified = True
            db.session.commit()
            flash('Email verified successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html', user_id=user_id)

@app.route('/resend-otp/<int:user_id>')
def resend_otp(user_id):
    user = User.query.get_or_404(user_id)
    send_verification_email(user)
    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('verify_otp', user_id=user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first!', 'warning')
                return redirect(url_for('verify_otp', user_id=user.id))
            
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/verify-face', methods=['GET', 'POST'])
@login_required
def verify_face():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No video file found!', 'danger')
            return redirect(url_for('verify_face'))
        
        video_file = request.files['video']
        if video_file.filename == '':
            flash('No video selected!', 'danger')
            return redirect(url_for('verify_face'))
        
        # Save video temporarily
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], f'face_verify_{current_user.id}.mp4')
        video_file.save(video_path)
        
        # Process video for face verification and deepfake detection
        # This is a placeholder - in a real application, you would use a proper deepfake detection model
        try:
            # Simulate face verification and deepfake detection
            # In a real application, you would use libraries like DeepFace or custom models
            current_user.face_verification = True
            db.session.commit()
            flash('Face verification successful!', 'success')
        except Exception as e:
            flash(f'Face verification failed: {str(e)}', 'danger')
        
        return redirect(url_for('profile'))
    
    return render_template('verify_face.html')

@app.route('/seller-dashboard')
@login_required
def seller_dashboard():
    if not current_user.is_seller:
        flash('You are not registered as a seller!', 'danger')
        return redirect(url_for('home'))
    
    products = Product.query.filter_by(seller_id=current_user.id).all()
    return render_template('seller_dashboard.html', products=products)

@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_seller:
        flash('You are not registered as a seller!', 'danger')
        return redirect(url_for('home'))
    
    if not current_user.face_verification:
        flash('Please complete face verification first!', 'warning')
        return redirect(url_for('verify_face'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        
        if 'image' not in request.files or 'certificate' not in request.files:
            flash('Both product image and certificate are required!', 'danger')
            return redirect(url_for('add_product'))
        
        image_file = request.files['image']
        certificate_file = request.files['certificate']
        
        if image_file.filename == '' or certificate_file.filename == '':
            flash('Both product image and certificate are required!', 'danger')
            return redirect(url_for('add_product'))
        
        # Save files
        image_filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{image_file.filename}")
        certificate_filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{certificate_file.filename}")
        
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        certificate_path = os.path.join(app.config['UPLOAD_FOLDER'], certificate_filename)
        
        image_file.save(image_path)
        certificate_file.save(certificate_path)
        
        # Create new product
        new_product = Product(
            name=name,
            description=description,
            price=float(price),
            image_path=image_filename,
            certificate_path=certificate_filename,
            seller_id=current_user.id
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product added successfully! It will be verified by our team.', 'success')
        return redirect(url_for('seller_dashboard'))
    
    return render_template('add_product.html')

@app.route('/product/<int:product_id>')
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    user_rating = None
    if current_user.is_authenticated:
        user_rating = Rating.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    ratings = Rating.query.filter_by(product_id=product_id).all()
    return render_template('product_detail.html', product=product, user_rating=user_rating, ratings=ratings)

@app.route('/rate_product/<int:product_id>', methods=['POST'])
@login_required
def rate_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Get rating data from form
    rating_value = int(request.form.get('rating'))
    review = request.form.get('review', '')
    
    # Check if user has already rated this product
    existing_rating = Rating.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    
    if existing_rating:
        # Update existing rating
        existing_rating.rating = rating_value
        existing_rating.review = review
        existing_rating.created_at = datetime.utcnow()
        db.session.commit()
        flash('Your rating has been updated!', 'success')
    else:
        # Create new rating
        new_rating = Rating(
            user_id=current_user.id,
            product_id=product_id,
            rating=rating_value,
            review=review
        )
        db.session.add(new_rating)
        db.session.commit()
        flash('Thank you for your rating!', 'success')
    
    # Update product's average rating
    ratings = Rating.query.filter_by(product_id=product_id).all()
    total_rating = sum(r.rating for r in ratings)
    avg_rating = total_rating / len(ratings) if ratings else 0
    
    product.avg_rating = avg_rating
    db.session.commit()
    
    return redirect(url_for('view_product', product_id=product_id))

@app.route('/delete_rating/<int:product_id>', methods=['POST'])
@login_required
def delete_rating(product_id):
    rating = Rating.query.filter_by(user_id=current_user.id, product_id=product_id).first_or_404()
    
    db.session.delete(rating)
    db.session.commit()
    
    # Update product's average rating
    ratings = Rating.query.filter_by(product_id=product_id).all()
    total_rating = sum(r.rating for r in ratings)
    avg_rating = total_rating / len(ratings) if ratings else 0
    
    product = Product.query.get(product_id)
    product.avg_rating = avg_rating
    db.session.commit()
    
    flash('Your rating has been deleted!', 'success')
    return redirect(url_for('view_product', product_id=product_id))

@app.route('/checkout')
@login_required
def checkout():
    product_id = request.args.get('product_id')
    
    # Check if we're coming from cart or direct buy
    cart_items_json = request.args.get('cart_items')
    
    if cart_items_json:
        # Coming from cart with multiple items
        try:
            cart_items = json.loads(cart_items_json)
            products = []
            total = 0
            
            for item in cart_items:
                product = Product.query.get(item['id'])
                if product:
                    quantity = item.get('quantity', 1)
                    item_total = product.price * quantity
                    products.append({
                        'product': product,
                        'quantity': quantity,
                        'total': item_total
                    })
                    total += item_total
            
            if not products:
                flash('No valid products in cart!', 'danger')
                return redirect(url_for('home'))
                
            # Calculate tax and shipping
            subtotal = total
            tax = subtotal * 0.1
            shipping = 100  # ₹100 shipping
            order_total = subtotal + tax + shipping
            
            return render_template('checkout.html', 
                                  products=products, 
                                  subtotal=subtotal,
                                  tax=tax,
                                  shipping=shipping,
                                  total=order_total,
                                  from_cart=True)
        except:
            flash('Error processing cart items!', 'danger')
            return redirect(url_for('home'))
    elif product_id:
        # Direct buy for a single product
        product = Product.query.get_or_404(product_id)
        return render_template('checkout.html', product=product)
    else:
        flash('No product selected for checkout!', 'danger')
        return redirect(url_for('home'))

@app.route('/report-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def report_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        description = request.form.get('description')
        
        new_complaint = Complaint(
            user_id=current_user.id,
            product_id=product_id,
            description=description
        )
        
        db.session.add(new_complaint)
        db.session.commit()
        
        flash('Complaint registered successfully!', 'success')
        return redirect(url_for('view_product', product_id=product.id))
    
    return render_template('report_product.html', product=product)

@app.route('/add-sample-products')
def add_sample_products():
    # Check if products already exist
    if Product.query.count() > 0:
        flash('Sample products already exist!', 'info')
        return redirect(url_for('home'))
    
    # Create sample seller if none exists
    sample_seller = User.query.filter_by(username='sample_seller').first()
    if not sample_seller:
        sample_seller = User(
            username='sample_seller',
            email='sample@example.com',
            password_hash=generate_password_hash('password123'),
            is_verified=True,
            is_seller=True,
            face_verification=True,
            otp_secret=pyotp.random_base32()
        )
        db.session.add(sample_seller)
        db.session.commit()
    
    # Create sample product images in static/images
    sample_images_dir = os.path.join('static', 'images', 'products')
    os.makedirs(sample_images_dir, exist_ok=True)
    
    # Create SVG sample product images
    products = [
        {
            'name': 'Premium Smartphone',
            'description': 'Latest model with advanced AI features, 5G connectivity, and a high-resolution camera.',
            'price': 74999.00,
            'image': 'images/products/smartphone.svg',
            'certificate': 'images/products/certificate1.svg'
        },
        {
            'name': 'Wireless Headphones',
            'description': 'Noise-cancelling headphones with premium sound quality and 30-hour battery life.',
            'price': 19999.00,
            'image': 'images/products/headphones.svg',
            'certificate': 'images/products/certificate2.svg'
        },
        {
            'name': 'Smart Watch',
            'description': 'Health tracking, notifications, and apps on your wrist with a beautiful OLED display.',
            'price': 29999.00,
            'image': 'images/products/smartwatch.svg',
            'certificate': 'images/products/certificate3.svg'
        }
    ]
    
    # Generate sample product images
    for product in products:
        # Create product in database
        new_product = Product(
            name=product['name'],
            description=product['description'],
            price=product['price'],
            image_path=product['image'],
            certificate_path=product['certificate'],
            seller_id=sample_seller.id,
            is_verified=True
        )
        db.session.add(new_product)
    
    db.session.commit()
    flash('Sample products added successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/buy-now/<int:product_id>')
@login_required
def buy_now(product_id):
    product = Product.query.get_or_404(product_id)
    seller = User.query.get(product.seller_id)
    
    # Check if product is verified
    if not product.is_verified:
        flash('This product is not verified yet.', 'warning')
        return redirect(url_for('view_product', product_id=product.id))
    
    # Create a single-item order for direct purchase
    order_items = [{
        'id': product.id,
        'name': product.name,
        'price': float(product.price),  # Ensure price is a float
        'quantity': 1,
        'image': url_for('static', filename=f'uploads/{product.image_path}')  # Make image path absolute
    }]
    
    # Calculate total
    total = float(product.price)  # Ensure total is a float
    
    return render_template('checkout.html', order_items=order_items, total=total, is_buy_now=True, seller=seller)

@app.route('/edit-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if the current user is the seller of this product
    if product.seller_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this product!', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        
        # Update product details
        product.name = name
        product.description = description
        product.price = float(price)
        
        # Handle image and certificate updates if provided
        if 'image' in request.files and request.files['image'].filename != '':
            image_file = request.files['image']
            image_filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{image_file.filename}")
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)
            product.image_path = image_filename
        
        if 'certificate' in request.files and request.files['certificate'].filename != '':
            certificate_file = request.files['certificate']
            certificate_filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{certificate_file.filename}")
            certificate_path = os.path.join(app.config['UPLOAD_FOLDER'], certificate_filename)
            certificate_file.save(certificate_path)
            product.certificate_path = certificate_filename
        
        # If admin edits a product, it remains verified
        # If seller edits, product needs to be re-verified
        if not current_user.is_admin:
            product.is_verified = False
            flash('Product updated successfully! It will need to be re-verified by our team.', 'success')
        else:
            flash('Product updated successfully!', 'success')
        
        db.session.commit()
        
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('seller_dashboard'))
    
    return render_template('edit_product.html', product=product)

@app.route('/create-order', methods=['POST'])
@login_required
def create_order():
    data = request.json
    
    # Create a new order
    new_order = Order(
        user_id=current_user.id,
        order_date=datetime.utcnow(),
        shipping_address=data['shipping_address'],
        shipping_city=data['shipping_city'],
        shipping_zip=data['shipping_zip'],
        shipping_country=data['shipping_country'],
        payment_method=data['payment_method'],
        order_total=float(data['order_total']),
        order_status='Processing'
    )
    
    db.session.add(new_order)
    db.session.flush()  # Get the order ID without committing
    
    # Add order items
    for item in data['items']:
        # Get the product from the database
        product = Product.query.get(item['id'])
        
        if product:
            # Get quantity from item or default to 1
            quantity = item.get('quantity', 1)
            
            # Create order item
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=product.id,
                quantity=quantity,
                price=product.price
            )
            
            db.session.add(order_item)
    
    # Commit all changes
    db.session.commit()
    
    return jsonify({
        'success': True,
        'order_id': new_order.id
    })

@app.route('/my-orders')
@login_required
def my_orders():
    # Get all orders for the current user
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.order_date.desc()).all()
    
    # Prepare order data for the template
    order_data = []
    for order in orders:
        # Get all items for this order
        items = OrderItem.query.filter_by(order_id=order.id).all()
        
        # Get product details for each item
        order_items = []
        order_total = 0
        
        for item in items:
            product = Product.query.get(item.product_id)
            if product:
                # Determine the image path
                if product.name == 'Premium Smartphone':
                    image_path = url_for('static', filename='images/products/smartphone.svg')
                elif product.name == 'Wireless Headphones':
                    image_path = url_for('static', filename='images/products/headphones.svg')
                elif product.name == 'Smart Watch':
                    image_path = url_for('static', filename='images/products/smartwatch.svg')
                else:
                    image_path = url_for('static', filename='uploads/' + product.image_path)
                
                # Calculate item total
                item_total = item.price * item.quantity
                order_total += item_total
                
                order_items.append({
                    'id': product.id,
                    'name': product.name,
                    'price': item.price,
                    'quantity': item.quantity,
                    'total': item_total,
                    'image': image_path
                })
        
        # Format the order date
        formatted_date = order.order_date.strftime('%B %d, %Y at %I:%M %p')
        
        # Add order to the list
        order_data.append({
            'id': order.id,
            'date': formatted_date,
            'status': order.order_status,
            'total': order.order_total,
            'order_items': order_items,
            'shipping_address': f"{order.shipping_address}, {order.shipping_city}, {order.shipping_zip}, {order.shipping_country}",
            'payment_method': order.payment_method
        })
    
    return render_template('my_orders.html', orders=order_data)

@app.route('/cancel-order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    # Get the order
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the current user
    if order.user_id != current_user.id:
        flash('You do not have permission to cancel this order.', 'danger')
        return redirect(url_for('my_orders'))
    
    # Check if the order is in a status that can be canceled
    if order.order_status in ['Delivered', 'Cancelled']:
        flash('This order cannot be cancelled.', 'warning')
        return redirect(url_for('my_orders'))
    
    # Update the order status to Cancelled
    order.order_status = 'Cancelled'
    db.session.commit()
    
    flash('Order has been cancelled successfully.', 'success')
    return redirect(url_for('my_orders'))

@app.route('/add-to-wishlist/<int:product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    # Check if product exists
    product = Product.query.get_or_404(product_id)
    
    # Check if product is already in user's wishlist
    existing_wishlist = Wishlist.query.filter_by(
        user_id=current_user.id, 
        product_id=product_id
    ).first()
    
    if existing_wishlist:
        # If already in wishlist, remove it
        db.session.delete(existing_wishlist)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Product removed from wishlist',
            'status': 'removed'
        })
    else:
        # Add to wishlist
        wishlist_item = Wishlist(
            user_id=current_user.id,
            product_id=product_id
        )
        db.session.add(wishlist_item)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Product added to wishlist',
            'status': 'added'
        })

@app.route('/wishlist')
@login_required
def view_wishlist():
    # Get all products in user's wishlist
    wishlist_items = Wishlist.query.filter_by(user_id=current_user.id).all()
    
    # Get product details for each wishlist item
    products = []
    for item in wishlist_items:
        product = Product.query.get(item.product_id)
        if product:
            # Determine the image path
            if product.name == 'Premium Smartphone':
                image_path = url_for('static', filename='images/products/smartphone.svg')
            elif product.name == 'Wireless Headphones':
                image_path = url_for('static', filename='images/products/headphones.svg')
            elif product.name == 'Smart Watch':
                image_path = url_for('static', filename='images/products/smartwatch.svg')
            else:
                image_path = url_for('static', filename='uploads/' + product.image_path)
            
            # Add product to the list with image path
            products.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': image_path,
                'seller': product.seller.username,
                'avg_rating': product.avg_rating,
                'added_on': format_ist_time(item.added_on)
            })
    
    return render_template('wishlist.html', products=products)

@app.route('/check-wishlist/<int:product_id>')
@login_required
def check_wishlist(product_id):
    # Check if product is in user's wishlist
    wishlist_item = Wishlist.query.filter_by(
        user_id=current_user.id, 
        product_id=product_id
    ).first()
    
    return jsonify({
        'in_wishlist': wishlist_item is not None
    })

# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    # Get counts for dashboard
    products_count = Product.query.count()
    users_count = User.query.count()
    complaints_count = Complaint.query.filter_by(status='pending').count()
    
    # Get pending products
    pending_products = Product.query.filter_by(is_verified=False).all()
    
    # Get complaints
    complaints = Complaint.query.filter_by(status='pending').all()
    
    # Get users
    users = User.query.all()
    
    return render_template('admin_dashboard.html', 
                           products_count=products_count,
                           users_count=users_count,
                           complaints_count=complaints_count,
                           pending_products=pending_products,
                           complaints=complaints,
                           users=users)

@app.route('/admin/dashboard/delete-product/<int:product_id>')
@login_required
def admin_dashboard_delete_product(product_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    product_name = product.name
    
    try:
        # First delete any complaints associated with this product
        Complaint.query.filter_by(product_id=product.id).delete()
        
        # Then delete the product
        db.session.delete(product)
        db.session.commit()
        flash(f'Product "{product_name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/verify-product/<int:product_id>')
@login_required
def admin_verify_product(product_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    product.is_verified = True
    db.session.commit()
    
    flash(f'Product "{product.name}" has been verified.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-product/<int:product_id>')
@login_required
def admin_reject_product(product_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    
    flash(f'Product "{product.name}" has been rejected and removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view-complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    complaint = Complaint.query.get_or_404(complaint_id)
    return render_template('view_complaint.html', complaint=complaint)

@app.route('/admin/resolve-complaint/<int:complaint_id>')
@login_required
def resolve_complaint(complaint_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.status = 'resolved'
    db.session.commit()
    
    flash('Complaint has been marked as resolved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-complaint/<int:complaint_id>')
@login_required
def reject_complaint(complaint_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.status = 'rejected'
    db.session.commit()
    
    flash('Complaint has been rejected.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view-user/<int:user_id>')
@login_required
def admin_view_user(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    products = Product.query.filter_by(seller_id=user.id).all() if user.is_seller else []
    
    return render_template('admin_view_user.html', user=user, products=products)

@app.route('/admin/make-seller/<int:user_id>')
@login_required
def admin_make_seller(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    user.is_seller = True
    db.session.commit()
    
    flash(f'User "{user.username}" has been granted seller privileges.', 'success')
    return redirect(url_for('admin_view_user', user_id=user.id))

@app.route('/admin/revoke-seller/<int:user_id>')
@login_required
def admin_revoke_seller(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    user.is_seller = False
    db.session.commit()
    
    flash(f'Seller privileges have been revoked from user "{user.username}".', 'success')
    return redirect(url_for('admin_view_user', user_id=user.id))

@app.route('/admin/toggle-user-status/<int:user_id>')
@login_required
def admin_toggle_user_status(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow toggling admin accounts
    if user.is_admin:
        flash('Cannot modify admin accounts.', 'danger')
        return redirect(url_for('admin_view_user', user_id=user.id))
    
    user.is_verified = not user.is_verified
    db.session.commit()
    
    status = 'activated' if user.is_verified else 'suspended'
    flash(f'User account "{user.username}" has been {status}.', 'success')
    return redirect(url_for('admin_view_user', user_id=user.id))

@app.route('/admin/unverify-product/<int:product_id>')
@login_required
def admin_unverify_product(product_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    product.is_verified = False
    db.session.commit()
    
    flash(f'Product "{product.name}" has been unmarked as verified.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/delete-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_delete_product(product_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    
    flash(f'Product "{product.name}" has been deleted.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/create-admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    # Only allow existing admins to create new admins
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('create_admin'))
        
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
        
        flash(f'Admin user "{username}" has been created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_admin.html')

@app.route('/make-me-admin')
@login_required
def make_me_admin():
    # This is a temporary route to create the first admin
    # It should be removed or secured in production
    current_user.is_admin = True
    db.session.commit()
    flash('You are now an admin!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/verify-aadhaar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_verify_aadhaar(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        aadhaar_number = request.form.get('aadhaar_number')
        
        # Validate Aadhaar number (simple validation for demo)
        if not aadhaar_number or len(aadhaar_number) != 12 or not aadhaar_number.isdigit():
            flash('Invalid Aadhaar number. It should be a 12-digit number.', 'danger')
            return redirect(url_for('admin_verify_aadhaar', user_id=user.id))
        
        # Check if Aadhaar is already assigned to another user
        existing_user = User.query.filter(User.aadhaar_number == aadhaar_number, User.id != user.id).first()
        if existing_user:
            flash('This Aadhaar number is already associated with another account.', 'danger')
            return redirect(url_for('admin_verify_aadhaar', user_id=user.id))
            
        # Update user's Aadhaar number
        user.aadhaar_number = aadhaar_number
        db.session.commit()
        
        flash(f'Aadhaar verification completed for {user.username}.', 'success')
        return redirect(url_for('admin_view_user', user_id=user.id))
    
    return render_template('admin_verify_aadhaar.html', user=user)

@app.route('/admin/remove-aadhaar/<int:user_id>')
@login_required
def admin_remove_aadhaar(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    
    if user.aadhaar_number:
        user.aadhaar_number = None
        db.session.commit()
        flash(f'Aadhaar details removed for {user.username}.', 'success')
    else:
        flash(f'No Aadhaar details found for {user.username}.', 'warning')
    
    return redirect(url_for('admin_view_user', user_id=user.id))

# Helper functions
def send_verification_email(user):
    otp = user.get_otp()
    msg = Message('Verify Your Email', recipients=[user.email])
    msg.body = f'''Hello {user.username},

Thank you for registering with Transparent Marketplace!

Your OTP for email verification is: {otp}

This OTP is valid for 5 minutes.

If you did not register on our platform, please ignore this email.

Best regards,
The Transparent Marketplace Team
'''
    mail.send(msg)

# Create database tables
with app.app_context():
    # Uncomment the next line to recreate all tables (WARNING: This will delete all data)
    # db.drop_all()
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
