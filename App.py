from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Secret key for session security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Database file location
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)  # Connect database to app

# ========== DATABASE MODELS (TABLES) ==========

# User table for storing user accounts
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Order table for storing food delivery orders
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    meal = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(300), nullable=False)

# TableBooking table for storing restaurant table reservations
class TableBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    table_number = db.Column(db.Integer, nullable=False)
    booking_time = db.Column(db.String(50), nullable=False)

# ContactMessage table for storing customer inquiries
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ========== DATABASE SETUP ==========

def setup_database():
    # Check if database file already exists
    db_exists = os.path.exists('database.db')
    
    with app.app_context():
        if not db_exists:
            # Create all database tables
            db.create_all()
            print("✅ Database created successfully")
            
            # Create admin user for managing the website
            try:
                # Check if admin already exists to avoid duplicates
                existing_admin = User.query.filter_by(email="admin@mealify.com").first()
                if not existing_admin:
                    admin_user = User(
                        username="admin",
                        email="admin@mealify.com",
                        password=generate_password_hash("admin123", method='pbkdf2:sha256')
                    )
                    db.session.add(admin_user)
                    db.session.commit()
                    print("✅ Admin account created - Username: admin, Password: admin123")
                else:
                    print("ℹ️ Admin account already exists")
            except Exception as e:
                print(f"❌ Error creating admin: {e}")
                db.session.rollback()
        else:
            print("ℹ️ Database already exists, skipping setup")

# Run database setup when app starts
setup_database()

# ========== HELPER FUNCTIONS ==========

def current_user():
    # Check if user is logged in by looking at session
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def is_admin():
    # Check if current user is the admin
    user = current_user()
    return user and user.username.lower() == "admin"

# ========== WEBSITE ROUTES ==========

# Home page route
@app.route('/')
def index():
    user = current_user()
    return render_template("index.html", user=user)

# Contact form submission route
@app.route('/contact', methods=['POST'])
def contact():
    if request.method == 'POST':
        # Get form data from contact form
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Check if all fields are filled
        if not all([name, email, subject, message]):
            flash("Please fill all fields!", "danger")
            return redirect(url_for('index', _anchor='contact'))
        
        # Save message to database
        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message
        )
        db.session.add(new_message)
        db.session.commit()
        
        flash("Your message has been sent successfully!", "success")
        return redirect(url_for('index', _anchor='contact'))

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get registration form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords match
        if password != confirm_password:
            flash("Passwords don't match!", "danger")
            return redirect(url_for('register'))
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for('register'))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))
        
        # Create new user with hashed password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))
    
    return render_template("register.html")
