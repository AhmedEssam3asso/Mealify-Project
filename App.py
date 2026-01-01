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

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get login credentials
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        # Verify user exists and password is correct
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Create user session
            flash(f"Welcome, {user.username}!", "success")
            return redirect(url_for('index'))
        flash("Invalid email or password!", "danger")
    
    return render_template("login.html")

# User logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    flash("Logged out successfully!", "info")
    return redirect(url_for('index'))

# Food ordering route
@app.route('/order', methods=['GET', 'POST'])
def order():
    user = current_user()
    if not user:
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get order details from form
        name = request.form.get('name')
        meal = request.form.get('meal')
        address = request.form.get('address')
        
        # Validate all fields are filled
        if not all([name, meal, address]):
            flash("Please fill all fields!", "danger")
            return redirect(url_for('order'))
        
        # Save order to database
        new_order = Order(
            user_id=user.id, 
            name=name, 
            meal=meal, 
            address=address
        )
        db.session.add(new_order)
        db.session.commit()
        
        flash(f"Order for '{meal}' placed successfully!", "success")
        return redirect(url_for('index'))

    return render_template("order.html", user=user)

# Table booking route
@app.route('/book_table', methods=['GET', 'POST'])
def book_table():
    user = current_user()
    if not user:
        flash("Please login first!", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get booking details from form
        name = request.form.get('name')
        table_number = request.form.get('table')
        booking_time = request.form.get('time')
        
        # Validate all fields are filled
        if not all([name, table_number, booking_time]):
            flash("Please fill all fields!", "danger")
            return redirect(url_for('book_table'))
        
        # Check if table is already booked at that time
        existing = TableBooking.query.filter_by(
            table_number=table_number, 
            booking_time=booking_time
        ).first()
        
        if existing:
            flash("Table already booked at this time!", "danger")
        else:
            # Save booking to database
            new_booking = TableBooking(
                user_id=user.id,
                name=name,
                table_number=table_number,
                booking_time=booking_time
            )
            db.session.add(new_booking)
            db.session.commit()
            flash(f"Table {table_number} booked for {booking_time}!", "success")
            return redirect(url_for('index'))

    return render_template("book_table.html", user=user)

# Admin dashboard route
@app.route('/admin')
def admin():
    if not is_admin():
        flash("Admin access only!", "danger")
        return redirect(url_for('index'))
    
    # Get all data for admin to view
    users = User.query.all()
    orders = Order.query.all()
    bookings = TableBooking.query.all()
    messages = ContactMessage.query.all()
    
    return render_template(
        "admin.html", 
        users=users, 
        orders=orders, 
        bookings=bookings,
        messages=messages,
        user=current_user()
    )

# Delete user route (admin only)
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if not is_admin():
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    # Also delete user's bookings and orders
    TableBooking.query.filter_by(user_id=user_id).delete()
    Order.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    
    flash("User deleted!", "success")
    return redirect(url_for('admin'))

# Delete order route (admin only)
@app.route('/delete_order/<int:order_id>')
def delete_order(order_id):
    if not is_admin():
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    
    flash("Order deleted!", "success")
    return redirect(url_for('admin'))

# Delete booking route (admin only)
@app.route('/delete_booking/<int:booking_id>')
def delete_booking(booking_id):
    if not is_admin():
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    booking = TableBooking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    
    flash("Booking deleted!", "success")
    return redirect(url_for('admin'))

# Delete message route (admin only)
@app.route('/delete_message/<int:message_id>')
def delete_message(message_id):
    if not is_admin():
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    message = ContactMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    
    flash("Message deleted!", "success")
    return redirect(url_for('admin'))

# Start the Flask application
if __name__ == "__main__":
    app.run(debug=False)