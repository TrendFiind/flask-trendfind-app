"""
TrendFind - Product Discovery Platform
Core Application File (app.py)

Features:
- User authentication (email + password, Google OAuth)
- Product search and saving
- User profile management
- Billing/subscription system
- Activity tracking and analytics

Security Features:
- CSRF protection
- Rate limiting
- Secure headers
- Input sanitization
- Password hashing
- Session security

Database Schema:
- users: Core user accounts
- saved_products: User's saved products
- user_stats: User activity statistics
- billing_info: Payment/subscription data
- user_activity: Activity log
- contact_submissions: Contact form entries
"""

import os
import re
import psycopg2
import sqlite3
import bleach
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, request, flash, redirect, 
    url_for, session, jsonify, g, abort
)
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError
import logging

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# ==================== CONFIGURATION ====================
class Config:
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    
    # Database
    DATABASE = 'database.db'
    
    # Email
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')
    
    # Rate limiting
    RATE_LIMITS = ["200 per day", "50 per hour"]

app.config.from_object(Config)

# ==================== FORM CLASSES ====================
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject')
    message = TextAreaField('Message', validators=[DataRequired()])
    
    def validate_email(self, field):
        """Validate email format"""
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', field.data):
            raise ValidationError('Invalid email address')

# ==================== EXTENSIONS ====================
# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=app.config['RATE_LIMITS'],
    storage_uri="memory://"
)

# Email
mail = Mail(app)

# OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

# ==================== DATABASE ====================
def get_db():
    """Get database connection with row factory"""
    if 'db' not in g:
        # Use SQLite for local development if DATABASE_URL isn't set
        if 'DATABASE_URL' not in os.environ:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        else:
            # Use PostgreSQL in production
            result = urlparse(os.environ['DATABASE_URL'])
            g.db = psycopg2.connect(
                database=result.path[1:],
                user=result.username,
                password=result.password,
                host=result.hostname,
                port=result.port
            )
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Close database connection at end of request"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with required tables"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        
        # Check if users table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            );
        """)
        
        if not cur.fetchone()[0]:
            # Create all tables
            # ... your table creation SQL here ...
            db.commit()
        
        # Enable foreign key constraints
        db.execute("PRAGMA foreign_keys = ON")
        
        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                name TEXT,
                phone TEXT,
                image TEXT DEFAULT 'default-profile.jpg',
                two_factor TEXT DEFAULT 'disabled',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Saved products
        db.execute('''
            CREATE TABLE IF NOT EXISTS saved_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id TEXT NOT NULL,
                title TEXT NOT NULL,
                price TEXT NOT NULL,
                image TEXT NOT NULL,
                link TEXT NOT NULL,
                retailer TEXT NOT NULL,
                description TEXT,
                rating TEXT,
                ratings_total INTEGER,
                saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user_id, product_id)
            )
        ''')
        
        # User statistics
        db.execute('''
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id INTEGER PRIMARY KEY,
                products_saved INTEGER DEFAULT 0,
                winning_finds INTEGER DEFAULT 0,
                active_projects INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Billing information
        db.execute('''
            CREATE TABLE IF NOT EXISTS billing_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                card_last4 TEXT,
                card_brand TEXT,
                card_expiry TEXT,
                billing_address TEXT,
                plan_name TEXT DEFAULT 'Free',
                plan_price REAL DEFAULT 0,
                next_billing_date TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # User activity log
        db.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                activity_details TEXT,
                activity_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Contact submissions
        db.execute('''
            CREATE TABLE IF NOT EXISTS contact_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT,
                message TEXT NOT NULL,
                ip_address TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Create indexes for performance
        db.execute('CREATE INDEX IF NOT EXISTS idx_saved_products_user ON saved_products(user_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity(user_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_user_activity_time ON user_activity(activity_time)')
        
        db.commit()

# ==================== HELPER FUNCTIONS ====================
def clean_input(input_str):
    """Sanitize user input to prevent XSS"""
    if input_str is None:
        return ''
    return bleach.clean(str(input_str).strip())

def track_user_activity(user_id, activity_type, details=None):
    """Record user activity in the database"""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO user_activity (user_id, activity_type, activity_details) VALUES (?, ?, ?)",
            (user_id, clean_input(activity_type), clean_input(details))
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Error tracking activity: {e}")

def update_user_stats(user_id, field):
    """Increment a stat field for a user"""
    try:
        db = get_db()
        
        # Check if stats record exists
        stats = db.execute(
            "SELECT 1 FROM user_stats WHERE user_id = ?", 
            (user_id,)
        ).fetchone()
        
        if not stats:
            # Create stats record if it doesn't exist
            db.execute(
                "INSERT INTO user_stats (user_id) VALUES (?)",
                (user_id,)
            )
        
        # Increment the specified field
        db.execute(
            f"UPDATE user_stats SET {field} = {field} + 1 WHERE user_id = ?",
            (user_id,)
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Error updating user stats: {e}")

def get_success_rate(user_id):
    """Calculate user's success rate (winning finds / products saved)"""
    try:
        db = get_db()
        stats = db.execute(
            "SELECT products_saved, winning_finds FROM user_stats WHERE user_id = ?", 
            (user_id,)
        ).fetchone()
        
        if stats and stats['products_saved'] > 0:
            return (stats['winning_finds'] / stats['products_saved']) * 100
        return 0
    except Exception as e:
        app.logger.error(f"Error calculating success rate: {e}")
        return 0

# ==================== SECURITY MIDDLEWARE ====================
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def login_required(f):
    """Decorator to ensure user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """500 error handler"""
    app.logger.error(f"500 Error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """CSRF error handler"""
    app.logger.warning(f"CSRF Error: {str(e)}")
    return render_template('csrf_error.html'), 400

# ==================== ROUTES ====================
@app.route("/")
def home():
    """Home page with product search"""
    if request.method == "POST":
        query = clean_input(request.form.get("query", ""))
        if not query:
            flash("Please enter a search term", "error")
            return redirect(url_for("home"))
        return redirect(url_for("results", query=query))
    return render_template("index.html")

@app.route("/results")
def results():
    """Display search results"""
    query = clean_input(request.args.get("query", ""))
    retailer = clean_input(request.args.get("retailer", "All"))
    
    # Implement your search logic here
    products = []  # This would be populated with actual search results
    
    return render_template("results.html", 
                         products=products, 
                         query=query, 
                         retailer=retailer)

# ==================== AUTHENTICATION ROUTES ====================
@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration"""
    if request.method == "POST":
        email = clean_input(request.form.get("email", "").lower())
        password = request.form.get("password", "")
        name = clean_input(request.form.get("name", ""))
        
        if not all([email, password]):
            flash("Email and password are required", "error")
            return redirect(url_for("register"))
        
        db = get_db()
        try:
            # Check if email exists
            if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                flash("Email already registered", "error")
                return redirect(url_for("register"))
            
            # Create user
            hashed_password = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
                (email, hashed_password, name))
            
            # Initialize stats
            db.execute(
                "INSERT INTO user_stats (user_id) VALUES (?)",
                (db.execute("SELECT last_insert_rowid()").fetchone()[0],))
            
            db.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        
        except Exception as e:
            db.rollback()
            app.logger.error(f"Registration error: {e}")
            flash("Registration failed. Please try again.", "error")
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with email/password"""
    if request.method == "POST":
        email = clean_input(request.form.get("email", "").lower())
        password = request.form.get("password", "")
        
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", 
            (email,)
        ).fetchone()
        
        if user and check_password_hash(user["password"], password):
            # Successful login
            session["user_id"] = user["id"]
            session["user_email"] = user["email"]
            session["user_name"] = user["name"] or "User"
            
            # Update last login
            db.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user["id"],))
            db.commit()
            
            track_user_activity(user["id"], "login", "User logged in")
            flash("Login successful!", "success")
            return redirect(url_for("profile"))
        
        flash("Invalid email or password", "error")
    
    return render_template("login.html")

@app.route("/login/google")
def google_login():
    """Initiate Google OAuth login"""
    if not os.getenv("GOOGLE_CLIENT_ID"):
        flash("Google login is not configured", "error")
        return redirect(url_for("login"))
    return google.authorize_redirect(url_for("google_authorize", _external=True))

@app.route('/login/google/authorize')
def google_authorize():
    """Google OAuth callback"""
    try:
        token = google.authorize_access_token()
        if not token:
            return "Access denied: Failed to obtain access token", 403
            
        # Get userinfo from Google
        userinfo = google.parse_id_token(token)
        if not userinfo:
            return "Failed to fetch user information", 400
            
        # Extract user data
        email = userinfo.get('email')
        if not email:
            return "Email not provided by Google", 400
            
        name = userinfo.get('name', 'User')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if not user:
            # Create new user
            db.execute(
                'INSERT INTO users (email, name) VALUES (?, ?)', 
                (email, name))
            
            # Initialize stats
            user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute(
                "INSERT INTO user_stats (user_id) VALUES (?)",
                (user_id,))
            
            db.commit()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        # Log user in
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name'] or 'User'
        
        # Update last login
        db.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user["id"],))
        db.commit()
        
        track_user_activity(user["id"], "login", "User logged in via Google")
        return redirect(url_for('profile'))
        
    except Exception as e:
        app.logger.error(f"Google auth error: {str(e)}")
        flash('Google authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route("/logout")
def logout():
    """Log out current user"""
    if 'user_id' in session:
        track_user_activity(session['user_id'], "logout", "User logged out")
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("home"))

# ==================== PROFILE ROUTES ====================
@app.route("/profile")
@login_required
def profile():
    """User profile dashboard"""
    try:
        db = get_db()
        
        # Get user info
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", 
            (session["user_id"],)
        ).fetchone()
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for("login"))
            
        # Get user stats
        stats = db.execute(
            "SELECT * FROM user_stats WHERE user_id = ?", 
            (session["user_id"],)
        ).fetchone()
        
        # Get billing info
        billing = db.execute(
            "SELECT * FROM billing_info WHERE user_id = ? ORDER BY id DESC LIMIT 1", 
            (session["user_id"],)
        ).fetchone()
        
        # Get recent activity
        activities = db.execute(
            "SELECT * FROM user_activity WHERE user_id = ? ORDER BY activity_time DESC LIMIT 5", 
            (session["user_id"],)
        ).fetchall()
        
        # Format dates
        created_at = user["created_at"][:10] if user.get("created_at") else "Unknown"
        next_billing = billing["next_billing_date"][:10] if billing and billing.get("next_billing_date") else None
        
        return render_template("profile.html", 
                             user=user,
                             stats=stats,
                             success_rate=round(get_success_rate(session["user_id"]), 1),
                             billing=billing,
                             activities=activities,
                             created_at=created_at,
                             next_billing=next_billing)
        
    except Exception as e:
        app.logger.error(f"Profile error: {e}")
        flash("Error loading profile", "error")
        return redirect(url_for("home"))

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    """Update user profile information"""
    name = clean_input(request.form.get("name", ""))
    email = clean_input(request.form.get("email", "").lower())
    phone = clean_input(request.form.get("phone", ""))
    
    if not email:
        flash("Email is required", "error")
        return redirect(url_for("profile"))
    
    db = get_db()
    try:
        # Check if email is taken by another user
        existing = db.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            (email, session["user_id"])
        ).fetchone()
        
        if existing:
            flash("Email already in use by another account", "error")
            return redirect(url_for("profile"))
        
        # Update profile
        db.execute(
            "UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?",
            (name, email, phone, session["user_id"])
        )
        db.commit()
        
        # Update session
        session["user_name"] = name or "User"
        session["user_email"] = email
        
        track_user_activity(session["user_id"], "profile_update", "Updated profile information")
        flash("Profile updated successfully", "success")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Profile update error: {e}")
        flash("Error updating profile", "error")
    
    return redirect(url_for("profile"))

@app.route("/update-avatar", methods=["POST"])
@login_required
def update_avatar():
    """Update user avatar/profile picture"""
    if 'avatar' not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"}), 400
    
    file = request.files['avatar']
    
    # Validate file
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
    
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({"success": False, "message": "Invalid file type"}), 400
    
    # Check file size (max 2MB)
    if file.content_length > 2 * 1024 * 1024:
        return jsonify({"success": False, "message": "File too large (max 2MB)"}), 400
    
    try:
        # Save the file (in a real app, you'd use S3 or similar)
        filename = f"user_{session['user_id']}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(app.root_path, 'static', 'uploads', 'avatars', filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        file.save(filepath)
        
        # Update database
        db = get_db()
        db.execute(
            "UPDATE users SET image = ? WHERE id = ?", 
            (f"uploads/avatars/{filename}", session['user_id']))
        db.commit()
        
        track_user_activity(session["user_id"], "avatar_update", "Updated profile picture")
        return jsonify({"success": True, "message": "Avatar updated successfully"})
    
    except Exception as e:
        app.logger.error(f"Error updating avatar: {e}")
        return jsonify({"success": False, "message": "Error updating avatar"}), 500

@app.route("/update-security", methods=["POST"])
@login_required
def update_security():
    """Update security settings (password, 2FA)"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    two_factor = clean_input(request.form.get('two_factor', 'disabled'))
    
    db = get_db()
    try:
        user = db.execute(
            "SELECT password FROM users WHERE id = ?", 
            (session['user_id'],)
        ).fetchone()
        
        # Validate current password if changing password
        if new_password:
            if not current_password:
                flash('Current password is required to change password', 'error')
                return redirect(url_for('profile'))
            
            if not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            
            # Validate new password
            if len(new_password) < 8:
                flash('Password must be at least 8 characters', 'error')
                return redirect(url_for('profile'))
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            db.execute(
                "UPDATE users SET password = ? WHERE id = ?", 
                (hashed_password, session['user_id']))
        
        # Update two-factor setting
        db.execute(
            "UPDATE users SET two_factor = ? WHERE id = ?", 
            (two_factor, session['user_id']))
        
        db.commit()
        track_user_activity(session["user_id"], "security_update", "Updated security settings")
        flash('Security settings updated successfully', 'success')
    except Exception as e:
        db.rollback()
        app.logger.error(f"Security update error: {e}")
        flash('Error updating security settings', 'error')
    
    return redirect(url_for('profile'))

@app.route("/update-billing", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def update_billing():
    """Update billing/payment information"""
    card_number = clean_input(request.form.get('card_number', ''))
    card_expiry = clean_input(request.form.get('card_expiry', ''))
    card_cvc = clean_input(request.form.get('card_cvc', ''))
    billing_address = clean_input(request.form.get('billing_address', ''))
    plan_name = clean_input(request.form.get('plan_name', 'Premium'))
    plan_price = float(request.form.get('plan_price', 29.00))

    # Basic validation
    if not all([card_number, card_expiry, billing_address]):
        flash('Please fill all required billing fields', 'error')
        return redirect(url_for('profile'))

    try:
        # Extract last 4 digits and card brand (simplified)
        last4 = card_number[-4:] if len(card_number) >= 4 else '4242'
        card_brand = 'visa' if card_number.startswith('4') else 'mastercard'

        db = get_db()
        db.execute(
            """INSERT INTO billing_info 
            (user_id, card_last4, card_brand, card_expiry, billing_address, plan_name, plan_price, next_billing_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, date('now', '+1 month'))""",
            (session['user_id'], last4, card_brand, card_expiry, billing_address, plan_name, plan_price)
        )
        db.commit()
        
        track_user_activity(session["user_id"], "billing_update", "Updated billing information")
        flash('Billing information updated successfully', 'success')
    except Exception as e:
        db.rollback()
        app.logger.error(f"Billing update error: {e}")
        flash('Error updating billing information', 'error')
    
    return redirect(url_for('profile'))

# ==================== PRODUCT ROUTES ====================
@app.route("/saved-products")
@login_required
def saved_products():
    """View saved products"""
    db = get_db()
    products = db.execute(
        "SELECT * FROM saved_products WHERE user_id = ? ORDER BY saved_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("saved-products.html", products=products)

@app.route('/initdb')
def initdb():
    init_db()
    return 'Database initialized', 200

@app.route("/save-product", methods=["POST"])
@login_required
def save_product():
    """Save a product to user's collection"""
    try:
        product_data = {
            "user_id": session["user_id"],
            "product_id": clean_input(request.form.get("product_id", "")),
            "title": clean_input(request.form.get("title", "")),
            "price": clean_input(request.form.get("price", "")),
            "image": clean_input(request.form.get("image", "")),
            "link": clean_input(request.form.get("link", "")),
            "retailer": clean_input(request.form.get("retailer", "Unknown")),
            "description": clean_input(request.form.get("description", "")),
            "rating": clean_input(request.form.get("rating", "")),
            "ratings_total": int(clean_input(request.form.get("ratings_total", 0)))
        }

        if not all([product_data["product_id"], product_data["title"]]):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        db = get_db()
        # Check if product already saved
        existing = db.execute(
            "SELECT id FROM saved_products WHERE user_id = ? AND product_id = ?",
            (session["user_id"], product_data["product_id"])
        ).fetchone()

        if existing:
            return jsonify({"status": "error", "message": "Product already saved"}), 400

        db.execute(
            """INSERT INTO saved_products 
            (user_id, product_id, title, price, image, link, retailer, description, rating, ratings_total)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            tuple(product_data.values())
        )
        
        # Update user stats
        update_user_stats(session["user_id"], "products_saved")
        
        # Track activity
        track_user_activity(
            session["user_id"], 
            "save", 
            f"\"{product_data['title']}\" added to saved products"
        )
        
        db.commit()
        return jsonify({"status": "success"})

    except Exception as e:
        app.logger.error(f"Error saving product: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 500

@app.route("/remove-product/<int:product_id>", methods=["POST"])
@login_required
def remove_product(product_id):
    """Remove a saved product"""
    db = get_db()
    try:
        # Get product title before deleting for activity log
        product = db.execute(
            "SELECT title FROM saved_products WHERE id = ? AND user_id = ?",
            (product_id, session["user_id"])
        ).fetchone()
        
        if not product:
            flash("Product not found", "error")
            return redirect(url_for("saved-products"))

        db.execute(
            "DELETE FROM saved_products WHERE id = ? AND user_id = ?",
            (product_id, session["user_id"])
        )
        
        # Track activity
        track_user_activity(
            session["user_id"],
            "remove",
            f"\"{product['title']}\" removed from saved products"
        )
        
        db.commit()
        flash("Product removed successfully", "success")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error removing product: {e}")
        flash("Error removing product", "error")
    
    return redirect(url_for("saved-products"))

# ==================== OTHER ROUTES ====================
@app.route("/contact-us", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def contact_us():
    """Contact form with rate limiting"""
    form = ContactForm()
    
    if form.validate_on_submit():
        try:
            # Sanitize inputs
            name = clean_input(form.name.data)
            email = clean_input(form.email.data)
            subject = clean_input(form.subject.data) if form.subject.data else None
            message = clean_input(form.message.data)
            ip_address = request.remote_addr

            # Save to database
            db = get_db()
            db.execute(
                """INSERT INTO contact_submissions 
                (name, email, subject, message, ip_address)
                VALUES (?, ?, ?, ?, ?)""",
                (name, email, subject, message, ip_address)
            )
            db.commit()

            # Try to send email
            try:
                msg = Message(
                    subject=f"New Contact: {subject or 'No Subject'}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[app.config['MAIL_USERNAME']],
                    body=f"""
                    New contact form submission:
                    
                    Name: {name}
                    Email: {email}
                    Subject: {subject or 'None'}
                    IP Address: {ip_address}
                    
                    Message:
                    {message}
                    """
                )
                mail.send(msg)
                app.logger.info("Contact email sent successfully")
            except Exception as e:
                app.logger.error(f"Email sending failed: {str(e)}")

            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('contact_us'))
            
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            flash('Failed to process your message. Please try again later.', 'error')
    
    return render_template('contact-us.html', form=form)

@app.route("/about-us")
def about_us():
    """About us page"""
    return render_template("about-us.html")

@app.route("/faq")
def faq():
    """FAQ page"""
    return render_template("faq.html")

@app.route("/plan-details")
def plan_details():
    """Subscription plan details"""
    return render_template("plan-details.html")

# ==================== MAIN APPLICATION ====================
if __name__ == "__main__":
    # Initialize database
    with app.app_context():
        init_db()
    
    # Configure logging
    if not app.debug:
        file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
    
    # Run application
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
