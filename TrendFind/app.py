import os
import requests
import sqlite3
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, g
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler
from bleach import clean
from flask_wtf.csrf import CSRFProtect, CSRFError  # Add CSRFError to the import

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Security configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    TEMPLATES_AUTO_RELOAD=True
)

# CSRF Protection
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configuration checks
required_vars = ["FLASK_SECRET_KEY", "MAIL_USERNAME", "MAIL_PASSWORD", "RAPIDAPI_KEY"]
if not all(os.getenv(var) for var in required_vars):
    raise ValueError("Missing required environment variables")

# Database setup with connection pooling
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('database.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                name TEXT,
                image TEXT DEFAULT 'default-profile.jpg',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Saved products table
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
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Contact submissions table
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
        db.commit()

init_db()

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")
mail = Mail(app)

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    },
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/'
)

# Logging configuration
if not app.debug:
    file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"500 Error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.warning(f"CSRF Error: {str(e)}")
    return render_template('csrf_error.html'), 400

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Product Search Functions ---
def search_amazon_products(query):
    url = "https://real-time-amazon-data.p.rapidapi.com/search"
    querystring = {"query": query, "page": "1", "country": "US"}
    headers = {
        "X-RapidAPI-Key": os.getenv("RAPIDAPI_KEY"),
        "X-RapidAPI-Host": "real-time-amazon-data.p.rapidapi.com"
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        results = response.json()

        products = []
        for item in results.get("data", {}).get("products", []):
            title = item.get("product_title", "N/A")
            price = item.get("product_price", "N/A")
            rating = item.get("product_star_rating", "N/A")
            ratings_total = item.get("product_num_ratings", 0)
            link = item.get("product_url", "N/A")
            image = item.get("product_photo", "N/A")

            if price == "N/A" or not any(c.isdigit() for c in price):
                continue

            description = f"{title} is a high-quality product with excellent features."

            products.append({
                "Title": title,
                "Price": price,
                "Rating": rating,
                "Ratings Total": ratings_total,
                "Link": link,
                "Image": image,
                "Description": description,
                "Retailer": "Amazon"
            })

        # Filter out digital products
        block_list = ["Kindle Store", "eBook", "Kindle Edition", "Audible Audiobook", "Streaming Video", 
            "Streaming Music", "Digital Music", "MP3 Download", "Digital Code", "Game Code", 
            "Digital Gift Card", "Subscription", "Amazon Music Unlimited", "Amazon Music Prime", 
            "Audible Original", "Movie Download", "TV Show Download", "Digital Software", 
            "Software License", "Digital Download", "Digital Content", "Digital Subscription", 
            "Video Streaming", "Game Download", "Game Digital Code", "Virtual Currency", 
            "Virtual Goods", "In-game Purchases", "Online Course", "Digital Learning", 
            "Digital Art Download", "Stock Photos", "Printable Art", "Photo Editing Software", 
            "Digital Prints", "Virtual Reality", "Augmented Reality", "Cloud Storage", 
            "SaaS Subscription", "Data Services", "Financial Data Subscription", 
            "Investment Software", "VR Game", "VR App", "AR Experience", "Mobile App", 
            "Android App", "iOS App", "Software as a Service", "App Subscription", 
            "Digital Product", "Digital License", "Digital Media", "Digital File", 
            "Online Streaming", "Video on Demand", "Digital Audio", "MP3 Streaming", 
            "Digital Movie", "Video Rental", "Music Streaming", "Subscription Box (Digital)", 
            "Digital Membership", "Downloadable Content (DLC)", "App Code", "Digital Ticket", 
            "Virtual Ticket", "E-learning Content", "Digital Magazine", "Online Tutorial", 
            "Webinar", "Downloadable Software", "Digital Game Key", "Virtual Experience", 
            "Digital Book", "Software Subscription", "Online Game Credits", "Cloud-Based Game", 
            "Game Expansion Pack", "Game Mod", "e-Book Subscription", "Digital Comic Book", 
            "Digital Audio Book", "Virtual Product", "Online Course Subscription", 
            "Downloadable Template", "Virtual Item", "Digital Magazine Subscription", 
            "Digital Document", "Digital Recipe", "Software Upgrade", "Digital Art Print", 
            "Cloud Software", "Online Service Subscription", "Digital Video Game", 
            "Subscription Service", "eGift Card", "Downloadable Music", "Online Streaming Service", 
            "Virtual Reality Game", "Downloadable Movie", "Streaming Audio", "Digital File Download", 
            "Digital Audio Streaming", "Digital Subscription Box", "Digital Cookbook", 
            "Digital Learning Material", "Virtual Fitness Class", "Virtual Fitness Program", 
            "Online Game Subscription", "Downloadable Game Content", "Digital Music Subscription", 
            "Digital Art File", "Digital Educational Content", "Virtual Goods for Games", 
            "Digital Activation Code", "Digital Collectible", "Digital Asset", "Content Subscription", 
            "Software Activation Key", "Streaming Media Service", "Content License", 
            "Cloud Gaming Subscription", "Virtual Currency Pack", "Game Item Bundle", 
            "Digital Rights Management (DRM)", "Virtual Item Pack", "Cloud-Based Service Subscription", 
            "Downloadable Virtual Content", "Digital Media File", "App Purchase Code", 
            "Digital Token", "Digital License Key", "Online Access Pass", "Digital Membership Access", 
            "Virtual Currency Exchange", "In-App Subscription", "Web-Based Service Subscription", 
            "Cloud Storage Subscription", "Online Content Pass", "Exclusive Digital Content", 
            "Downloadable Template Package", "App Activation Key", "Virtual Experience Subscription", 
            "Digital Code for Streaming", "Digital Download Link", "Premium Digital Membership", 
            "Digital Licensing Service", "Cloud-Based Media", "Virtual Item Activation", 
            "Game Credit Code", "Virtual Rewards Program", "Game Expansion Download", 
            "Software Patch Download", "Digital Collectible Card", "Exclusive Digital Video Content", 
            "Game Content Code", "Streaming Access Pass", "Digital Asset Transfer", 
            "Interactive Digital Content", "Online Platform Access Code", "Digital-Only Bundle", 
            "Streaming Service Code", "Digital Coupon Code", "Digital Subscription Access Code", 
            "Software Download Link", "Web Access Subscription", "In-App Game Currency", 
            "Virtual Skill Points", "Premium Digital Game Content", "Digital-exclusive Bonus", 
            "Downloadable Game DLC (Downloadable Content)", "Cloud-Based Content Distribution"]
        products = [p for p in products if not any(b in p["Title"] for b in block_list)]
        products.sort(key=lambda x: int(x["Ratings Total"]), reverse=True)
        return products[:10]

    except Exception as e:
        print(f"Amazon search error: {e}")
        flash("Error searching Amazon products", "error")
        return []

# Similar search functions for Walmart, BestBuy, AliExpress
# (Include your existing implementations here)

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        if not query:
            flash("Please enter a search term", "error")
            return redirect(url_for("home"))
        return redirect(url_for("results", query=query))
    return render_template("index.html")

@app.route("/results", methods=["GET", "POST"])
def results():
    query = request.args.get("query", "")
    retailer = request.args.get("retailer", "All")

    # Get products based on retailer
    if retailer == "Amazon":
        products = search_amazon_products(query)
    elif retailer == "Walmart":
        products = search_walmart_products(query)
    elif retailer == "BestBuy":
        products = search_bestbuy_products(query)
    elif retailer == "AliExpress":
        products = search_aliexpress_products(query)
    else:
        products = []
        for func in [search_amazon_products, search_walmart_products, 
                    search_bestbuy_products, search_aliexpress_products]:
            products.extend(func(query))

    # Calculate profit if cost price submitted
    if request.method == "POST" and "cost_price" in request.form:
        try:
            cost_price = float(request.form["cost_price"].replace("$", ""))
            for product in products:
                try:
                    selling_price = float(product["Price"].replace("$", "").replace(",", ""))
                    profit = selling_price - cost_price
                    if profit < 0:
                        product["Profit Margin"] = f"Loss: ${abs(profit):.2f}"
                    else:
                        margin = (profit / selling_price) * 100
                        product["Profit Margin"] = f"{margin:.2f}%"
                except (ValueError, AttributeError):
                    product["Profit Margin"] = "N/A"
        except ValueError:
            flash("Invalid cost price format", "error")

    return render_template("results.html", 
                         products=products, 
                         query=query, 
                         retailer=retailer)

# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        try:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if user and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                session["user_email"] = user["email"]
                session["user_name"] = user["name"] if "name" in user and user["name"] else "User"
                flash("Login successful!", "success")
                return redirect(url_for("profile"))
            
            flash("Invalid email or password", "error")
        except Exception as e:
            print(f"Login error: {e}")
            flash("An error occurred during login", "error")
    
    return render_template("login.html")

@app.route("/login/google")
def google_login():
    if not os.getenv("GOOGLE_CLIENT_ID"):
        flash("Google login is not configured", "error")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_authorize", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
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
            db.execute('INSERT INTO users (email, name) VALUES (?, ?)', 
                      (email, name))
            db.commit()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user.get('name', 'User')
        return redirect(url_for('profile'))
        
    except Exception as e:
        print(f"Google auth error: {str(e)}")
        flash('Google authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))
        
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        name = request.form.get("name", "").strip()
        
        if not all([email, password]):
            flash("Email and password are required", "error")
            return redirect(url_for("register"))
        
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("Email already registered", "error")
            return redirect(url_for("register"))
        
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
                  (email, hashed_password, name))
        db.commit()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("home"))

# --- Profile Routes ---
@app.route("/profile")
@login_required
def profile():
    try:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for("login"))
            
        # Format the created_at date safely
        created_at = user["created_at"] if "created_at" in user else "Unknown"
        if isinstance(created_at, str) and len(created_at) >= 10:
            created_at = created_at[:10]  # Get just the date part
            
        return render_template("profile.html", 
                             user=user,
                             created_at=created_at)
        
    except Exception as e:
        print(f"Profile error: {e}")
        flash("Error loading profile", "error")
        return redirect(url_for("home"))

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    
    if not email:
        flash("Email is required", "error")
        return redirect(url_for("profile"))
    
    db = get_db()
    # Check if email is already taken by another user
    existing = db.execute(
        "SELECT id FROM users WHERE email = ? AND id != ?",
        (email, session["user_id"])
    ).fetchone()
    
    if existing:
        flash("Email already in use by another account", "error")
        return redirect(url_for("profile"))
    
    db.execute(
        "UPDATE users SET name = ?, email = ? WHERE id = ?",
        (name, email, session["user_id"])
    )
    db.commit()
    
    session["user_name"] = name
    session["user_email"] = email
    flash("Profile updated successfully", "success")
    return redirect(url_for("profile"))

# --- Saved Products Routes ---
@app.route("/saved-products")
@login_required
def saved_products():
    db = get_db()
    products = db.execute(
        "SELECT * FROM saved_products WHERE user_id = ? ORDER BY saved_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("saved-products.html", products=products)

@app.route("/save-product", methods=["POST"])
@login_required
def save_product():
    try:
        product_data = {
            "user_id": session["user_id"],
            "product_id": request.form.get("product_id", ""),
            "title": request.form.get("title", ""),
            "price": request.form.get("price", ""),
            "image": request.form.get("image", ""),
            "link": request.form.get("link", ""),
            "retailer": request.form.get("retailer", "Unknown"),
            "description": request.form.get("description", ""),
            "rating": request.form.get("rating", ""),
            "ratings_total": request.form.get("ratings_total", 0)
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
        db.commit()
        return jsonify({"status": "success"})

    except Exception as e:
        print(f"Error saving product: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 500

@app.route("/remove-product/<int:product_id>", methods=["POST"])
@login_required
def remove_product(product_id):
    db = get_db()
    db.execute(
        "DELETE FROM saved_products WHERE id = ? AND user_id = ?",
        (product_id, session["user_id"])
    )
    db.commit()
    flash("Product removed from saved items", "success")
    return redirect(url_for("saved-products"))

# Enhanced Contact Us Route
@app.route("/contact-us", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def contact_us():
    if request.method == "POST":
        try:
            name = clean(request.form.get("name", "").strip())
            email = clean(request.form.get("email", "").strip())
            subject = clean(request.form.get("subject", "").strip())
            message = clean(request.form.get("message", "").strip())
            ip_address = request.remote_addr

            # Validate required fields
            if not all([name, email, message]):
                flash('Name, email and message are required', 'error')
                return redirect(url_for('contact_us'))

            # Save to database
            db = get_db()
            db.execute(
                """INSERT INTO contact_submissions 
                (name, email, subject, message, ip_address)
                VALUES (?, ?, ?, ?, ?)""",
                (name, email, subject, message, ip_address)
            )
            db.commit()

            # Send email notification
            msg = Message(
                subject=f"New Contact Submission: {subject or 'No Subject'}",
                sender=os.getenv("MAIL_USERNAME"),
                recipients=[os.getenv("MAIL_USERNAME")],
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

            flash('Your message has been sent! We\'ll contact you soon.', 'success')
            return redirect(url_for('contact_us'))
            
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            flash('Failed to send message. Please try again later.', 'error')
    
    return render_template('contact-us.html', csrf_token=generate_csrf())

# --- Other Pages ---
@app.route("/about-us")
def about_us():
    return render_template("about-us.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/plan-details")
def plan_details():
    return render_template("plan-details.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
