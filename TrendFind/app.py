import os
import asyncio
import aiohttp
import asyncpg
from datetime import datetime
import logging
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, g
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email
from flask_limiter.util import get_remote_address
from datetime import timedelta
import sqlite3
import bleach
from bleach import clean

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# ==================== FORM CLASSES ====================
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject')
    message = TextAreaField('Message', validators=[DataRequired()])

# ==================== SECURITY CONFIGURATIONS ====================
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

# ==================== SOLANA TRADING BOT CONFIG ====================
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
JUPITER_API_URL = "https://price.jup.ag/v4/price"
RAYDIUM_API_URL = "https://api.raydium.io/v2/main/price"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SolanaBot")

class SolanaBot:
    def __init__(self):
        self.client = None
        self.session = None
        self.token_cache = {}
        self.active_tokens = []
        self.last_updated = None
        self.pg_pool = None
        
    async def initialize(self):
        """Initialize connections"""
        self.client = AsyncClient(SOLANA_RPC_URL)
        self.session = aiohttp.ClientSession()
        
        # Initialize PostgreSQL connection pool
        self.pg_pool = await asyncpg.create_pool(
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            host=os.getenv("DB_HOST")
        )
        
    async def close(self):
        """Clean up connections"""
        if self.client:
            await self.client.close()
        if self.session:
            await self.session.close()
        if self.pg_pool:
            await self.pg_pool.close()
            
    async def discover_active_tokens(self):
        """Discover active memecoins using Jupiter API"""
        try:
            params = {
                "ids": "all",
                "vsToken": "So11111111111111111111111111111111111111112"  # SOL
            }
            
            async with self.session.get(JUPITER_API_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    tokens = data.get('data', [])
                    
                    # Filter for memecoins (simple heuristic - low price and high volume)
                    memecoins = [
                        t for t in tokens 
                        if float(t['price']) < 0.1 and float(t['volume24h']) > 1000
                    ]
                    
                    self.active_tokens = memecoins[:50]  # Limit to top 50
                    self.last_updated = datetime.now().isoformat()
                    
                    # Store in database
                    await self.store_tokens_in_db(memecoins[:50])
                    
                    return memecoins[:50]
                
        except Exception as e:
            logger.error(f"Error discovering tokens: {str(e)}")
            return []
            
    async def store_tokens_in_db(self, tokens):
        """Store discovered tokens in PostgreSQL database"""
        if not self.pg_pool:
            return
            
        try:
            async with self.pg_pool.acquire() as conn:
                # Create tables if they don't exist
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS tokens (
                        id SERIAL PRIMARY KEY,
                        token_address VARCHAR(56) NOT NULL UNIQUE,
                        token_name VARCHAR(100),
                        symbol VARCHAR(10),
                        price NUMERIC(32, 9),
                        volume_24h NUMERIC(32, 2),
                        price_change_24h NUMERIC(10, 2),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_updated TIMESTAMP
                    )
                ''')
                
                # Insert or update tokens
                for token in tokens:
                    await conn.execute('''
                        INSERT INTO tokens (token_address, token_name, symbol, price, volume_24h, price_change_24h, last_updated)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (token_address) 
                        DO UPDATE SET
                            price = EXCLUDED.price,
                            volume_24h = EXCLUDED.volume_24h,
                            price_change_24h = EXCLUDED.price_change_24h,
                            last_updated = EXCLUDED.last_updated
                    ''', 
                    token['id'],
                    token.get('name'),
                    token.get('symbol'),
                    token.get('price'),
                    token.get('volume24h'),
                    token.get('price_change_24h'),
                    datetime.now()
                    )
                    
        except Exception as e:
            logger.error(f"Error storing tokens in DB: {str(e)}")
            
    async def get_token_metadata(self, mint_address):
        """Get token metadata from Solana chain"""
        try:
            if mint_address in self.token_cache:
                return self.token_cache[mint_address]
                
            # Get token info
            pubkey = Pubkey.from_string(mint_address)
            account_info = await self.client.get_account_info(pubkey)
            
            if account_info.value:
                # Basic metadata extraction
                metadata = {
                    'mint': mint_address,
                    'decimals': 9,  # Default, would need proper parsing
                    'supply': None,
                    'owner': str(account_info.value.owner)
                }
                
                self.token_cache[mint_address] = metadata
                return metadata
                
        except Exception as e:
            logger.error(f"Error getting metadata for {mint_address}: {str(e)}")
            return None
            
    async def get_liquidity_data(self, mint_address):
        """Get liquidity data from Raydium API"""
        try:
            async with self.session.get(f"{RAYDIUM_API_URL}?ids={mint_address}") as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get(mint_address, {})
        except Exception as e:
            logger.error(f"Error getting liquidity for {mint_address}: {str(e)}")
            return {}
            
    async def get_token_price(self, mint_address):
        """Get token price from Jupiter API"""
        try:
            params = {
                "ids": mint_address,
                "vsToken": "So11111111111111111111111111111111111111112"  # SOL
            }
            
            async with self.session.get(JUPITER_API_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get(mint_address, {})
        except Exception as e:
            logger.error(f"Error getting price for {mint_address}: {str(e)}")
            return {}

# Global bot instance
bot = SolanaBot()

# ==================== DATABASE SETUP ====================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('database.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
async def shutdown(exception=None):
    # Close SQLite connection
    db = g.pop('db', None)
    if db is not None:
        db.close()
    
    # Close Solana bot connections
    await bot.close()

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

# ==================== EMAIL CONFIGURATION ====================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_TIMEOUT'] = 10
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# ==================== OAUTH CONFIGURATION ====================
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

# ==================== LOGGING CONFIGURATION ====================
if not app.debug:
    file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

# ==================== SECURITY MIDDLEWARE ====================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==================== ERROR HANDLERS ====================
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

# ==================== AUTHENTICATION DECORATOR ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ==================== PRODUCT SEARCH FUNCTIONS ====================
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
        block_list = ["Kindle Store", "eBook", "Kindle Edition", "Audible Audiobook", 
                    "Cloud-Based Content Distribution"]
        products = [p for p in products if not any(b in p["Title"] for b in block_list)]
        products.sort(key=lambda x: int(x["Ratings Total"]), reverse=True)
        return products[:10]

    except Exception as e:
        app.logger.error(f"Amazon search error: {e}")
        flash("Error searching Amazon products", "error")
        return []

# ==================== ROUTES ====================
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        query = clean(request.form.get("query", "").strip())
        if not query:
            flash("Please enter a search term", "error")
            return redirect(url_for("home"))
        return redirect(url_for("results", query=query))
    return render_template("index.html")

@app.route("/results", methods=["GET", "POST"])
def results():
    query = clean(request.args.get("query", ""))
    retailer = clean(request.args.get("retailer", "All"))

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
            cost_price = float(clean(request.form["cost_price"].replace("$", "")))
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

# ==================== TRADING BOT ROUTES ====================
@app.route("/tbot")
async def tbot():
    """Main trading bot page"""
    if not bot.client:
        await bot.initialize()
        
    # Get initial data
    tokens = await bot.discover_active_tokens()
    
    # Get detailed data for first 5 tokens (for performance)
    detailed_tokens = []
    for token in tokens[:5]:
        mint_address = token['id']
        metadata = await bot.get_token_metadata(mint_address)
        liquidity = await bot.get_liquidity_data(mint_address)
        price_data = await bot.get_token_price(mint_address)
        
        detailed_tokens.append({
            **token,
            'metadata': metadata,
            'liquidity': liquidity,
            'price_data': price_data,
            'last_updated': datetime.now().isoformat()
        })
    
    return render_template("tbot.html", 
                         tokens=detailed_tokens,
                         last_updated=bot.last_updated)

@app.route("/tbot/update")
async def update_data():
    """Endpoint for live updates"""
    try:
        tokens = await bot.discover_active_tokens()
        
        updated_tokens = []
        for token in tokens[:5]:  # Limit to 5 for performance
            mint_address = token['id']
            liquidity = await bot.get_liquidity_data(mint_address)
            price_data = await bot.get_token_price(mint_address)
            
            updated_tokens.append({
                **token,
                'liquidity': liquidity,
                'price_data': price_data,
                'last_updated': datetime.now().isoformat()
            })
            
        return jsonify({
            'success': True,
            'tokens': updated_tokens,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Update error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# ==================== AUTHENTICATION ROUTES ====================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = clean(request.form.get("email", "").strip())
        password = request.form.get("password", "").strip()
        
        try:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if user and user["password"] and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                session["user_email"] = user["email"]
                session["user_name"] = user["name"] if "name" in user and user["name"] else "User"
                flash("Login successful!", "success")
                return redirect(url_for("profile"))
            
            flash("Invalid email or password", "error")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
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
        session['user_name'] = user['name'] if 'name' in user.keys() and user['name'] else 'User'
        return redirect(url_for('profile'))
        
    except Exception as e:
        app.logger.error(f"Google auth error: {str(e)}")
        flash('Google authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))
        
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = clean(request.form.get("email", "").strip())
        password = request.form.get("password", "").strip()
        name = clean(request.form.get("name", "").strip())
        
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

# ==================== PROFILE ROUTES ====================
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
        app.logger.error(f"Profile error: {e}")
        flash("Error loading profile", "error")
        return redirect(url_for("home"))

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    name = clean(request.form.get("name", "").strip())
    email = clean(request.form.get("email", "").strip().lower())
    
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

@app.route("/update-avatar", methods=["POST"])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"}), 400
    
    file = request.files['avatar']
    
    # Validate file
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
    
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({"success": False, "message": "Invalid file type"}), 400
    
    # Check file size (max 2MB)
    if file.content_length > 2 * 1024 * 1024:
        return jsonify({"success": False, "message": "File too large (max 2MB)"}), 400
    
    try:
        # Save the file
        filename = f"user_{session['user_id']}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(app.root_path, 'static', 'uploads', 'avatars', filename)
        file.save(filepath)
        
        # Update database
        db = get_db()
        db.execute("UPDATE users SET image = ? WHERE id = ?", 
                  (f"uploads/avatars/{filename}", session['user_id']))
        db.commit()
        
        return jsonify({"success": True, "message": "Avatar updated successfully"})
    
    except Exception as e:
        app.logger.error(f"Error updating avatar: {e}")
        return jsonify({"success": False, "message": "Error updating avatar"}), 500

# ==================== SAVED PRODUCTS ROUTES ====================
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
            "product_id": clean(request.form.get("product_id", "")),
            "title": clean(request.form.get("title", "")),
            "price": clean(request.form.get("price", "")),
            "image": clean(request.form.get("image", "")),
            "link": clean(request.form.get("link", "")),
            "retailer": clean(request.form.get("retailer", "Unknown")),
            "description": clean(request.form.get("description", "")),
            "rating": clean(request.form.get("rating", "")),
            "ratings_total": int(clean(request.form.get("ratings_total", 0)))
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
        app.logger.error(f"Error saving product: {e}")
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

# ==================== CONTACT FORM ====================
@app.route("/contact-us", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def contact_us():
    form = ContactForm()
    
    if form.validate_on_submit():
        try:
            # Sanitize inputs using bleach
            name = clean(form.name.data.strip())
            email = clean(form.email.data.strip())
            subject = clean(form.subject.data.strip()) if form.subject.data else None
            message = clean(form.message.data.strip())
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
                app.logger.info("Email sent successfully")
                flash('Your message has been sent successfully!', 'success')
            except Exception as e:
                app.logger.error(f"Email sending failed: {str(e)}")
                flash('Your message was received but we couldn\'t send a confirmation email.', 'warning')

            return redirect(url_for('contact_us'))
            
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            flash('Failed to process your message. Please try again later.', 'error')
    
    return render_template('contact-us.html', form=form)

# ==================== OTHER PAGES ====================
@app.route("/about-us")
def about_us():
    return render_template("about-us.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/plan-details")
def plan_details():
    return render_template("plan-details.html")

@app.before_first_request
async def startup():
    # Initialize the Solana bot
    await bot.initialize()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
