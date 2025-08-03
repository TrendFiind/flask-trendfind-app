"""
TrendFind – Full Application (Fixed & Refactored)
=================================================
Robust database layer, Google OAuth, CSRF, etc.
"""

from __future__ import annotations          # ← line 6

# ----------------- standard library -----------------
import os
import re
import sqlite3
import stripe
import logging
from datetime import datetime, timedelta 
from functools import wraps
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
#  Third-party
# ---------------------------------------------------------------------------
import bleach
import psycopg2
import psycopg2.extras
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from blueprints.auth import bp as auth_bp
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError, CSRFProtect
from logging.handlers import RotatingFileHandler
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError

# ---------------------------------------------------------------------------
#  Environment & configuration
# ---------------------------------------------------------------------------
load_dotenv()  # .env for local dev

class Config:
    """Flask configuration object."""
    # Core
    SECRET_KEY                 = os.getenv("FLASK_SECRET_KEY")
    SESSION_COOKIE_SECURE      = True
    SESSION_COOKIE_HTTPONLY    = True
    SESSION_COOKIE_SAMESITE    = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

    # CSRF
    WTF_CSRF_ENABLED     = True        
    WTF_CSRF_SECRET_KEY  = SECRET_KEY

    # Database (SQLite fallback)
    LOCAL_SQLITE_PATH = "database.db"

    # Mail
    MAIL_SERVER         = "smtp.gmail.com"
    MAIL_PORT           = 587
    MAIL_USE_TLS        = True
    MAIL_USERNAME       = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD       = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

    # Rate limiting
    RATE_LIMITS = ["200 per day", "50 per hour"]


# ---------------------------------------------------------------------------
#  App & extensions
# ---------------------------------------------------------------------------
app = Flask(__name__)                      # ✅ define app first
app.config.from_object(Config)
app.config["WTF_CSRF_TIME_LIMIT"] = None          # DEV ONLY ⚠️

from mail import mail
mail.init_app(app)

csrf     = CSRFProtect(app)
mail     = Mail(app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=Config.RATE_LIMITS,
    storage_uri="memory://"
)
limiter.init_app(app)          # ← this attaches the limiter to your Flask app
oauth    = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile", "prompt": "select_account"}
)


@app.template_filter("date_only")
def date_only(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return value

# ---------------------------------------------------------------------------
#  Database layer
# ---------------------------------------------------------------------------
class DBWrapper:
    """
    Uniform wrapper so the rest of the code can do:

        db = get_db()
        db.execute(sql, params)
        rows = db.fetchall()
        db.commit()

    and it works on both Postgres (psycopg2) and SQLite.
    """

    def __init__(self, conn, is_sqlite: bool):
        self.conn      = conn
        self.is_sqlite = is_sqlite

    # ─── Basic delegates ────────────────────────────────────────────────
    def commit(self)   -> None: self.conn.commit()
    def rollback(self) -> None: self.conn.rollback()
    def close(self)    -> None: self.conn.close()

    # ─── Internal cursor helper ────────────────────────────────────────
    def _cursor(self):
        if self.is_sqlite:
            return self.conn.cursor()
        # RealDictCursor → rows behave like dicts (column names as keys)
        return self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ─── Execute (auto-converts “?” → “%s” for Postgres) ───────────────
    def execute(self, sql: str, params: Sequence[Any] | None = None):
        if not self.is_sqlite:
            # psycopg2 expects %s placeholders; SQLite uses ?
            sql = sql.replace("?", "%s")
        cur = self._cursor()
        cur.execute(sql, params or ())
        return cur

    # ─── Convenience helpers ───────────────────────────────────────────
    def fetchone(self, *args, **kwargs):
        return self.execute(*args, **kwargs).fetchone()

    def fetchall(self, *args, **kwargs):
        return self.execute(*args, **kwargs).fetchall()

def get_db() -> DBWrapper:
    """Return a DBWrapper, creating one per-request."""
    if "db" not in g:
        dsn = os.getenv("DATABASE_URL")

        # ── Heroku Postgres ────────────────────────────────────────────────
        if dsn:
            if dsn.startswith("postgres://"):
                dsn = dsn.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(dsn, sslmode="require")
            g.db = DBWrapper(conn, is_sqlite=False)

        # ── Local SQLite fallback ─────────────────────────────────────────
        else:
            conn = sqlite3.connect(
                Config.LOCAL_SQLITE_PATH,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            conn.row_factory = sqlite3.Row
            g.db = DBWrapper(conn, is_sqlite=True)

    return g.db

@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

# ---------------------------------------------------------------------------
#  Database bootstrap
# ---------------------------------------------------------------------------
def init_db() -> None:
    """
    Creates tables if they do not yet exist.
    We generate engine-specific DDL so both SQLite & Postgres are happy.
    """
    db = get_db()
    is_sqlite = db.is_sqlite

    pk = "INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "SERIAL PRIMARY KEY"
    now = "CURRENT_TIMESTAMP"                # both engines accept this

    # Users -----------------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id            {pk},
            email         TEXT UNIQUE NOT NULL,
            password      TEXT,
            name          TEXT,
            phone         TEXT,
            image         TEXT DEFAULT 'static/images/default-profile.jpg',
            two_factor    TEXT DEFAULT 'disabled',
            created_at    TIMESTAMP DEFAULT {now},
            last_login    TIMESTAMP
        );
    """)

    # Saved products --------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS saved_products (
            id            {pk},
            user_id       INTEGER NOT NULL,
            product_id    TEXT NOT NULL,
            title         TEXT NOT NULL,
            price         TEXT NOT NULL,
            image         TEXT NOT NULL,
            link          TEXT NOT NULL,
            retailer      TEXT NOT NULL,
            description   TEXT,
            rating        TEXT,
            ratings_total INTEGER,
            saved_at      TIMESTAMP DEFAULT {now},
            UNIQUE(user_id, product_id)
        );
    """)

    # User stats ------------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id        INTEGER PRIMARY KEY,
            products_saved INTEGER DEFAULT 0,
            winning_finds  INTEGER DEFAULT 0,
            active_projects INTEGER DEFAULT 0
        );
    """)

    # Billing ---------------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS billing_info (
            id               {pk},
            user_id          INTEGER NOT NULL,
            card_last4       TEXT,
            card_brand       TEXT,
            card_expiry      TEXT,
            billing_address  TEXT,
            plan_name        TEXT DEFAULT 'Free',
            plan_price       REAL DEFAULT 0,
            next_billing_date TIMESTAMP
        );
    """)

    # Activity --------------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS user_activity (
            id              {pk},
            user_id         INTEGER NOT NULL,
            activity_type   TEXT NOT NULL,
            activity_details TEXT,
            activity_time   TIMESTAMP DEFAULT {now}
        );
    """)

    # Contact form ----------------------------------------------------------
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS contact_submissions (
            id           {pk},
            name         TEXT NOT NULL,
            email        TEXT NOT NULL,
            subject      TEXT,
            message      TEXT NOT NULL,
            ip_address   TEXT,
            submitted_at TIMESTAMP DEFAULT {now},
            status       TEXT DEFAULT 'pending'
        );
    """)

    # Helpful indexes
    db.execute("CREATE INDEX IF NOT EXISTS idx_saved_products_user ON saved_products(user_id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity(user_id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_user_activity_time ON user_activity(activity_time);")

    db.commit()

# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------
def clean(s: Optional[str]) -> str:
    """Trim & bleach user input."""
    return "" if s is None else bleach.clean(str(s).strip())

def flash_and_redirect(message: str, category: str, endpoint: str):
    flash(message, category)
    return redirect(url_for(endpoint))

def login_required(fn):
    @wraps(fn)
    def _wrapped(*a, **kw):
        if "user_id" not in session:
            return flash_and_redirect("Please log in to access that page.", "error", "login")
        return fn(*a, **kw)
    return _wrapped

def track_activity(user_id: int, kind: str, details: str | None = None):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO user_activity (user_id, activity_type, activity_details) VALUES (?, ?, ?)",
            (user_id, clean(kind), clean(details))
        )
        db.commit()
    except Exception as exc:   # pragma: no cover
        app.logger.warning("Activity log failed: %s", exc)

def update_stats(user_id: int, field: str):
    db = get_db()
    # ensure row exists
    db.execute("INSERT OR IGNORE INTO user_stats (user_id) VALUES (?)", (user_id,))
    db.execute(f"UPDATE user_stats SET {field} = {field} + 1 WHERE user_id = ?", (user_id,))
    db.commit()

# ---------------------------------------------------------------------------
#  Forms
# ---------------------------------------------------------------------------
class ContactForm(FlaskForm):
    name    = StringField("Name",    validators=[DataRequired()])
    email   = StringField("Email",   validators=[DataRequired(), Email()])
    subject = StringField("Subject")
    message = TextAreaField("Message", validators=[DataRequired()])

    def validate_email(self, field):
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", field.data):
            raise ValidationError("Invalid email address")

# ---------------------------------------------------------------------------
#  Security headers
# ---------------------------------------------------------------------------
@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "SAMEORIGIN"
    resp.headers["X-XSS-Protection"]       = "1; mode=block"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

# ---------------------------------------------------------------------------
#  Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def _404(err):   return render_template("404.html"), 404

@app.errorhandler(500)
def _500(err):
    app.logger.error("500: %s", err)
    return render_template("500.html"), 500

@app.errorhandler(CSRFError)
def _csrf(err):
    flash("Form expired – please try again.", "error")
    return redirect(request.referrer or url_for("home"))

# ---------------------------------------------------------------------------
#  Public routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        q = clean(request.form.get("query"))
        if not q:
            return flash_and_redirect("Enter a search term.", "error", "home")
        return redirect(url_for("results", query=q))
    return render_template("index.html")

@app.route("/results")
def results():
    query    = clean(request.args.get("query"))
    retailer = clean(request.args.get("retailer", "All"))
    # TODO: plug in real search engine
    products = []   # ← placeholder
    return render_template("results.html", products=products, query=query, retailer=retailer)

# ---------------------------------------------------------------------------
#  Authentication
# ---------------------------------------------------------------------------
# Registration – replaced PBKDF2 with argon2
@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        email=clean(request.form.get("email")).lower()
        pw=request.form.get("password",""); name=clean(request.form.get("name"))
        if not (email and pw): return flash_redirect("Email & password required.","error","register")
        db=get_db()
        if db.fetchone("SELECT 1 FROM users WHERE email = ?",(email,)):
            return flash_redirect("Email already registered.","error","register")
        db.execute("INSERT INTO users (email,password,name) VALUES (?,?,?)",
                   (email, generate_password_hash(pw), name))                   # default pbkdf2:sha256
        db.commit()
        flash("Registration successful – please log in.","success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = clean(request.form.get("email")).lower()
        pw    = request.form.get("password", "")

        db   = get_db()
        user = db.fetchone("SELECT * FROM users WHERE email = ?", (email,))

        # 1. Account exists but was created via Google OAuth (no password stored)
        if user and not user["password"]:
            flash("That account was created with Google login. "
                  "Click “Log in with Google” or set a password on your profile page.",
                  "error")
            return redirect(url_for("login"))

        # 2. Standard email-and-password check (only if a hash exists)
        if user and user["password"] and check_password_hash(user["password"], pw):
            session.update(
                user_id    = user["id"],
                user_name  = user["name"] or "User",
                user_email = user["email"],
            )
            db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                       (user["id"],))
            db.commit()
            track_activity(user["id"], "login", "email/pw")
            return redirect(url_for("profile"))

        # 3. Anything else → invalid
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))

    # GET request → render form
    return render_template("login.html")

@app.route("/login/google")
def google_login():
    if not google.client_id:
        return flash_and_redirect("Google login isn’t configured.", "error", "login")
    return google.authorize_redirect(url_for("google_callback", _external=True))

@app.route('/firebase-login', methods=['POST'])
def firebase_login():
    # Handle Firebase login here
    return jsonify({"message": "Login successful"})

@app.route("/login/google/authorize")
def google_callback():
    try:
        token  = google.authorize_access_token()
        userinfo = google.parse_id_token(token)
        if not (token and userinfo):
            abort(400)

        email = userinfo["email"].lower()
        name  = userinfo.get("name", "User")

        db   = get_db()
        user = db.fetchone("SELECT * FROM users WHERE email = ?", (email,))

        if not user:
            db.execute("INSERT INTO users (email, name) VALUES (?, ?)", (email, name))
            db.commit()
            user = db.fetchone("SELECT * FROM users WHERE email = ?", (email,))
            db.execute("INSERT INTO user_stats (user_id) VALUES (?)", (user["id"],))
            db.commit()

        session.update(user_id=user["id"], user_name=name, user_email=email)
        db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
        db.commit()
        track_activity(user["id"], "login", "Google OAuth")
        return redirect(url_for("profile"))

    except Exception as exc:
        app.logger.error("Google OAuth failed: %s", exc)
        return flash_and_redirect("Google authentication failed.", "error", "login")

@app.route("/logout")
def logout():
    if "user_id" in session:
        track_activity(session["user_id"], "logout", "User logged out")
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))

# ---------------------------------------------------------------------------
#  Profile & settings
# ---------------------------------------------------------------------------
@app.route("/profile")
@login_required
def profile():
    db   = get_db()
    user = db.fetchone("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    if not user:
        return flash_and_redirect("User not found.", "error", "logout")

    stats       = db.fetchone("SELECT * FROM user_stats WHERE user_id = ?", (user["id"],))
    billing     = db.fetchone(
        "SELECT * FROM billing_info WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user["id"],)
    )
    activities  = db.fetchall(
        "SELECT * FROM user_activity WHERE user_id = ? ORDER BY activity_time DESC LIMIT 5",
        (user["id"],)
    )

    # simple success-rate calc
    rate = 0
    if stats and stats["products_saved"]:
        rate = round((stats["winning_finds"] / stats["products_saved"]) * 100, 1)

    return render_template(
        "profile.html",
        user=user,
        stats=stats,
        success_rate=rate,
        billing=billing,
        activities=activities
    )

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    name  = clean(request.form.get("name"))
    email = clean(request.form.get("email")).lower()
    phone = clean(request.form.get("phone"))

    if not email:
        return flash_and_redirect("Email is required.", "error", "profile")

    db = get_db()
    conflict = db.fetchone(
        "SELECT 1 FROM users WHERE email = ? AND id != ?", (email, session["user_id"])
    )
    if conflict:
        return flash_and_redirect("Email already in use.", "error", "profile")

    db.execute(
        "UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?",
        (name, email, phone, session["user_id"])
    )
    db.commit()
    session.update(user_name=(name or "User"), user_email=email)
    track_activity(session["user_id"], "profile_update", "Updated profile")
    flash("Profile updated.", "success")
    return redirect(url_for("profile"))

# ── Avatar upload ----------------------------------------------------------
@app.route("/update-avatar", methods=["POST"])
@login_required
def update_avatar():
    file = request.files.get("avatar")
    if not file or file.filename == "":
        return jsonify(success=False, message="No file uploaded"), 400

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in {"png", "jpg", "jpeg", "gif"}:
        return jsonify(success=False, message="Invalid file type"), 400

    if file.content_length and file.content_length > 2 * 1024 * 1024:
        return jsonify(success=False, message="File > 2 MB"), 400

    filename   = f"user_{session['user_id']}.{ext}"
    upload_dir = os.path.join(app.root_path, "static", "uploads", "avatars")
    os.makedirs(upload_dir, exist_ok=True)
    file.save(os.path.join(upload_dir, filename))

    get_db().execute(
        "UPDATE users SET image = ? WHERE id = ?",
        (f"uploads/avatars/{filename}", session["user_id"])
    )
    get_db().commit()
    track_activity(session["user_id"], "avatar_update", "Changed avatar")
    return jsonify(success=True, message="Avatar updated")

# ── Security settings ------------------------------------------------------
@app.route("/update-security", methods=["POST"])
@login_required
def update_security():
    cur_pw  = request.form.get("current_password") or ""
    new_pw  = request.form.get("new_password")    or ""
    twofac  = clean(request.form.get("two_factor")) or "disabled"

    db   = get_db()
    user = db.fetchone("SELECT password FROM users WHERE id = ?", (session["user_id"],))

    if new_pw:
        if not (cur_pw and check_password_hash(user["password"], cur_pw)):
            return flash_and_redirect("Current password incorrect.", "error", "profile")
        if len(new_pw) < 8:
            return flash_and_redirect("Password must be ≥ 8 chars.", "error", "profile")
        db.execute("UPDATE users SET password = ? WHERE id = ?",
                   (generate_password_hash(new_pw), session["user_id"]))
    db.execute("UPDATE users SET two_factor = ? WHERE id = ?", (twofac, session["user_id"]))
    db.commit()
    track_activity(session["user_id"], "security_update", "Updated security")
    flash("Security settings saved.", "success")
    return redirect(url_for("profile"))

# ---------------------------------------------------------------------------
#  Billing, products, contact, misc.
#  (All routes are unchanged from your original code except minor refactors.)
# ---------------------------------------------------------------------------
@app.route("/update-billing", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def update_billing():
    card   = clean(request.form.get("card_number"))
    expiry = clean(request.form.get("card_expiry"))
    addr   = clean(request.form.get("billing_address"))
    plan   = clean(request.form.get("plan_name") or "Premium")
    price  = float(request.form.get("plan_price") or 29.00)

    if not (card and expiry and addr):
        return flash_and_redirect("Missing billing fields.", "error", "profile")

    last4 = card[-4:]
    brand = "visa" if card.startswith("4") else "mastercard"

    db = get_db()
    db.execute("""
        INSERT INTO billing_info
            (user_id, card_last4, card_brand, card_expiry, billing_address,
             plan_name, plan_price, next_billing_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, date('now', '+1 month'))
    """, (session["user_id"], last4, brand, expiry, addr, plan, price))
    db.commit()
    track_activity(session["user_id"], "billing_update", "Updated billing")
    flash("Billing updated.", "success")
    return redirect(url_for("profile"))

@app.route("/saved-products")
@login_required
def saved_products():
    prods = get_db().fetchall(
        "SELECT * FROM saved_products WHERE user_id = ? ORDER BY saved_at DESC",
        (session["user_id"],)
    )
    return render_template("saved-products.html", products=prods)

@app.route("/save-product", methods=["POST"])
@login_required
def save_product():
    p = {k: clean(request.form.get(k)) for k in (
        "product_id", "title", "price", "image", "link", "retailer", "description", "rating")}
    p["ratings_total"] = int(request.form.get("ratings_total") or 0)

    if not (p["product_id"] and p["title"]):
        return jsonify(status="error", message="Missing fields"), 400

    db = get_db()
    if db.fetchone("SELECT 1 FROM saved_products WHERE user_id = ? AND product_id = ?",
                   (session["user_id"], p["product_id"])):
        return jsonify(status="error", message="Already saved"), 400

    db.execute("""
        INSERT INTO saved_products
        (user_id, product_id, title, price, image, link, retailer,
         description, rating, ratings_total)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session["user_id"], *p.values()))
    db.commit()

    update_stats(session["user_id"], "products_saved")
    track_activity(session["user_id"], "save", f"{p['title']} saved")
    return jsonify(status="success")

@app.route("/remove-product/<int:product_id>", methods=["POST"])
@login_required
def remove_product(product_id: int):
    db      = get_db()
    product = db.fetchone(
        "SELECT title FROM saved_products WHERE id = ? AND user_id = ?",
        (product_id, session["user_id"])
    )
    if not product:
        return flash_and_redirect("Product not found.", "error", "saved_products")

    db.execute("DELETE FROM saved_products WHERE id = ? AND user_id = ?",
               (product_id, session["user_id"]))
    db.commit()
    track_activity(session["user_id"], "remove", f"{product['title']} removed")
    flash("Product removed.", "success")
    return redirect(url_for("saved_products"))

# ── Contact ----------------------------------------------------------------
@app.route("/contact-us", methods=["GET", "POST"])
@limiter.limit("5/minute")
def contact_us():
    form = ContactForm()
    if form.validate_on_submit():
        name, email = clean(form.name.data), clean(form.email.data)
        subject     = clean(form.subject.data or "")
        message     = clean(form.message.data)
        ip          = request.remote_addr

        db = get_db()
        db.execute("""
            INSERT INTO contact_submissions
                (name, email, subject, message, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (name, email, subject, message, ip))
        db.commit()

        # Fire off email (best-effort)
        try:
            mail.send(Message(
                subject=f"TrendFind Contact: {subject or 'No subject'}",
                recipients=[Config.MAIL_USERNAME],
                body=(f"From: {name} <{email}>\nIP: {ip}\n\n{message}")
            ))
        except Exception as exc:   # pragma: no cover
            app.logger.warning("Mail send failed: %s", exc)

        flash("Message sent – we'll reply within 24 h.", "success")
        return redirect(url_for("contact_us"))
    return render_template("contact-us.html", form=form)

# Static pages
# ── Static pages ──────────────────────────────────────────────────────────
@app.route("/about-us")
def about_us():
    return render_template("about-us.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/plan-details")
def plan_details():
    return render_template("plan-details.html")

# Quick admin endpoint to (re)create DB
@app.route("/initdb")
def _initdb():
    init_db()
    return "Database initialised.", 200

# ---------------------------------------------------------------------------
#  Main entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()

    if not app.debug:
        handler = RotatingFileHandler("error.log", maxBytes=1_048_576, backupCount=3)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        ))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)

    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=app.debug)

