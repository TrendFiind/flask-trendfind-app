import requests
import os
from flask import Flask, render_template, request, flash, redirect, url_for
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check if required environment variables are set
if not os.getenv("RAPIDAPI_KEY"):
    raise ValueError("RAPIDAPI_KEY is not set in the environment variables.")
if not os.getenv("FLASK_SECRET_KEY"):
    raise ValueError("FLASK_SECRET_KEY is not set in the environment variables.")

# RapidAPI configuration
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Required for flash messages

def search_amazon_products(query):
    url = "https://real-time-amazon-data.p.rapidapi.com/search"
    querystring = {"query": query, "page": "1", "country": "US"}
    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": "real-time-amazon-data.p.rapidapi.com"
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()  # Raise an error for bad responses
        results = response.json()
        print("API Response:", results)  # Debug print

        # Extract product details
        products = []
        for item in results.get("data", {}).get("products", []):
            title = item.get("product_title", "N/A")
            price = item.get("product_price", "N/A")
            rating = item.get("product_star_rating", "N/A")
            ratings_total = item.get("product_num_ratings", 0)
            link = item.get("product_url", "N/A")
            image = item.get("product_photo", "N/A")

            # Skip products with no price or invalid price
            if price == "N/A" or price is None or not price.replace("$", "").replace(".", "").isdigit():
                continue

            # Simulate a description (since the API doesn't provide one)
            description = f"{title} is a high-quality product with excellent features and specifications. It is highly rated by customers and offers great value for money."

            # Add the product to the list
            products.append({
                "Title": title,
                "Price": price,
                "Rating": rating,
                "Ratings Total": ratings_total,
                "Link": link,
                "Image": image,
                "Description": description
            })

        # Block list for digital products
        BLOCKED_CATEGORIES = [
    "Apps & Games",
    "Audible Books & Originals",
    "Digital Educational Resources",
    "Digital Music",
    "Digital Software & Video Games",
    "Gift Cards",
    "Kindle Store",
    "Movies & TV",
    "Prime Video",
    "Software",
    "Subscription Boxes",
    "Alexa Skills",
    "Cloud Storage",
    "Online Courses",
    "eTextbooks",
    "Game Codes",
    "Streaming Services",
    "Virtual Currency",
    "Audiobooks",
    "MP3 Downloads",
    "eBooks",
    "Digital Codes",
    "Online Games",
    "Digital Subscriptions",
    "Downloadable Content",
    "Cloud Services",
    "Web Hosting Services",
    "SaaS (Software as a Service)",
    "Virtual Items",
    "Game Expansion Packs",
    "Music Streaming Subscriptions",
    "Video Streaming Subscriptions",
    "Online Magazine Subscriptions",
    "Digital Art",
    "NFTs (Non-Fungible Tokens)",
    "Digital Design Templates",
    "Stock Photos",
    "Stock Videos",
    "Stock Audio",
    "Website Themes",
    "Online Tools & Utilities",
    "Online Storage Plans",
    "VPN Subscriptions",
    "Coding Courses",
    "eLearning Platforms",
    "Cloud Gaming Services",
    "Digital Maps & Navigation",
    "Stock Market Trading Software",
    "Cryptocurrency Software",
    "Automated Trading Bots",
    "AI & Machine Learning Models",
    "License Keys",
    "Mobile Game Purchases",
    "Digital Wallpapers",
    "Virtual Assistants & AI Services",
    "Online Fitness Classes",
    "Virtual Coaching Sessions",
    "Consulting Services",
    "Legal Document Templates",
    "AI Art Generators",
    "Website Builder Subscriptions",
    "Cloud-Based Software",
    "Digital Gift Cards",
    "eGift Cards",
    "Online Music Lessons",
    "Virtual Events & Tickets",
    "AI-Generated Content",
    "Augmented Reality Apps",
    "VR Experiences",
    "Blockchain Services",
    "Cryptocurrency Courses",
    "Forex Trading Bots",
    "Automated Investment Tools",
    "Virtual Goods & Skins",
    "In-Game Purchases",
    "Metaverse Land & Property",
    "Online Business Tools",
    "Web Development Services",
    "Freelance Services",
    "Remote Work Solutions",
    "AI Chatbot Subscriptions",
    "Custom AI Model Training",
    "Cloud-Based AI APIs",
    "Digital Tarot Readings",
    "Horoscope & Astrology Reports",
    "Online Therapy Services",
    "Virtual Medical Consultations",
    "Online Legal Advice",
    "Custom Digital Logos",
    "Stock Trading Signals",
    "Automated Betting Systems",
    "Dropshipping Course Access",
    "SEO & Marketing Tools",
    "Ecommerce Optimization Services",
    "Social Media Automation Tools",
    "Online Store Subscriptions",
    "Business Plan Templates",
    "3D Printing Blueprints",
    "CNC Machine Files",
    "Custom Fonts & Typography",
    "Exclusive Digital Memberships",
    "Professional Resume Templates",
    "Virtual Team-Building Activities",
    "Digital Coaching Sessions",
    "Custom AI Profile Pictures",
    "Deepfake Services",
    "AI Voice Cloning",
    "Online Stock Analysis Tools"
]
   
    return [
        product for product in products
        if product.get("Title") and not any(blocked.lower() in product["Title"].lower() for blocked in BLOCKED_CATEGORIES)
    ]

        # Sort products by number of ratings
        products.sort(key=lambda x: int(x["Ratings Total"]), reverse=True)

        # Limit to 10 products
        products = products[:10]

        if not products:
            flash(f"No physical products found for '{query}'. Please refine your search.", "error")
            return []

        return products

    except Exception as e:
        print(f"Error making API request: {e}")
        flash("Error: Unable to fetch products. Please check your internet connection or try again later.", "error")
        return []

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        query = request.form.get("query")
        if not query or query.strip() == "":
            flash("Please enter a search term.", "error")
            return redirect(url_for("home"))
        
        return redirect(url_for("results", query=query))
    
    return render_template("index.html")

@app.route("/results", methods=["GET", "POST"])
def results():
    query = request.args.get("query")
    products = search_amazon_products(query)  # Fetch products

    if request.method == "POST":
        cost_price = request.form.get("cost_price")
        if not cost_price or not cost_price.replace("$", "").replace(".", "").isdigit():
            flash("Please enter a valid cost price.", "error")
            return redirect(url_for("results", query=query))

        cost_price = float(cost_price.replace("$", ""))

        # Calculate profit margin for each product
        for product in products:
            selling_price = float(product["Price"].replace("$", ""))
            if selling_price <= 0:
                product["Profit Margin"] = "N/A"
                continue

            profit = selling_price - cost_price
            if profit < 0:
                product["Profit Margin"] = f"Loss: {abs(profit):.2f}"
            else:
                profit_margin = (profit / selling_price) * 100
                product["Profit Margin"] = f"{profit_margin:.2f}%"

    return render_template("results.html", products=products, query=query)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Heroku's PORT or default to 5000
    app.run(host="0.0.0.0", port=port)
