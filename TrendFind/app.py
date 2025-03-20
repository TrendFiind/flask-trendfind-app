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
        block_list = [
            "Kindle Store", "eBook", "Kindle Edition", "Audible Audiobook", "Streaming Video", 
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
            "Downloadable Game DLC (Downloadable Content)", "Cloud-Based Content Distribution"
        ]

        # Filter out digital products
        products = [product for product in products if not any(blocked in product.get("Title", "") for blocked in block_list)]

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
