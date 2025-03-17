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

            # Filter out non-physical products (e.g., subscriptions, apps)
            if (
                "N/A" not in [title, price, link]
                and "subscription" not in title.lower()
                and "app" not in title.lower()
                and "software" not in title.lower()
                and "digital" not in title.lower()
            ):
                products.append({
                    "Title": title,
                    "Price": price,
                    "Rating": rating,
                    "Ratings Total": ratings_total,
                    "Link": link,
                    "Image": image
                })

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

@app.route("/results")
def results():
    query = request.args.get("query")
    products = search_amazon_products(query)  # Use the new function
    return render_template("results.html", products=products, query=query)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Heroku's PORT or default to 5000
    app.run(host="0.0.0.0", port=port)
