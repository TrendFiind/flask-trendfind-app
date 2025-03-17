from flask import Flask, render_template, request, flash
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check if required environment variables are set
if not os.getenv("SERPAPI_KEY"):
    raise ValueError("SERPAPI_KEY is not set in the environment variables.")
if not os.getenv("FLASK_SECRET_KEY"):
    raise ValueError("FLASK_SECRET_KEY is not set in the environment variables.")

# SerpAPI configuration
SERPAPI_KEY = os.getenv("SERPAPI_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Required for flash messages

def search_google_products(query):
    params = {
        "api_key": SERPAPI_KEY,
        "engine": "google",
        "q": query + " buy",
        "tbm": "shop"
    }

    try:
        # Make the HTTP GET request to SerpAPI
        response = requests.get("https://serpapi.com/search", params=params)
        response.raise_for_status()
        data = response.json()
        print("API Response:", data)  # Debug print

        # Check if shopping_results exists in the response
        if "shopping_results" not in data:
            print("No shopping results found in the API response.")
            flash("No products found. Please try a different search term.", "error")
            return []

        # Extract product details
        products = []
        for item in data.get("shopping_results", []):
            title = item.get("title", "N/A").lower()
            price = item.get("price", "N/A")
            rating = item.get("rating", "N/A")
            ratings_total = item.get("reviews", 0)
            link = item.get("link", "N/A")

            # Skip products with N/A in critical fields
            if "N/A" not in [title, price, link]:
                products.append({
                    "Title": item.get("title", "N/A"),
                    "Price": price,
                    "Rating": rating,
                    "Ratings Total": ratings_total,
                    "Link": link,
                })

        # Sort products by number of ratings
        products.sort(key=lambda x: int(x["Ratings Total"]), reverse=True)

        # Limit to 10 products
        products = products[:10]

        if not products:
            flash(f"Error: No products found for '{query}'. Please refine your search.", "error")
            return []

        return products

    except requests.exceptions.RequestException as e:
        print(f"Error making API request: {e}")
        flash("Error: Unable to fetch products. Please check your internet connection or try again later.", "error")
        return []
    except KeyError as e:
        print(f"Error parsing API response: {e}")
        flash("Error: The API response format is unexpected. Please try again.", "error")
        return []

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        query = request.form.get("query")
        print("Search Query:", query)  # Debug print
        if not query or query.strip() == "":
            flash("Error: Please enter a search term.", "error")
            return render_template("index.html")
        
        products = search_google_products(query)
        if products:
            print("Products to be displayed:", products)  # Debug print
            return render_template("results.html", products=products)
        else:
            flash("No products found. Please try a different search term.", "error")
            return render_template("index.html")
    
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Heroku's PORT or default to 5000
    app.run(host="0.0.0.0", port=port)  # Run on all available IPs
