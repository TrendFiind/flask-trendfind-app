import requests
import os
from flask import Flask, render_template, request, flash, redirect, url_for
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check if required environment variables are set
if not os.getenv("EBAY_APP_ID"):
    raise ValueError("EBAY_APP_ID is not set in the environment variables.")
if not os.getenv("FLASK_SECRET_KEY"):
    raise ValueError("FLASK_SECRET_KEY is not set in the environment variables.")

# eBay API configuration
EBAY_APP_ID = os.getenv("EBAY_APP_ID")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Required for flash messages

def search_ebay_products(query):
    url = "https://svcs.sandbox.ebay.com/services/search/FindingService/v1"
    params = {
        "OPERATION-NAME": "findItemsByKeywords",
        "SERVICE-VERSION": "1.0.0",
        "SECURITY-APPNAME": EBAY_APP_ID,
        "RESPONSE-DATA-FORMAT": "JSON",
        "keywords": query,
        "paginationInput.entriesPerPage": 10  # Limit to 10 results
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an error for bad responses
        results = response.json()
        print("eBay API Response:", results)  # Debug print

        # Extract product details
        products = []
        for item in results.get("findItemsByKeywordsResponse", [{}])[0].get("searchResult", [{}])[0].get("item", []):
            title = item.get("title", ["N/A"])[0]
            price = item.get("sellingStatus", [{}])[0].get("currentPrice", [{}])[0].get("__value__", "N/A")
            link = item.get("viewItemURL", ["N/A"])[0]
            image = item.get("galleryURL", ["N/A"])[0]
            condition = item.get("condition", [{}])[0].get("conditionDisplayName", ["N/A"])[0]
            shipping_cost = item.get("shippingInfo", [{}])[0].get("shippingServiceCost", [{}])[0].get("__value__", "N/A")

            # Simulate a description (eBay API does not provide descriptions in the search results)
            description = f"{title} is a high-quality product with excellent features and specifications. It is in {condition} condition and ships for ${shipping_cost}."

            # Add the product to the list
            products.append({
                "Title": title,
                "Price": f"${price}",
                "Link": link,
                "Image": image,
                "Description": description,
                "Condition": condition,
                "Shipping Cost": f"${shipping_cost}"
            })

        if not products:
            flash(f"No products found for '{query}'. Please refine your search.", "error")
            return []

        return products

    except Exception as e:
        print(f"Error making eBay API request: {e}")
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
    products = search_ebay_products(query)  # Fetch products from eBay

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
                product["Profit Margin"] = f"Loss: ${abs(profit):.2f}"
            else:
                profit_margin = (profit / selling_price) * 100
                product["Profit Margin"] = f"{profit_margin:.2f}%"

    return render_template("results.html", products=products, query=query)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Heroku's PORT or default to 5000
    app.run(host="0.0.0.0", port=port)
