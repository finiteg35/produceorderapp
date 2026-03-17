"""
web_app.py – Flask web interface for the Produce Order App.

Provides a browser-based store login and ordering dashboard that integrates
with the existing FastAPI backend at https://produce-backend.onrender.com.

Run locally:
    python web_app.py

Or with Gunicorn:
    gunicorn web_app:app
"""

import os
import logging
from datetime import datetime
from functools import wraps

import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_URL = os.environ.get("API_URL", "https://produce-backend.onrender.com")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_required(f):
    """Decorator: redirect to login page if the user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "store_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def _api(method: str, path: str, **kwargs):
    """Make an HTTP request to the FastAPI backend and return the response."""
    url = f"{API_URL}{path}"
    try:
        resp = requests.request(method, url, timeout=15, **kwargs)
        return resp
    except requests.exceptions.RequestException as exc:
        logger.error("Backend request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "store_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "store_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            error = "Please enter both username and password."
        else:
            resp = _api("POST", "/auth/store-login",
                        json={"username": username, "password": password})
            if resp is None:
                error = "Could not reach the server. Please try again later."
            elif resp.status_code == 200:
                data = resp.json()
                session["store_id"] = data["store_id"]
                session["store_name"] = data["store_name"]
                logger.info("Store '%s' logged in", data["store_name"])
                return redirect(url_for("dashboard"))
            elif resp.status_code == 401:
                error = "Invalid username or password."
            else:
                error = "Login failed. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Fetch inventory from the backend
    resp = _api("GET", "/inventory")
    inventory = []
    if resp and resp.status_code == 200:
        inventory = resp.json()

    # Group items by category
    categories: dict = {}
    for item in inventory:
        cat = item.get("category", "Other")
        categories.setdefault(cat, []).append(item)

    # Fetch allowed delivery dates
    dates_resp = _api("GET", "/settings/allowed_dates")
    allowed_dates = []
    if dates_resp and dates_resp.status_code == 200:
        allowed_dates = dates_resp.json()

    cart = session.get("cart", [])
    cart_total = sum(int(i.get("qty", 0)) for i in cart)

    return render_template(
        "dashboard.html",
        store_name=session["store_name"],
        store_id=session["store_id"],
        categories=categories,
        allowed_dates=allowed_dates,
        cart=cart,
        cart_total=cart_total,
    )


# ---------------------------------------------------------------------------
# Cart API (session-based, JSON responses)
# ---------------------------------------------------------------------------

@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    data = request.get_json(silent=True) or {}
    category = data.get("category", "").strip()
    item = data.get("item", "").strip()

    try:
        qty = int(data.get("qty", 1))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid item data"}), 400

    if not category or not item or qty <= 0:
        return jsonify({"error": "Invalid item data"}), 400

    cart = session.get("cart", [])

    # Update quantity if item already in cart
    for entry in cart:
        if entry["category"] == category and entry["item"] == item:
            entry["qty"] = qty
            session["cart"] = cart
            return jsonify({"cart": cart, "total": sum(e["qty"] for e in cart)})

    cart.append({"category": category, "item": item, "qty": qty})
    session["cart"] = cart
    return jsonify({"cart": cart, "total": sum(e["qty"] for e in cart)})


@app.route("/cart/remove", methods=["POST"])
@login_required
def cart_remove():
    data = request.get_json(silent=True) or {}
    category = data.get("category", "").strip()
    item = data.get("item", "").strip()

    cart = session.get("cart", [])
    cart = [e for e in cart if not (e["category"] == category and e["item"] == item)]
    session["cart"] = cart
    return jsonify({"cart": cart, "total": sum(e["qty"] for e in cart)})


@app.route("/cart/clear", methods=["POST"])
@login_required
def cart_clear():
    session["cart"] = []
    return jsonify({"cart": [], "total": 0})


# ---------------------------------------------------------------------------
# Order submission
# ---------------------------------------------------------------------------

@app.route("/order/submit", methods=["POST"])
@login_required
def order_submit():
    data = request.get_json(silent=True) or {}
    delivery_date = data.get("delivery_date", "").strip()
    cart = session.get("cart", [])

    if not delivery_date:
        return jsonify({"error": "Please select a delivery date."}), 400
    if not cart:
        return jsonify({"error": "Your cart is empty."}), 400

    submitted_at = datetime.utcnow().isoformat()
    payload = [
        {
            "store_id": session["store_id"],
            "category": item["category"],
            "item": item["item"],
            "qty": item["qty"],
            "delivery_date": delivery_date,
            "submitted_at": submitted_at,
        }
        for item in cart
    ]

    resp = _api("POST", "/orders/submit", json=payload)
    if resp is None:
        return jsonify({"error": "Could not reach the server. Please try again."}), 503
    if resp.status_code == 200:
        session["cart"] = []
        return jsonify({"success": True, "message": "Order submitted successfully!"})

    logger.error("Order submit failed: %s %s", resp.status_code, resp.text)
    return jsonify({"error": "Order submission failed. Please try again."}), 500


# ---------------------------------------------------------------------------
# Order history
# ---------------------------------------------------------------------------

@app.route("/history")
@login_required
def history():
    store_name = session["store_name"]
    resp = _api("GET", f"/orders/store/{store_name}")
    orders = []
    if resp and resp.status_code == 200:
        orders = resp.json()
        orders.sort(key=lambda o: o.get("submitted_at", ""), reverse=True)

    return render_template(
        "history.html",
        store_name=store_name,
        orders=orders,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
