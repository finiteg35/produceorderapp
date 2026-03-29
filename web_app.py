"""
web_app.py – Flask web interface for the Produce Order App.

Provides a browser-based store login and ordering dashboard that integrates
with the existing FastAPI backend at https://produce-backend.onrender.com.

Run locally:
    python web_app.py

Or with Gunicorn:
    gunicorn web_app:app
"""

import io
import os
import logging
import secrets
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

import requests
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
    send_file,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_URL = os.environ.get("API_URL", "https://produce-backend.onrender.com")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except ValueError:
    SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", SMTP_USERNAME)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if not os.environ.get("ADMIN_PASSWORD"):
    logger.warning(
        "ADMIN_PASSWORD env var is not set – using insecure default. "
        "Set ADMIN_PASSWORD in your environment before deploying."
    )


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


def admin_required(f):
    """Decorator: redirect to admin login page if the admin is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


def _extract_detail(resp) -> str:
    """Return the 'detail' field from a JSON error response, or empty string."""
    try:
        return resp.json().get("detail", "")
    except ValueError:
        return ""


def _api(method: str, path: str, **kwargs):
    """Make an HTTP request to the FastAPI backend and return the response."""
    url = f"{API_URL}{path}"
    logger.info("Backend request: %s %s", method, url)
    try:
        resp = requests.request(method, url, timeout=15, **kwargs)
        content_type = resp.headers.get("Content-Type", "")
        logger.info(
            "Backend response: status=%s content-type=%s body=%.500s",
            resp.status_code,
            content_type,
            resp.text,
        )
        return resp
    except requests.exceptions.RequestException as exc:
        logger.error("Backend request failed: %s", exc)
        return None


def _send_order_confirmation(
    to_email: str,
    store_name: str,
    ordered_by: str,
    delivery_date: str,
    items: list,
) -> None:
    """Send an order confirmation email to the store.  Errors are logged but
    do not bubble up so that a missing/mis-configured SMTP server never blocks
    a successful order submission."""
    if not SMTP_HOST or not to_email:
        logger.info("Email not configured or no recipient – skipping confirmation email")
        return

    try:
        subject = f"Order Confirmation – {store_name}"

        # Build plain-text body
        lines = [
            f"Hi {store_name},",
            "",
            f"Your order has been placed successfully by {ordered_by}.",
            f"Delivery Date: {delivery_date}",
            "",
            "Order Summary:",
        ]
        for entry in items:
            lines.append(f"  • {entry.get('item', '')} ({entry.get('category', '')}) – Qty: {entry.get('qty', 0)}")
        lines += [
            "",
            "Thank you for your order!",
            "– Green Meadow Farms",
        ]
        text_body = "\n".join(lines)

        # Build HTML body
        item_rows = "".join(
            f"<tr><td>{entry.get('item', '')}</td><td>{entry.get('category', '')}</td>"
            f"<td style='text-align:center'>{entry.get('qty', 0)}</td></tr>"
            for entry in items
        )
        html_body = f"""
        <html><body>
        <p>Hi <strong>{store_name}</strong>,</p>
        <p>Your order has been placed successfully by <strong>{ordered_by}</strong>.</p>
        <p><strong>Delivery Date:</strong> {delivery_date}</p>
        <h3>Order Summary</h3>
        <table border="1" cellpadding="6" cellspacing="0"
               style="border-collapse:collapse;font-family:sans-serif">
          <thead>
            <tr style="background:#4a7c59;color:#fff">
              <th>Item</th><th>Category</th><th>Qty</th>
            </tr>
          </thead>
          <tbody>{item_rows}</tbody>
        </table>
        <br/>
        <p>Thank you for your order!<br/>– Green Meadow Farms</p>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_EMAIL, [to_email], msg.as_string())

        logger.info("Confirmation email sent to %s", to_email)
    except Exception as exc:
        logger.error("Failed to send confirmation email: %s", exc)


# ---------------------------------------------------------------------------
# Spreadsheet builder
# ---------------------------------------------------------------------------

def _build_order_spreadsheet(orders: list, delivery_date: str) -> io.BytesIO:
    """Build an Excel workbook from a list of orders for the given delivery date.

    Layout:
      Row 1 (header): Category | Item | <Store 1> | <Store 2> | …
      Subsequent rows: one row per (category, item) pair, quantities per store.
    Items are sorted by category then name; stores are sorted alphabetically.
    """
    # Gather unique stores and (category, item) pairs
    stores = sorted({o.get("store_name", "") for o in orders})
    items_set = set()
    for o in orders:
        items_set.add((o.get("category", ""), o.get("item", "")))
    items_sorted = sorted(items_set)  # sorts by (category, item)

    # Build lookup: (category, item, store) -> qty
    qty_map: dict = {}
    for o in orders:
        key = (o.get("category", ""), o.get("item", ""), o.get("store_name", ""))
        qty_map[key] = qty_map.get(key, 0) + int(o.get("qty", 0))

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = delivery_date[:10] if delivery_date else "Orders"

    # Styles
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="4A7C59")
    category_fill = PatternFill("solid", fgColor="D9EAD3")
    center_align = Alignment(horizontal="center", vertical="center")
    thin_border_side = Side(style="thin", color="BBBBBB")
    cell_border = Border(
        left=thin_border_side,
        right=thin_border_side,
        top=thin_border_side,
        bottom=thin_border_side,
    )

    # Header row
    headers = ["Category", "Item"] + stores
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center_align
        cell.border = cell_border

    # Data rows
    for row_idx, (category, item) in enumerate(items_sorted, start=2):
        cat_cell = ws.cell(row=row_idx, column=1, value=category)
        item_cell = ws.cell(row=row_idx, column=2, value=item)
        for cell in (cat_cell, item_cell):
            cell.fill = category_fill
            cell.border = cell_border
            cell.alignment = Alignment(vertical="center")

        for col_idx, store in enumerate(stores, start=3):
            qty = qty_map.get((category, item, store), 0)
            qty_cell = ws.cell(row=row_idx, column=col_idx, value=qty if qty else "")
            qty_cell.alignment = center_align
            qty_cell.border = cell_border

    # Column widths
    ws.column_dimensions["A"].width = 20
    ws.column_dimensions["B"].width = 28
    for col_idx in range(3, 3 + len(stores)):
        col_letter = openpyxl.utils.get_column_letter(col_idx)
        # Use store name length + padding, minimum 12
        store_name = stores[col_idx - 3]
        ws.column_dimensions[col_letter].width = max(12, len(store_name) + 4)

    # Freeze header row and first two columns
    ws.freeze_panes = "C2"

    # Row height for header
    ws.row_dimensions[1].height = 20

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output


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
            logger.info("Store login attempt received")
            resp = _api("POST", "/auth/store-login",
                        json={"username": username, "password": password})
            if resp is None:
                error = "Could not reach the server. Please try again later."
            elif resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    logger.error(
                        "Unexpected content-type from backend: %s", content_type
                    )
                    error = "Unexpected response from server. Please try again later."
                else:
                    try:
                        data = resp.json()
                        session["store_id"] = data["store_id"]
                        session["store_name"] = data["store_name"]
                        session["store_email"] = data.get("email") or ""
                        logger.info("Store '%s' logged in", data["store_name"])
                        return redirect(url_for("dashboard"))
                    except ValueError as exc:
                        logger.error("Failed to decode login JSON response: %s", exc)
                        error = "Unexpected response from server. Please try again later."
                    except KeyError as exc:
                        logger.error("Missing expected field in login response: %s", exc)
                        error = "Unexpected response from server. Please try again later."
            elif resp.status_code == 401:
                detail = _extract_detail(resp)
                error = detail if detail else "Invalid username or password."
            else:
                detail = _extract_detail(resp)
                error = detail if detail else "Login failed. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/logout-beacon", methods=["POST"])
def logout_beacon():
    """Endpoint called by navigator.sendBeacon() when the page/tab is closed."""
    if "store_id" in session:
        session.clear()
    return "", 204


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
        data = dates_resp.json()
        if isinstance(data, list):
            allowed_dates = data
        elif isinstance(data, dict):
            allowed_dates = data.get("dates", data.get("allowed_dates", []))

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
    ordered_by = data.get("ordered_by", "").strip()
    cart = session.get("cart", [])

    if not delivery_date:
        return jsonify({"error": "Please select a delivery date."}), 400
    if not ordered_by:
        return jsonify({"error": "Please enter the name of the person placing the order."}), 400
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
            "ordered_by": ordered_by,
        }
        for item in cart
    ]

    resp = _api("POST", "/orders/submit", json=payload)
    if resp is None:
        return jsonify({"error": "Could not reach the server. Please try again."}), 503
    if resp.status_code == 200:
        _send_order_confirmation(
            to_email=session.get("store_email", ""),
            store_name=session["store_name"],
            ordered_by=ordered_by,
            delivery_date=delivery_date,
            items=cart,
        )
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
# Admin – login / dashboard / spreadsheet download
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user_ok = secrets.compare_digest(username, ADMIN_USERNAME)
        pass_ok = secrets.compare_digest(password, ADMIN_PASSWORD)
        if user_ok and pass_ok:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Invalid admin credentials."

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    # Fetch allowed delivery dates for the date picker
    dates_resp = _api("GET", "/settings/allowed_dates")
    allowed_dates = []
    if dates_resp and dates_resp.status_code == 200:
        data = dates_resp.json()
        if isinstance(data, list):
            allowed_dates = data
        elif isinstance(data, dict):
            allowed_dates = data.get("dates", data.get("allowed_dates", []))

    selected_date = request.args.get("delivery_date", "").strip()
    orders = []
    stores = []
    items_sorted = []
    qty_map: dict = {}

    if selected_date:
        resp = _api("GET", f"/orders?date_prefix={selected_date}")
        if resp and resp.status_code == 200:
            orders = resp.json()
        stores = sorted({o.get("store_name", "") for o in orders})
        items_set = set()
        for o in orders:
            items_set.add((o.get("category", ""), o.get("item", "")))
        items_sorted = sorted(items_set)
        for o in orders:
            key = (o.get("category", ""), o.get("item", ""), o.get("store_name", ""))
            qty_map[key] = qty_map.get(key, 0) + int(o.get("qty", 0))

    return render_template(
        "admin.html",
        allowed_dates=allowed_dates,
        selected_date=selected_date,
        stores=stores,
        items=items_sorted,
        qty_map=qty_map,
    )


@app.route("/admin/orders/spreadsheet")
@admin_required
def admin_spreadsheet():
    delivery_date = request.args.get("delivery_date", "").strip()
    if not delivery_date:
        flash("Please select a delivery date.", "error")
        return redirect(url_for("admin_dashboard"))

    resp = _api("GET", f"/orders?date_prefix={delivery_date}")
    if resp is None:
        flash("Could not reach the server. Please try again.", "error")
        return redirect(url_for("admin_dashboard", delivery_date=delivery_date))
    if resp.status_code != 200:
        flash("Failed to retrieve orders.", "error")
        return redirect(url_for("admin_dashboard", delivery_date=delivery_date))

    orders = resp.json()
    if not orders:
        flash("No orders found for that delivery date.", "warning")
        return redirect(url_for("admin_dashboard", delivery_date=delivery_date))

    spreadsheet = _build_order_spreadsheet(orders, delivery_date)
    safe_date = delivery_date.replace(" ", "_").replace(",", "").replace("/", "-")
    filename = f"orders_{safe_date}.xlsx"

    return send_file(
        spreadsheet,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
