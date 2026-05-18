"""
Everblack – Web edition with authentication
====================================================
Roles:
  admin  – full access to everything
  store  – submit orders and view own order history only
API key header (X-API-Key) grants admin-level access for backend automation.
"""

import json
import os
import sys
import logging
import tempfile
import threading
import functools
import smtplib
import secrets
import io
import base64
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import (
    Flask, redirect, render_template_string, request,
    url_for, session, jsonify
)
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

import main as cli

# ---------------------------------------------------------------------------
# UPC resolver — finds the correct UPC for a store given inventory store_groups
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Timezone helper — stamp orders in Eastern Time
# ---------------------------------------------------------------------------

_EASTERN = timezone(timedelta(hours=-5))  # EST; DST-aware via dateutil if available

def _now_eastern():
    """Return current time as an Eastern-time ISO string (e.g. 2026-04-30 05:38 ET)."""
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo('America/New_York')
        return datetime.now(tz).strftime('%Y-%m-%d %I:%M %p ET')
    except Exception:
        # Fallback: fixed UTC-5 offset
        return datetime.now(timezone.utc).astimezone(_EASTERN).strftime('%Y-%m-%d %I:%M %p ET')

def _stamp_eastern(order):
    """Overwrite submitted_at on an order dict with the current Eastern time."""
    order['submitted_at'] = _now_eastern()
    return order


def _resolve_upc(inventory_item, store_number):
    """Return the correct UPC for store_number. New items have a flat upc field.
    Legacy items may have store_groups array."""
    # New flat format
    if inventory_item.get('upc'):
        return str(inventory_item['upc'])
    # Legacy store_groups array
    store_groups = inventory_item.get('store_groups', [])
    if not store_groups:
        return ''
    sn = str(store_number).strip()
    for sg in store_groups:
        if sn in [str(s).strip() for s in sg.get('stores', [])]:
            return sg.get('upc', '')
    return store_groups[0].get('upc', '') if store_groups else ''

app = Flask(__name__)
# Trust exactly one proxy (Traefik) for X-Forwarded-For — prevents IP spoofing
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ---------------------------------------------------------------------------
# Structured logging — JSON lines to stdout for docker logs / log aggregators
# ---------------------------------------------------------------------------
_log_handler = logging.StreamHandler(sys.stdout)
_log_handler.setFormatter(logging.Formatter(
    '{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}'
))
app.logger.handlers = [_log_handler]
app.logger.setLevel(logging.INFO)
logging.getLogger("gunicorn.error").handlers = [_log_handler]
logging.getLogger("gunicorn.access").handlers = [_log_handler]
_secret_key = os.environ.get("SECRET_KEY", "")
if not _secret_key or _secret_key == "change-me-in-production-please":
    print("FATAL: SECRET_KEY environment variable is not set or is the default placeholder. "
          "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(64))\""
          " and set it in your .env file.", file=sys.stderr)
    sys.exit(1)
app.secret_key = _secret_key
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour max
app.config["SESSION_COOKIE_PERMANENT"] = False  # session cookie only — dies when browser closes
API_KEY = os.environ.get("API_KEY", "")
if not API_KEY or API_KEY == "openclaw-produce-api-key-2026":
    print("FATAL: API_KEY environment variable is not set or is the default value. "
          "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
          " and set it in your .env file.", file=sys.stderr)
    sys.exit(1)
DATA_DIR = os.environ.get("DATA_DIR", "./data")

# ---------------------------------------------------------------------------
# Security headers — added to every response
# ---------------------------------------------------------------------------
@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https://*.tile.openstreetmap.org; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self'"
    )
    return response

@app.errorhandler(Exception)
def _handle_unhandled_exception(e):
    """Catch-all: log full traceback, return sanitized error to client."""
    import traceback
    app.logger.error(
        f"Unhandled exception | "
        f"path={request.path} | method={request.method} | "
        f"user={session.get('username', 'anon')} | "
        f"error={e}\n{traceback.format_exc()}"
    )
    # Re-raise HTTP exceptions (404, 403, etc.) so Flask handles them normally
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    return "An unexpected error occurred. Please try again.", 500

# ---------------------------------------------------------------------------
# Brute-force login protection — max 10 attempts per IP per 10 min
# Persisted to file so limits survive restarts
# ---------------------------------------------------------------------------
_LOGIN_WINDOW = 600   # seconds
_LOGIN_MAX = 10
_RATE_STATE_FILE = None  # set after DATA_DIR is known
_rate_state_lock = threading.Lock()

def _get_rate_state_file():
    global _RATE_STATE_FILE
    if _RATE_STATE_FILE is None:
        _RATE_STATE_FILE = os.path.join(DATA_DIR, ".rate_state.json")
    return _RATE_STATE_FILE

def _load_rate_state():
    path = _get_rate_state_file()
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {"login": {}, "api": {}}

def _save_rate_state(state):
    try:
        _atomic_write(_get_rate_state_file(), state)
    except Exception:
        pass  # non-critical — degrade gracefully

def _check_login_rate(ip):
    """Return True if allowed, False if rate-limited."""
    now = datetime.now(timezone.utc).timestamp()
    with _rate_state_lock:
        state = _load_rate_state()
        attempts = [t for t in state["login"].get(ip, []) if now - t < _LOGIN_WINDOW]
        if len(attempts) >= _LOGIN_MAX:
            return False
        attempts.append(now)
        state["login"][ip] = attempts
        _save_rate_state(state)
    return True

# ---------------------------------------------------------------------------
# API rate limiting — sliding window per IP
# ---------------------------------------------------------------------------
_API_WINDOW      = 60    # seconds
_API_MAX_READ    = 120   # GET requests per window
_API_MAX_WRITE   = 60    # POST requests per window

def _check_api_rate(ip, is_write=False):
    """Return (allowed, retry_after)."""
    now = datetime.now(timezone.utc).timestamp()
    with _rate_state_lock:
        state = _load_rate_state()
        calls = [t for t in state["api"].get(ip, []) if now - t < _API_WINDOW]
        limit = _API_MAX_WRITE if is_write else _API_MAX_READ
        if len(calls) >= limit:
            oldest = calls[0]
            retry_after = int(_API_WINDOW - (now - oldest)) + 1
            return False, retry_after
        calls.append(now)
        state["api"][ip] = calls
        _save_rate_state(state)
    return True, 0

def api_rate_limit(f):
    """Decorator: rate-limit API endpoints. Must come AFTER @app.route."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        is_write = request.method == "POST"
        allowed, retry_after = _check_api_rate(ip, is_write)
        if not allowed:
            resp = jsonify({"error": "rate limit exceeded", "retry_after": retry_after})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# CSRF Protection
# ---------------------------------------------------------------------------

def _get_csrf_token():
    """Return (and lazily create) the CSRF token for the current session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_protect(f):
    """Decorator: validate CSRF token on POST. Skips when X-API-Key header is present."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            if request.headers.get('X-API-Key') == API_KEY:
                return f(*args, **kwargs)
            token = (request.form.get('csrf_token') or
                     request.headers.get('X-CSRF-Token') or '')
            if not token or token != session.get('csrf_token', ''):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'ok': False, 'msg': 'Invalid or missing CSRF token.'}), 403
                return redirect(url_for('login', msg='Session expired. Please log in again.', cls='err'))
        return f(*args, **kwargs)
    return decorated

USERS_FILE = os.path.join(DATA_DIR, "users.json")
VENDORS_FILE = os.path.join(DATA_DIR, "vendors.json")
INVOICES_FILE = os.path.join(DATA_DIR, "invoices.json")
QR_TOKENS_FILE = os.path.join(DATA_DIR, "qr_tokens.json")

# ---------------------------------------------------------------------------
# File-write safety — per-file locks + atomic saves
# ---------------------------------------------------------------------------
_FILE_LOCKS = {}
_FILE_LOCKS_LOCK = threading.Lock()

def _get_file_lock(path):
    """Return (creating if needed) a per-file threading.Lock."""
    with _FILE_LOCKS_LOCK:
        if path not in _FILE_LOCKS:
            _FILE_LOCKS[path] = threading.Lock()
        return _FILE_LOCKS[path]

def _atomic_write(path, data):
    """Write JSON atomically: write to temp file then os.replace (POSIX atomic)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    dir_ = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", dir=dir_, delete=False, suffix=".tmp") as tf:
        json.dump(data, tf, indent=2)
        tmp_path = tf.name
    os.replace(tmp_path, path)

QR_TOKEN_TTL_DAYS = 90  # QR tokens expire after this many days

# ---------------------------------------------------------------------------
# Driver area store lists
# ---------------------------------------------------------------------------
BREWER_STORES = {
    "hannaford_ellsworth", "hannaford_barharbor", "hannaford_bluehill",
    "hannaford_bucksport", "hannaford_brewer", "hannaford_hampden",
    "hannaford_hoganroad", "hannaford_airport", "hannaford_broadway",
    "hannaford_oldtown", "hannaford_lincoln", "danforth", "paradis",
    "edward_brothers", "gm_familymarket", "lincoln_steaks",
    "friends_family", "hilton_garden_inn", "chases_restaurant",
    "masons_brewing", "marsh_island", "paddy_murphys", "dennis_food",
}
BIDDEFORD_STORES = {
    "beckys_diner", "scratch_bakery", "twofatcats", "rosemont_bakery",
    "valeries_diner", "robins_confections", "pier_fries",
    "josephs_bythesea", "hannaford_biddeford", "hannaford_saco",
    "hannaford_scarborough", "hannaford_mainemall", "hannaford_millcreek",
    "ramunos", "hannaford_riverside", "hannaford_falmouth",
    "hannaford_westbrook", "beach_lobster", "native_maine",
}
AREA_STORES = {"brewer": BREWER_STORES, "biddeford": BIDDEFORD_STORES}

# ---------------------------------------------------------------------------
# Vendor storage helpers
# ---------------------------------------------------------------------------

def _load_vendors():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(VENDORS_FILE):
        return [{"id": "gmf", "name": "Green Meadow Farms", "slug": "gmf", "office_email": ""}]
    with open(VENDORS_FILE) as f:
        return json.load(f)

def _save_vendors(vendors):
    with _get_file_lock(VENDORS_FILE):
        _atomic_write(VENDORS_FILE, vendors)

def _get_vendor(vid):
    return next((v for v in _load_vendors() if v["id"] == vid), None)

# ---------------------------------------------------------------------------
# QR Token helpers
# ---------------------------------------------------------------------------

def _load_qr_tokens():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(QR_TOKENS_FILE):
        return []
    with open(QR_TOKENS_FILE) as f:
        return json.load(f)

def _save_qr_tokens(tokens):
    with _get_file_lock(QR_TOKENS_FILE):
        _atomic_write(QR_TOKENS_FILE, tokens)

def _get_qr_token_for_user(username):
    """Return the active token record for a username, or None."""
    return next((t for t in _load_qr_tokens() if t['username'] == username), None)

def _generate_qr_token(username):
    """Generate (or replace) a QR login token for a user. Returns the token string."""
    tokens = _load_qr_tokens()
    tokens = [t for t in tokens if t['username'] != username]  # revoke old
    token = secrets.token_urlsafe(48)
    from datetime import datetime, timezone, timedelta
    now_utc = datetime.now(timezone.utc)
    tokens.append({
        'token': token,
        'username': username,
        'created_at': now_utc.isoformat(),
        'expires_at': (now_utc + timedelta(days=QR_TOKEN_TTL_DAYS)).isoformat(),
    })
    _save_qr_tokens(tokens)
    return token

def _revoke_qr_token(username):
    """Remove any QR token for a username."""
    tokens = [t for t in _load_qr_tokens() if t['username'] != username]
    _save_qr_tokens(tokens)

_LOGO_B64 = "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"

def _make_qr_png_bytes(url, vendor_name="", store_name=""):
    """Return a branded QR card PNG: vendor name + store name header + QR code with Everblack logo center."""
    import qrcode
    from PIL import Image, ImageDraw, ImageFont
    # Build QR with high error correction so logo overlay doesn't break scanning
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    qr_size = qr_img.size[0]
    # Paste logo in center
    logo_bytes = base64.b64decode(_LOGO_B64)
    logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
    logo_target = int(qr_size * 0.20)
    logo = logo.resize((logo_target, logo_target), Image.LANCZOS)
    pad = 6
    bg = Image.new("RGBA", (logo_target + pad * 2, logo_target + pad * 2), (255, 255, 255, 255))
    bg.paste(logo, (pad, pad), logo)
    pos = ((qr_size - bg.size[0]) // 2, (qr_size - bg.size[1]) // 2)
    qr_img.paste(bg, pos, bg)
    # Build card with header
    header_h = 100
    card = Image.new("RGBA", (qr_size, qr_size + header_h), (255, 255, 255, 255))
    draw = ImageDraw.Draw(card)
    try:
        font_big = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 26)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except Exception:
        font_big = ImageFont.load_default()
        font_small = font_big
    # Vendor name
    label = vendor_name or "Everblack"
    bbox = draw.textbbox((0, 0), label, font=font_big)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    top_y = 10
    draw.text(((qr_size - tw) // 2, top_y), label, fill=(30, 30, 30), font=font_big)
    # Store name below
    if store_name:
        sbbox = draw.textbbox((0, 0), store_name, font=font_small)
        sw = sbbox[2] - sbbox[0]
        draw.text(((qr_size - sw) // 2, top_y + th + 10), store_name, fill=(80, 80, 80), font=font_small)
    card.paste(qr_img, (0, header_h))
    buf = io.BytesIO()
    card.convert("RGB").save(buf, format="PNG")
    return buf.getvalue()

# ---------------------------------------------------------------------------
# Order UPC patcher
# ---------------------------------------------------------------------------

def _patch_order_upc(order_id, upc, vendor_id=None, case_size=None, submitted_at=None):
    """Backfill upc, vendor_id, case_size, and submitted_at onto a just-saved order record in orders.json."""
    orders_file = os.path.join(DATA_DIR, "orders.json")
    if not os.path.exists(orders_file):
        return
    with open(orders_file) as f:
        orders = json.load(f)
    for o in orders:
        if o.get('id') == order_id:
            o['upc'] = upc
            if vendor_id:
                o['vendor_id'] = vendor_id
            if case_size is not None:
                o['case_size'] = case_size
            if submitted_at:
                o['submitted_at'] = submitted_at
            break
    orders_file = os.path.join(DATA_DIR, "orders.json")
    with _get_file_lock(orders_file):
        _atomic_write(orders_file, orders)

def _disp_qty(qty, case_size):
    """Return qty × numeric part of case_size when parseable, else return qty as-is."""
    import re
    if case_size:
        m = re.match(r'^(\d+)', str(case_size).strip())
        if m:
            cs = int(m.group(1))
            if cs > 0:
                try:
                    return int(qty) * cs
                except (ValueError, TypeError):
                    pass
    return qty

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.hostinger.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "everblack@watcherhq.net")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
OFFICE_EMAIL = os.environ.get("OFFICE_EMAIL", "everblack@watcherhq.net")

# ---------------------------------------------------------------------------
# Barcode helper — generates base64 PNG for embedding in emails
# ---------------------------------------------------------------------------

def _upc_to_barcode_b64(upc):
    """Return a base64-encoded PNG barcode for the given UPC string, or None on failure."""
    try:
        import barcode as _barcode
        import io, base64
        from barcode.writer import ImageWriter
        upc = str(upc).strip().replace('-', '').replace(' ', '')
        if not upc or upc == 'None':
            return None
        # Always use CODE128 — handles any length (12, 13, 14-digit UPCs all work)
        buf = io.BytesIO()
        bc = _barcode.get('code128', upc, writer=ImageWriter())
        bc.write(buf, options={
            'write_text': False,
            'module_height': 10,
            'quiet_zone': 2,
            'font_size': 0,
        })
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None


def _send_email(to, subject, body_html, body_text=""):
    """Send email via SMTP SSL in a background thread."""
    def _send():
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"Everblack <{SMTP_USER}>"
            msg["To"] = to
            if body_text:
                msg.attach(MIMEText(body_text, "plain"))
            msg.attach(MIMEText(body_html, "html"))
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_USER, to, msg.as_string())
            app.logger.info(f"Email sent | to={to} | subject={subject!r}")
        except Exception as e:
            app.logger.error(f"Email FAILED | to={to} | subject={subject!r} | error={e}")
    if SMTP_PASS:
        threading.Thread(target=_send, daemon=True).start()
    else:
        app.logger.warning(f"Email skipped (SMTP_PASS not set) | to={to} | subject={subject!r}")

def _send_order_confirmation(to_email, order, store_name, store_number=""):
    store_label = f"{store_name} #{store_number}" if store_number else store_name
    subject = f"Order Confirmation #{order['id']} — {store_label}"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto">
      <div style="background:#2d6a4f;padding:1rem 1.5rem;border-radius:8px 8px 0 0">
        <h2 style="color:#fff;margin:0">Order Confirmed</h2>
      </div>
      <div style="background:#fff;padding:1.5rem;border:1px solid #e0e0e0;border-radius:0 0 8px 8px">
        <p style="color:#555">Your order has been received. Here are the details:</p>
        <table style="width:100%;border-collapse:collapse;margin-top:1rem">
          <tr style="background:#e9f5ee"><th style="padding:.5rem;text-align:left">Field</th><th style="padding:.5rem;text-align:left">Details</th></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Order #</td><td style="padding:.5rem;border-bottom:1px solid #eee">{order['id']}</td></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Store</td><td style="padding:.5rem;border-bottom:1px solid #eee">{store_label}</td></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Category</td><td style="padding:.5rem;border-bottom:1px solid #eee">{order.get('category','')}</td></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Item</td><td style="padding:.5rem;border-bottom:1px solid #eee">{order.get('item','')}</td></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Quantity</td><td style="padding:.5rem;border-bottom:1px solid #eee">{_disp_qty(order.get('qty',0), order.get('case_size',''))}</td></tr>
          <tr><td style="padding:.5rem;border-bottom:1px solid #eee">Delivery Date</td><td style="padding:.5rem;border-bottom:1px solid #eee">{order.get('delivery_date','')}</td></tr>
          <tr><td style="padding:.5rem">Submitted</td><td style="padding:.5rem">{order.get('submitted_at','')}</td></tr>
        </table>
        <p style="margin-top:1.5rem;color:#888;font-size:.85rem">Questions? Contact your produce rep.</p>
      </div>
    </div>
    """
    _send_email(to_email, subject, html)

def _send_order_confirmation_summary(to_email, orders, store_name, delivery_date, store_number="", vendor_name=""):
    """Send one consolidated confirmation email for all items in an order."""
    store_label = f"{store_name} #{store_number}" if store_number else store_name
    rows = "".join([
        f"""<tr>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('category','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('item','')} {'<span style="font-size:.75rem;color:#888">(' + o.get('case_size','') + ' / case)</span>' if o.get('case_size') else ''}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{_disp_qty(o.get('qty',0), o.get('case_size',''))}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">
            {'<img src="data:image/png;base64,' + _upc_to_barcode_b64(o.get("upc","")) + '" style="display:block;height:40px" alt="' + str(o.get("upc","")) + '"><div style="font-size:.7rem;color:#888;text-align:center">' + str(o.get("upc","")) + '</div>' if o.get('upc') and _upc_to_barcode_b64(o.get('upc','')) else o.get('upc','&mdash;')}
          </td>
        </tr>""" for o in orders
    ])
    subject = f"Order Confirmation \u2014 {store_label} \u2014 Delivery {delivery_date}"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto">
      <div style="background:#2d6a4f;padding:1rem 1.5rem;border-radius:8px 8px 0 0">
        <h2 style="color:#fff;margin:0">Order Confirmed{' by ' + vendor_name if vendor_name else ''}</h2>
        <p style="color:#52c97a;margin:.25rem 0 0">{store_label} &mdash; Delivery: {delivery_date}</p>
      </div>
      <div style="background:#fff;padding:1.5rem;border:1px solid #e0e0e0;border-radius:0 0 8px 8px">
        <p style="color:#555;margin-bottom:1rem">Your order has been received. Here are the items ordered:</p>
        <table style="width:100%;border-collapse:collapse">
          <tr style="background:#e9f5ee">
            <th style="padding:.5rem .75rem;text-align:left">Category</th>
            <th style="padding:.5rem .75rem;text-align:left">Item</th>
            <th style="padding:.5rem .75rem;text-align:left">Qty</th>
            <th style="padding:.5rem .75rem;text-align:left">UPC</th>
          </tr>
          {rows}
        </table>
        <p style="margin-top:1.5rem;color:#888;font-size:.85rem">Questions? Contact your produce rep.</p>
      </div>
    </div>
    """
    _send_email(to_email, subject, html)

def _send_new_order_alert(vendor_id, store_name, store_number, delivery_date, ordered_by, submitted_orders):
    """Fire a real-time email to the vendor's office when a new order is submitted."""
    vendor = _get_vendor(vendor_id)
    if not vendor:
        return
    to_email = vendor.get("office_email") or OFFICE_EMAIL
    vendor_name = vendor.get("name", vendor_id)
    store_label = f"{store_name} #{store_number}" if store_number else store_name
    item_count = len(submitted_orders)
    rows = "".join([
        f"""<tr>
          <td style="padding:.4rem .75rem;border-bottom:1px solid #eee">{o.get('category','')}</td>
          <td style="padding:.4rem .75rem;border-bottom:1px solid #eee">{o.get('item','')}{
            ' <span style="font-size:.75rem;color:#888">('+o.get('case_size','')+' / case)</span>' if o.get('case_size') else ''
          }</td>
          <td style="padding:.4rem .75rem;border-bottom:1px solid #eee;text-align:center">{_disp_qty(o.get('qty',0), o.get('case_size',''))}</td>
        </tr>""" for o in submitted_orders
    ])
    subject = f"\U0001f6d2 New Order — {store_label} — Delivery {delivery_date}"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto">
      <div style="background:#1a3a2a;padding:1rem 1.5rem;border-radius:8px 8px 0 0;border-bottom:3px solid #52c97a">
        <h2 style="color:#52c97a;margin:0">✅ New Order Received</h2>
        <p style="color:#a0e4b8;margin:.35rem 0 0;font-size:.95rem">
          <strong>{store_label}</strong> &mdash; {item_count} item{'s' if item_count != 1 else ''} &mdash; Delivery: <strong>{delivery_date}</strong>
        </p>
      </div>
      <div style="background:#fff;padding:1.5rem;border:1px solid #d0e8d8;border-radius:0 0 8px 8px">
        <p style="color:#444;margin:0 0 1rem">Ordered by: <strong>{ordered_by}</strong> &mdash; Submitted: <strong>{submitted_orders[0].get('submitted_at','') if submitted_orders else ''}</strong></p>
        <table style="width:100%;border-collapse:collapse">
          <tr style="background:#e9f5ee">
            <th style="padding:.5rem .75rem;text-align:left;font-size:.875rem">Category</th>
            <th style="padding:.5rem .75rem;text-align:left;font-size:.875rem">Item</th>
            <th style="padding:.5rem .75rem;text-align:center;font-size:.875rem">Qty</th>
          </tr>
          {rows}
        </table>
        <p style="margin-top:1.25rem;color:#888;font-size:.8rem">
          Sent by Everblack Orders &mdash; {vendor_name}
        </p>
      </div>
    </div>
    """
    _send_email(to_email, subject, html)

def _send_office_daily_summary(delivery_date):
    orders = cli.orders_list(date=delivery_date)
    if not orders:
        return
    vendors = _load_vendors()
    vmap = {v["id"]: v for v in vendors}

    # Group orders by vendor_id so each vendor gets their own summary
    from collections import defaultdict
    by_vendor = defaultdict(list)
    for o in orders:
        vid = o.get("vendor_id", "gmf")
        by_vendor[vid].append(o)

    for vid, vendor_orders in by_vendor.items():
        vendor = vmap.get(vid, {})
        to_email = vendor.get("office_email") or OFFICE_EMAIL
        vendor_name = vendor.get("name", vid)
        rows = "".join([
            f"""<tr>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o['id']}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('store_name','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('category','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('item','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{_disp_qty(o.get('qty',0), o.get('case_size',''))}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">
            {'<img src="data:image/png;base64,' + _upc_to_barcode_b64(o.get("upc","")) + '" style="display:block;height:40px" alt="' + str(o.get("upc","")) + '"><div style="font-size:.7rem;color:#888;text-align:center">' + str(o.get("upc","")) + '</div>' if o.get('upc') and _upc_to_barcode_b64(o.get('upc','')) else o.get('upc','&mdash;')}
          </td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{o.get('ordered_by','')}</td>
        </tr>""" for o in vendor_orders
        ])
        subject = f"Daily Order Summary \u2014 {vendor_name} \u2014 Delivery {delivery_date} ({len(vendor_orders)} orders)"
        html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:800px;margin:0 auto">
      <div style="background:#2d6a4f;padding:1rem 1.5rem;border-radius:8px 8px 0 0">
        <h2 style="color:#fff;margin:0">Daily Order Summary</h2>
        <p style="color:#52c97a;margin:.25rem 0 0">{vendor_name} &mdash; Delivery Date: {delivery_date} &mdash; {len(vendor_orders)} order(s)</p>
      </div>
      <div style="background:#fff;padding:1.5rem;border:1px solid #e0e0e0;border-radius:0 0 8px 8px">
        <table style="width:100%;border-collapse:collapse">
          <tr style="background:#e9f5ee">
            <th style="padding:.5rem .75rem;text-align:left">ID</th>
            <th style="padding:.5rem .75rem;text-align:left">Store</th>
            <th style="padding:.5rem .75rem;text-align:left">Category</th>
            <th style="padding:.5rem .75rem;text-align:left">Item</th>
            <th style="padding:.5rem .75rem;text-align:left">Qty</th>
            <th style="padding:.5rem .75rem;text-align:left">Barcode</th>
            <th style="padding:.5rem .75rem;text-align:left">Ordered By</th>
          </tr>
          {rows}
        </table>
      </div>
    </div>
    """
        _send_email(to_email, subject, html)

def _qb_push_invoice(inv, vendor_user):
    """Push invoice to QuickBooks Online. Returns (True, qb_id) or (False, error_msg).
    Uses only stdlib urllib — no requests dependency.
    Auto-refreshes expired tokens, auto-creates QB customers that don't exist yet.
    Persists refreshed tokens back to users.json.
    """
    import urllib.request as _urlreq, urllib.parse as _urlparse, base64 as _b64, json as _json
    realm_id = vendor_user.get("qb_realm_id", "")
    if not vendor_user.get("qb_token") or not realm_id:
        return False, "QB not connected for this vendor."
    QB_CLIENT_ID = os.environ.get("QB_CLIENT_ID", "")
    QB_CLIENT_SECRET = os.environ.get("QB_CLIENT_SECRET", "")
    base_url = "https://sandbox-quickbooks.api.intuit.com" if os.environ.get("QB_SANDBOX", "0") == "1" else "https://quickbooks.api.intuit.com"

    def _http(method, url, headers=None, body=None):
        """Simple urllib wrapper. Returns (status_code, parsed_json_or_string)."""
        import urllib.error as _urlerr
        if isinstance(body, dict):
            body = _json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        req = _urlreq.Request(url, data=body, headers=headers or {}, method=method)
        try:
            with _urlreq.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode()
                try:
                    return resp.status, _json.loads(raw)
                except Exception:
                    return resp.status, raw
        except _urlerr.HTTPError as e:
            try:
                raw = e.read().decode()
            except Exception:
                raw = str(e)
            try:
                return e.code, _json.loads(raw)
            except Exception:
                return e.code, raw
        except Exception as e:
            return 0, str(e)

    def _auth_headers():
        return {"Authorization": f"Bearer {vendor_user['qb_token']}",
                "Accept": "application/json", "Content-Type": "application/json"}

    def _do_refresh():
        creds = _b64.b64encode(f"{QB_CLIENT_ID}:{QB_CLIENT_SECRET}".encode()).decode()
        body = _urlparse.urlencode({"grant_type": "refresh_token",
                                    "refresh_token": vendor_user.get("qb_refresh_token", "")})
        status, data = _http("POST", "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
                             headers={"Authorization": f"Basic {creds}",
                                      "Accept": "application/json",
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             body=body)
        if status == 200 and isinstance(data, dict):
            new_access = data.get("access_token", "")
            new_refresh = data.get("refresh_token", vendor_user.get("qb_refresh_token", ""))
            all_users = _load_users()
            for u in all_users:
                if u.get("username") == vendor_user.get("username"):
                    u["qb_token"] = new_access
                    u["qb_refresh_token"] = new_refresh
            _save_users(all_users)
            vendor_user["qb_token"] = new_access
            vendor_user["qb_refresh_token"] = new_refresh

    def _ensure_customer(name):
        q = _urlparse.urlencode({"query": f"SELECT Id FROM Customer WHERE DisplayName = '{name.replace(chr(39), chr(39)*2)}'",
                                  "minorversion": "65"})
        status, data = _http("GET", f"{base_url}/v3/company/{realm_id}/query?{q}",
                             headers=_auth_headers())
        if status == 401:
            _do_refresh()
            status, data = _http("GET", f"{base_url}/v3/company/{realm_id}/query?{q}",
                                 headers=_auth_headers())
        if status == 200 and isinstance(data, dict):
            customers = data.get("QueryResponse", {}).get("Customer", [])
            if customers:
                return customers[0]["Id"], None
        # Not found — create
        status, data = _http("POST", f"{base_url}/v3/company/{realm_id}/customer?minorversion=65",
                             headers=_auth_headers(), body={"DisplayName": name})
        if status == 401:
            _do_refresh()
            status, data = _http("POST", f"{base_url}/v3/company/{realm_id}/customer?minorversion=65",
                                 headers=_auth_headers(), body={"DisplayName": name})
        if status == 200 and isinstance(data, dict):
            return data.get("Customer", {}).get("Id"), None
        # If duplicate error (6240), customer exists under a different name — fetch all and match
        is_duplicate = False
        if isinstance(data, dict):
            for err in (data.get("Fault") or {}).get("Error", []):
                if str(err.get("code")) == "6240":
                    is_duplicate = True
        if is_duplicate:
            q2 = _urlparse.urlencode({"query": "SELECT Id, DisplayName FROM Customer MAXRESULTS 1000",
                                      "minorversion": "65"})
            s2, d2 = _http("GET", f"{base_url}/v3/company/{realm_id}/query?{q2}",
                           headers=_auth_headers())
            if s2 == 200 and isinstance(d2, dict):
                all_customers = d2.get("QueryResponse", {}).get("Customer", [])
                # Exact match first (case-insensitive)
                name_lower = name.lower()
                for c in all_customers:
                    if c.get("DisplayName", "").lower() == name_lower:
                        return c["Id"], None
                # Partial match — first word of store name
                first_word = name_lower.split()[0] if name_lower.split() else name_lower
                matches = [c for c in all_customers if first_word in c.get("DisplayName", "").lower()]
                if matches:
                    matched_name = matches[0]["DisplayName"]
                    # Save the correct QB name back to the store user so future syncs hit exactly
                    all_u = _load_users()
                    for u in all_u:
                        if u.get("store_name") == inv.get("store_name") and u.get("vendor_id") == inv.get("vendor_id"):
                            u["qb_customer_name"] = matched_name
                    _save_users(all_u)
                    return matches[0]["Id"], None
            return None, f"Duplicate customer in QB but could not locate it. Please check QB customer name for '{name}'."
        err = data if isinstance(data, str) else _json.dumps(data)[:400]
        return None, f"QB customer error (HTTP {status}): {err}"

    # Resolve customer name
    _users = _load_users()
    _store_user = next((u for u in _users if u.get("store_name") == inv.get("store_name")
                        and u.get("vendor_id") == inv.get("vendor_id")), None)
    _qb_customer_name = ((_store_user or {}).get("qb_customer_name") or inv.get("store_name", "")).strip()

    cust_id, cust_err = _ensure_customer(_qb_customer_name)
    if not cust_id:
        return False, cust_err or f"Could not find or create QB customer '{_qb_customer_name}'."

    # Fetch item prices AND IDs from QB catalog in one bulk call
    def _fetch_item_catalog():
        q = _urlparse.urlencode({"query": "SELECT Id, Name, UnitPrice, Sku FROM Item MAXRESULTS 1000", "minorversion": "65"})
        status, data = _http("GET", f"{base_url}/v3/company/{realm_id}/query?{q}", headers=_auth_headers())
        if status == 401:
            _do_refresh()
            status, data = _http("GET", f"{base_url}/v3/company/{realm_id}/query?{q}", headers=_auth_headers())
        if status == 200 and isinstance(data, dict):
            catalog = {}
            for item in data.get("QueryResponse", {}).get("Item", []):
                catalog[item["Name"]] = {
                    "id":    item.get("Id", ""),
                    "price": float(item.get("UnitPrice") or 0),
                    "sku":   item.get("Sku", "") or ""
                }
            return catalog
        return {}

    catalog = _fetch_item_catalog()
    # Build case-insensitive lookup as fallback
    catalog_lower = {k.lower(): v for k, v in catalog.items()}
    # PLU→QB item lookup: only items where QB has a SKU (= PLU) populated
    plu_catalog = {v["sku"].strip(): v for v in catalog.values() if v.get("sku", "").strip()}

    def _lookup_item(name):
        """Exact match → case-insensitive → PLU/SKU → starts-with → contains."""
        if not name:
            return {}
        # Exact
        if name in catalog:
            return catalog[name]
        # Case-insensitive exact
        nl = name.lower().strip()
        if nl in catalog_lower:
            return catalog_lower[nl]
        # PLU/SKU match — catches Hannaford items where qb_item_name was set to PLU
        if name.strip() in plu_catalog:
            return plu_catalog[name.strip()]
        # Starts-with (QB name starts with invoice name, or vice versa)
        for k, v in catalog_lower.items():
            if k.startswith(nl) or nl.startswith(k):
                return v
        # Contains first two words
        words = nl.split()
        if len(words) >= 2:
            prefix = ' '.join(words[:2])
            for k, v in catalog_lower.items():
                if prefix in k:
                    return v
        # Contains first word (only if it's long enough to be meaningful)
        if words and len(words[0]) >= 4:
            for k, v in catalog_lower.items():
                if words[0] in k:
                    return v
        return {}

    line_items = []
    for i, li in enumerate(inv.get("line_items", [])):
        item_name  = li.get("qb_item_name") or li.get("item", "")
        qty        = float(li.get("qty", 1))
        # UPC/PLU match FIRST — more precise than name fuzzy matching
        # Tries: last 4, last 5, dash segment, full stripped UPC (with/without leading zeros)
        upc_raw = str(li.get("upc") or "").strip().replace("-", "").replace(" ", "")
        upc_orig = str(li.get("upc") or "").strip()
        dash_segment = upc_orig.split("-")[-1].strip() if "-" in upc_orig else ""
        upc_last4 = upc_raw[-4:] if len(upc_raw) >= 4 else ""
        upc_last5 = upc_raw[-5:] if len(upc_raw) >= 5 else ""
        cat_entry = (
            (plu_catalog.get(upc_last4) if upc_last4 else None)
            or (plu_catalog.get(upc_last4.lstrip("0")) if upc_last4 else None)
            or (plu_catalog.get(upc_last5) if upc_last5 else None)
            or (plu_catalog.get(upc_last5.lstrip("0")) if upc_last5 else None)
            or (plu_catalog.get(dash_segment) if dash_segment else None)
            or (plu_catalog.get(dash_segment.lstrip("0")) if dash_segment else None)
            or (plu_catalog.get(upc_raw) if upc_raw else None)
            or {}
        )
        # Fall back to name matching only if UPC/PLU found nothing
        if not cat_entry:
            cat_entry = _lookup_item(item_name)
        # Use inventory price if already set on the line item — QB catalog is fallback only
        inv_price = float(li.get("unit_price") or 0.0)
        unit_price = inv_price if inv_price > 0 else cat_entry.get("price", 0.0)
        item_id    = cat_entry.get("id", "")
        amount     = round(qty * unit_price, 2)
        item_ref   = {"name": item_name}
        if item_id:
            item_ref["value"] = item_id   # QB matches by ID when value is present
        line_item = {
            "Id": str(i + 1),
            "LineNum": i + 1,
            "DetailType": "SalesItemLineDetail",
            "Amount": amount,
            "SalesItemLineDetail": {
                "ItemRef": item_ref,
                "Qty": qty,
                "UnitPrice": unit_price
            }
        }
        line_items.append(line_item)

    payload = {
        "Line": line_items,
        "CustomerRef": {"value": cust_id, "name": _qb_customer_name},
        "DueDate": inv.get("due_date", ""),
        "TxnDate": inv.get("created_date", ""),
        "PrivateNote": f"Everblack Order | Delivery: {inv.get('delivery_date','')} | Invoice #{inv.get('id','')}"
    }
    status, data = _http("POST", f"{base_url}/v3/company/{realm_id}/invoice?minorversion=65",
                         headers=_auth_headers(), body=payload)
    if status == 401:
        _do_refresh()
        status, data = _http("POST", f"{base_url}/v3/company/{realm_id}/invoice?minorversion=65",
                             headers=_auth_headers(), body=payload)
    if status == 200 and isinstance(data, dict):
        qb_inv = data.get("Invoice", {})
        qb_id = qb_inv.get("Id", "")
        qb_doc_number = qb_inv.get("DocNumber", "")
        qb_total = float(qb_inv.get("TotalAmt", 0) or 0)
        # Extract per-line prices back from QB response — skip SubTotal/Discount lines
        qb_lines = []
        for line in qb_inv.get("Line", []):
            if line.get("DetailType") != "SalesItemLineDetail":
                continue
            detail = line.get("SalesItemLineDetail", {})
            qb_lines.append({
                "qty": float(detail.get("Qty", 0) or 0),
                "unit_price": float(detail.get("UnitPrice", 0) or 0),
                "total": float(line.get("Amount", 0) or 0),
            })
        return True, (qb_id, qb_doc_number, qb_total, qb_lines)
    err = data if isinstance(data, str) else _json.dumps(data)[:300]
    return False, (None, err)


def _send_invoice_email(to_email, inv, vendor_name):
    store_label = f"{inv['store_name']} #{inv['store_number']}" if inv.get('store_number') else inv['store_name']
    rows = "".join([
        f"""<tr>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee">{li.get('item','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee;text-align:right">{li.get('qty','')}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee;text-align:right">${float(li.get('unit_price',0)):.2f}</td>
          <td style="padding:.45rem .75rem;border-bottom:1px solid #eee;text-align:right">${float(li.get('total',0)):.2f}</td>
        </tr>""" for li in inv.get('line_items',[])
    ])
    subject = f"Invoice #{inv['id']} \u2014 {store_label} \u2014 {vendor_name}"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:650px;margin:0 auto">
      <div style="background:#2d6a4f;padding:1rem 1.5rem;border-radius:8px 8px 0 0">
        <h2 style="color:#fff;margin:0">Invoice #{inv['id']}</h2>
        <p style="color:#52c97a;margin:.25rem 0 0">{vendor_name} &mdash; {store_label}</p>
      </div>
      <div style="background:#fff;padding:1.5rem;border:1px solid #e0e0e0;border-radius:0 0 8px 8px">
        <p style="color:#555;margin-bottom:.5rem">Due Date: <strong>{inv.get('due_date','')}</strong> &nbsp; Delivery Date: {inv.get('delivery_date','')}</p>
        <table style="width:100%;border-collapse:collapse;margin-top:1rem">
          <tr style="background:#e9f5ee">
            <th style="padding:.5rem .75rem;text-align:left">Item</th>
            <th style="padding:.5rem .75rem;text-align:right">Qty</th>
            <th style="padding:.5rem .75rem;text-align:right">Unit Price</th>
            <th style="padding:.5rem .75rem;text-align:right">Total</th>
          </tr>
          {rows}
          <tr style="background:#f5f5f5;font-weight:bold">
            <td colspan="3" style="padding:.5rem .75rem;text-align:right">Total Due</td>
            <td style="padding:.5rem .75rem;text-align:right">${float(inv.get('total',0)):.2f}</td>
          </tr>
        </table>
        {f'<p style="margin-top:1rem;color:#555">Notes: {inv["notes"]}</p>' if inv.get('notes') else ''}
        <p style="margin-top:1.5rem;color:#888;font-size:.85rem">Questions? Contact your produce rep.</p>
      </div>
    </div>
    """
    _send_email(to_email, subject, html)

# ---------------------------------------------------------------------------
# User storage helpers
# ---------------------------------------------------------------------------

def _load_users():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE) as f:
        return json.load(f)

def _save_users(users):
    with _get_file_lock(USERS_FILE):
        _atomic_write(USERS_FILE, users)

def _get_user(username):
    return next((u for u in _load_users() if u["username"] == username), None)

def _ensure_admin():
    users = _load_users()
    changed = False
    admin = next((u for u in users if u.get("role") == "admin"), None)
    if not admin:
        # Generate a random password — printed once to stdout, must be changed on first login
        import secrets as _sec
        _pw = _sec.token_urlsafe(16)
        print(f"[BOOTSTRAP] No admin user found. Created admin account with password: {_pw}"
              f" — change this immediately.", flush=True)
        users.append({
            "id": 1,
            "username": "admin",
            "password": generate_password_hash(_pw),
            "role": "admin",
            "store_name": "Admin"
        })
        changed = True
    elif not admin.get("password"):
        import secrets as _sec
        _pw = _sec.token_urlsafe(16)
        print(f"[BOOTSTRAP] Admin account had no password. Reset to: {_pw}"
              f" — change this immediately.", flush=True)
        admin["password"] = generate_password_hash(_pw)
        changed = True
    if changed:
        _save_users(users)

_ensure_admin()

# Log QB environment at startup so it's always visible in docker logs
_qb_env = "SANDBOX" if os.environ.get("QB_SANDBOX", "0") == "1" else "PRODUCTION"
app.logger.warning(f"[STARTUP] QuickBooks environment: {_qb_env}")
if _qb_env == "PRODUCTION":
    app.logger.warning("[STARTUP] QB is pointed at PRODUCTION — real invoices will be created on sync.")

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-API-Key") == API_KEY:
            return f(*args, **kwargs)
        if "username" not in session:
            session.clear()
            return redirect(url_for("login", next=request.url))
        # Validate session user still exists and session version matches
        users = _load_users()
        user = next((u for u in users if u["username"] == session["username"]), None)
        if not user:
            session.clear()
            return redirect(url_for("login"))
        # Invalidate session if password or role changed since login
        stored_ver = user.get("session_version", 0)
        if session.get("session_version", 0) != stored_ver:
            session.clear()
            return redirect(url_for("login", msg="Your session has expired. Please log in again.", cls="err"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-API-Key") == API_KEY:
            return f(*args, **kwargs)
        if "username" not in session:
            session.clear()
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return redirect(url_for("orders", msg="Admin access required.", cls="err"))
        return f(*args, **kwargs)
    return decorated

def vendor_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            session.clear()
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "vendor"):
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# Internal vendor IDs that are always treated as Pro/exempt from plan gating.
# Controlled here — never trust user-supplied vendor_id to grant this status.
_INTERNAL_VENDOR_IDS = frozenset(os.environ.get("INTERNAL_VENDOR_IDS", "gmf").split(","))

def _is_internal_vendor(vid):
    """Return True if vid is a known internal/house account exempt from plan gating."""
    return vid in _INTERNAL_VENDOR_IDS

def _check_invoice_plan():
    """Return a redirect response if the current vendor is not on a plan that includes invoicing,
    or None if access is allowed. Admin always passes. Internal (house) vendors always pass."""
    if session.get("role") == "admin":
        return None
    vid = session.get("vendor_id") or (session.get("vendor_ids") or ["gmf"])[0]
    if _is_internal_vendor(vid):
        return None
    vendor = _get_vendor(vid)
    plan = (vendor or {}).get("plan", "starter")
    if plan not in ("standard", "pro", "seasonal"):
        return redirect(url_for("orders", msg="Invoicing is available on Standard, Pro, and Seasonal plans.", cls="err"))
    return None

# ---------------------------------------------------------------------------
# Invoice storage helpers
# ---------------------------------------------------------------------------

def _load_invoices():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(INVOICES_FILE):
        return []
    with open(INVOICES_FILE) as f:
        return json.load(f)

def _save_invoices(invoices):
    with _get_file_lock(INVOICES_FILE):
        _atomic_write(INVOICES_FILE, invoices)

def _next_invoice_id():
    invoices = _load_invoices()
    return max((inv["id"] for inv in invoices), default=1000) + 1

def _auto_create_invoice(vendor_id, store_name, delivery_date, orders):
    """Auto-create invoice from a list of orders. Skips if invoice already exists for this group."""
    from datetime import date as _date, timedelta
    all_inv = _load_invoices()
    # Deduplicate — skip if invoice already exists for this vendor/store/date
    for inv in all_inv:
        if (inv.get("vendor_id") == vendor_id
                and inv.get("store_name") == store_name
                and inv.get("delivery_date") == delivery_date):
            return inv  # already exists
    users = _load_users()
    store_user = next((u for u in users if u.get("store_name") == store_name), {})
    try:
        due = str(_date.fromisoformat(delivery_date) + timedelta(days=30))
    except Exception:
        due = ""
    line_items = [{"item": o.get("item", ""), "qty": _disp_qty(o.get("qty", 1), o.get("case_size", "")),
                   "unit_price": 0.0, "total": 0.0, "upc": o.get("upc", ""),
                   "qb_item_name": o.get("qb_item_name", "")} for o in orders]
    inv = {
        "id": _next_invoice_id(),
        "vendor_id": vendor_id,
        "store_name": store_name,
        "store_number": store_user.get("store_number", ""),
        "delivery_date": delivery_date,
        "due_date": due,
        "created_date": str(_date.today()),
        "line_items": line_items,
        "total": 0.0,
        "status": "unpaid",
        "notes": "",
        "paid_date": ""
    }
    all_inv.append(inv)
    _save_invoices(all_inv)
    return inv

# ---------------------------------------------------------------------------
# Base HTML
# ---------------------------------------------------------------------------

_BASE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Everblack™</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:system-ui,sans-serif;
  background:#000005;
  color:#e2e8f0;
  min-height:100vh;
}
#canvas-bg{position:fixed;inset:0;z-index:0;pointer-events:none}
.bg-noise{
  position:fixed;inset:0;z-index:5;pointer-events:none;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 512 512' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.80' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
  background-size:180px 180px;mix-blend-mode:soft-light;opacity:0.10;
}
nav{
  position:relative;z-index:10;
  background:
    radial-gradient(ellipse 90% 160% at 8% 50%, rgba(139,15,15,0.92) 0%, transparent 55%),
    radial-gradient(ellipse 70% 130% at 93% 30%, rgba(90,5,5,0.88) 0%, transparent 50%),
    radial-gradient(ellipse 130% 80% at 50% 105%, rgba(30,0,5,1) 0%, transparent 65%),
    #0a0005;
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  padding:.75rem 1.5rem;
  display:flex;gap:1.5rem;align-items:center;
  border-bottom:1px solid rgba(180,20,20,0.4);
  box-shadow:0 1px 24px rgba(0,0,0,0.6),0 2px 12px rgba(100,0,0,0.3);
}
nav a{color:#ffb3b3;text-decoration:none;font-weight:700;font-size:.9rem;letter-spacing:.3px;transition:color .15s,text-shadow .15s;text-shadow:0 0 8px rgba(220,80,80,0.7),0 0 18px rgba(180,40,40,0.4)}
nav a:hover{color:#fff;text-shadow:0 0 10px rgba(255,160,160,0.9),0 0 24px rgba(220,80,80,0.6)}
nav .brand{font-size:1.05rem;font-weight:700;margin-right:auto;color:#fff;-webkit-text-stroke:0.5px #cc3333;text-shadow:0 0 8px rgba(200,50,50,1),0 0 20px rgba(160,30,30,0.8);letter-spacing:.5px}
nav .user-info{color:#ffc5c5;font-size:.8rem}
.theme-toggle{background:none;border:none;cursor:pointer;padding:.2rem .4rem;border-radius:6px;font-size:1.15rem;line-height:1;color:#ffc5c5;transition:opacity .15s,background .15s}
.theme-toggle:hover{opacity:.8;background:rgba(255,255,255,0.12)}
.container{max-width:980px;margin:2rem auto;padding:0 1.25rem;position:relative;z-index:1}
h1{margin-bottom:1.25rem;font-size:1.5rem;color:#c4b5fd;font-weight:700;text-shadow:0 0 10px rgba(168,85,247,0.6),0 0 24px rgba(139,92,246,0.3)}
h2{margin-bottom:1rem;font-size:1.1rem;color:#c4b5fd;font-weight:600;text-shadow:0 0 8px rgba(168,85,247,0.5),0 0 18px rgba(139,92,246,0.25)}
.card{
  background:rgba(10,10,20,0.75);
  border:1px solid rgba(139,92,246,0.25);
  border-radius:12px;
  box-shadow:0 4px 24px rgba(0,0,0,0.35);
  padding:1.25rem;
  margin-bottom:1.5rem;
  backdrop-filter:blur(8px);
  -webkit-backdrop-filter:blur(8px);
}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{background:rgba(124,58,237,0.2);text-align:left;padding:.55rem .75rem;color:#a78bfa;font-size:.8rem;letter-spacing:.5px;text-transform:uppercase;border-bottom:1px solid rgba(139,92,246,0.25)}
td{padding:.5rem .75rem;border-bottom:1px solid rgba(124,58,237,0.1);color:#ccc}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(124,58,237,0.06)}
.empty{color:#a78bfa;font-style:italic}
label{display:block;font-size:.75rem;font-weight:600;color:#a0aec0;margin-bottom:3px;letter-spacing:.8px;text-transform:uppercase}
input[type=text],input[type=number],input[type=password],input[type=email],input[type=date],select{
  padding:.45rem .7rem;
  border:1px solid rgba(139,92,246,0.25);
  border-radius:7px;
  font-size:.9rem;
  width:100%;
  background:rgba(255,255,255,0.06);
  color:#e2e8f0;
  transition:border-color .2s,box-shadow .2s;
}
input[type=search],input[type=text][placeholder*="Search"],input[type=text][placeholder*="search"],input[type=text][id*="search"]{
  border-color:rgba(139,92,246,0.6);
  background:rgba(88,28,135,0.12);
  box-shadow:0 0 0 2px rgba(124,58,237,0.2),0 0 12px rgba(139,92,246,0.25),0 0 24px rgba(124,58,237,0.1);
}
input[type=search]:focus,input[type=text][placeholder*="Search"]:focus,input[type=text][placeholder*="search"]:focus,input[type=text][id*="search"]:focus{
  border-color:#a855f7;
  outline:none;
  box-shadow:0 0 0 3px rgba(124,58,237,0.3),0 0 16px rgba(168,85,247,0.45),0 0 32px rgba(124,58,237,0.2);
  background:rgba(88,28,135,0.18);
}
input:focus,select:focus{border-color:#7c3aed;outline:none;box-shadow:0 0 0 3px rgba(124,58,237,0.2)}
.field{display:flex;flex-direction:column;min-width:140px}
.form-row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:flex-end;margin-bottom:.75rem}
.btn{padding:.45rem 1rem;border:none;border-radius:7px;cursor:pointer;font-size:.9rem;font-weight:600;transition:opacity .15s,box-shadow .15s;letter-spacing:.3px}
.btn-green{background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff;box-shadow:0 2px 8px rgba(124,58,237,0.4)}
.btn-green:hover{opacity:.85;box-shadow:0 4px 16px rgba(124,58,237,0.5)}
.btn-red{background:linear-gradient(135deg,#922b21,#7b241c);color:#ffd5d5}
.btn-red:hover{opacity:.85}
.btn-blue{background:linear-gradient(135deg,#1a5276,#154360);color:#d6eaf8}
.btn-blue:hover{opacity:.85}
.btn-steel{background:linear-gradient(to bottom,#4a4e52,#b0b5ba 40%,#b0b5ba 60%,#4a4e52);color:#111;border:1px solid #777;box-shadow:0 2px 8px rgba(0,0,0,0.35),inset 0 1px 1px rgba(255,255,255,0.12);text-shadow:0 1px 1px rgba(255,255,255,0.15)}
.btn-steel:hover{opacity:.88;box-shadow:0 4px 16px rgba(0,0,0,0.45),inset 0 1px 1px rgba(255,255,255,0.12)}
.flash{padding:.65rem 1rem;border-radius:8px;margin-bottom:1rem;font-size:.9rem;border:1px solid transparent}
.flash.ok{background:rgba(88,28,135,0.3);color:#c4b5fd;border-color:rgba(139,92,246,0.35)}
.flash.err{background:rgba(123,36,28,0.5);color:#f5b7b1;border-color:rgba(146,43,33,0.3)}
.pill{display:inline-block;background:rgba(124,58,237,0.2);color:#a78bfa;border:1px solid rgba(139,92,246,0.3);border-radius:999px;padding:.2rem .65rem;font-size:.78rem;margin:2px}
.timeout-bar{position:fixed;bottom:0;left:0;height:3px;background:linear-gradient(90deg,#7c3aed,#a855f7);transition:width 1s linear;width:100%;z-index:9999}
.login-wrap{max-width:360px;margin:5rem auto}
.cat-header{
  background:
    radial-gradient(ellipse 90% 160% at 8% 50%, rgba(139,15,15,0.92) 0%, transparent 55%),
    radial-gradient(ellipse 70% 130% at 93% 30%, rgba(90,5,5,0.88) 0%, transparent 50%),
    radial-gradient(ellipse 130% 80% at 50% 105%, rgba(30,0,5,1) 0%, transparent 65%),
    #0a0005;
  border:1px solid rgba(180,20,20,0.5);
  color:#ffb3b3;
  padding:.65rem 1rem;
  border-radius:8px;
  margin-bottom:.75rem;
  font-weight:700;
  font-size:1rem;
  box-shadow:0 2px 8px rgba(0,0,0,0.45), 0 1px 12px rgba(100,0,0,0.3);
  text-shadow:0 0 8px rgba(200,50,50,0.8), 0 0 18px rgba(160,30,30,0.5);
  letter-spacing:.3px;
}
.qty-input{width:80px;text-align:center;font-size:1rem;padding:.35rem .5rem;border:1px solid rgba(139,92,246,0.35);border-radius:6px;background:rgba(255,255,255,0.05);color:#e2e8f0}
.qty-input:focus{border-color:#7c3aed;outline:none;box-shadow:0 0 0 3px rgba(124,58,237,0.2)}
.cart-badge{background:#c0392b;color:#fff;border-radius:999px;padding:.1rem .5rem;font-size:.78rem;margin-left:.4rem}
/* === LIGHT MODE === */
[data-theme='light'] body{background:#f0ecf8;color:#1a1a2e}
[data-theme='light'] body::before{background-image:linear-gradient(rgba(124,58,237,0.07) 1px,transparent 1px),linear-gradient(90deg,rgba(124,58,237,0.07) 1px,transparent 1px)}
[data-theme='light'] .card{background:rgba(255,255,255,0.96);border-color:rgba(139,92,246,0.2);box-shadow:0 4px 24px rgba(124,58,237,0.08)}
[data-theme='light'] th{background:rgba(124,58,237,0.09);color:#5b21b6}
[data-theme='light'] table td{background:#fff;color:#1a1a2e;border-bottom-color:rgba(124,58,237,0.1)}
[data-theme='light'] tr:nth-child(even) td{background:rgba(124,58,237,0.04)}
[data-theme='light'] tr:hover td{background:rgba(124,58,237,0.08)}
[data-theme='light'] .total-row td{background:rgba(124,58,237,0.1) !important;color:#1a1a2e !important;}
[data-theme='light'] table.picklist-table th{background:rgba(124,58,237,0.09);color:#5b21b6}
[data-theme='light'] table.picklist-table td{background:#fff;color:#1a1a2e}
[data-theme='light'] table.picklist-table tr:nth-child(even) td{background:rgba(124,58,237,0.04)}
[data-theme='light'] table.picklist-table tr:hover td{background:rgba(124,58,237,0.08)}
[data-theme='light'] .cat-row td{background:rgba(124,58,237,0.1) !important;color:#5b21b6 !important}
[data-theme='light'] h1{color:#5b21b6;text-shadow:none}
[data-theme='light'] h2{color:#6d28d9;text-shadow:none}
[data-theme='light'] .empty{color:#7c3aed}
[data-theme='light'] label{color:#4b5563}
[data-theme='light'] input[type=text],[data-theme='light'] input[type=number],[data-theme='light'] input[type=password],[data-theme='light'] input[type=email],[data-theme='light'] input[type=date],[data-theme='light'] select{background:#fff;color:#1a1a2e;border-color:rgba(139,92,246,0.3)}
[data-theme='light'] input:focus,[data-theme='light'] select:focus{border-color:#7c3aed;box-shadow:0 0 0 3px rgba(124,58,237,0.15)}
[data-theme='light'] .flash.ok{background:rgba(237,233,254,0.95);color:#5b21b6;border-color:rgba(139,92,246,0.35)}
[data-theme='light'] .flash.err{background:rgba(254,226,226,0.95);color:#991b1b;border-color:rgba(220,38,38,0.3)}
[data-theme='light'] .pill{background:rgba(237,233,254,0.7);color:#6d28d9;border-color:rgba(139,92,246,0.3)}
[data-theme='light'] .qty-input{background:#fff;color:#1a1a2e;border-color:rgba(139,92,246,0.35)}
[data-theme='light'] .login-wrap .card{background:rgba(255,255,255,0.97)}

/* ===== MOBILE RESPONSIVE (<=640px) ===== */
@media (max-width: 640px) {
  /* Nav: collapse links into a wrapping row, smaller font */
  nav{
    flex-wrap:wrap;
    gap:.6rem;
    padding:.6rem 1rem;
  }
  nav .brand{
    width:100%;
    font-size:.95rem;
  }
  nav .user-info{
    width:100%;
    font-size:.72rem;
    margin-top:-.2rem;
  }
  nav a{
    font-size:.8rem;
    letter-spacing:0;
  }
  /* Container: tighter padding */
  .container{
    padding:0 .75rem;
    margin:1rem auto;
  }
  /* Cards: reduce padding */
  .card{
    padding:.9rem;
    border-radius:8px;
    margin-bottom:1rem;
  }
  /* Tables: allow horizontal scroll */
  .card{overflow-x:auto;}
  table{
    font-size:.82rem;
    min-width:0;
  }
  th,td{
    padding:.4rem .5rem;
  }
  /* Qty inputs: bigger touch targets */
  .qty-input{
    width:64px;
    font-size:1rem;
    padding:.45rem .4rem;
    min-height:44px;
  }
  /* Catalog item row: stack name above qty */
  .accordion-body tr td:first-child{
    display:block;
    padding-bottom:.25rem;
  }
  .accordion-body tr td:last-child{
    display:block;
    padding-top:.1rem;
  }
  .accordion-body tr{
    display:block;
    border-bottom:1px solid #2a2a2a;
    padding:.4rem 0;
  }
  /* Buttons: full-width in key actions */
  .form-row .btn,
  .form-row button[type=submit]{
    min-height:44px;
  }
  /* Form rows: stack on mobile */
  .form-row{
    flex-direction:column;
    align-items:stretch;
  }
  .field{
    min-width:0;
    width:100%;
  }
  /* Accordion headers: bigger tap target */
  .cat-header{
    padding:.75rem 1rem;
    font-size:.95rem;
    min-height:48px;
  }
  /* Flash messages */
  .flash{
    font-size:.85rem;
  }
  /* H1/H2 sizing */
  h1{font-size:1.2rem;}
  h2{font-size:1rem;}
  /* Login wrap */
  .login-wrap{
    margin:2rem auto;
    padding:0 .5rem;
  }
  /* Hide less critical table columns on narrow screens */
  .hide-mobile{display:none !important;}
  /* Inline action buttons in tables: stack vertically */
  td > form,
  td > a.btn{
    display:block;
    margin-bottom:.3rem;
  }
  td > form:last-child,
  td > a.btn:last-child{
    margin-bottom:0;
  }
  /* Cart/submit bar */
  #submit-bar{
    padding:.6rem 1rem;
    font-size:.9rem;
  }
  /* Picklist controls */
  .picklist-controls{
    flex-direction:column;
    align-items:stretch;
  }
}
</style>
<script>
(function(){
  var TIMEOUT = {{ _inactivity_timeout|default(60) }};
  var remaining = TIMEOUT;
  var bar = null;
  var timer = null;
  var hidden_at = null;
  function reset(){
    remaining = TIMEOUT;
    if(bar) bar.style.width = '100%';
  }
  function tick(){
    remaining--;
    if(bar) bar.style.width = (remaining/TIMEOUT*100)+'%';
    if(remaining <= 0){
      clearInterval(timer);
      window.location.href = '/logout?msg=Session+expired+due+to+inactivity.&cls=err';
    }
  }
  document.addEventListener('DOMContentLoaded', function(){
    bar = document.getElementById('timeout-bar');
    if(!bar) return;
    ['mousemove','keydown','keyup','click','scroll','touchstart','input','change'].forEach(function(e){
      document.addEventListener(e, reset);
    });
    timer = setInterval(tick, 1000);
  });
  document.addEventListener('visibilitychange', function(){
    if(document.hidden){
      hidden_at = Date.now();
    } else {
      if(hidden_at){
        var elapsed = Math.floor((Date.now() - hidden_at) / 1000);
        remaining = Math.max(0, remaining - elapsed);
        hidden_at = null;
        if(remaining <= 0){
          window.location.href = '/logout?msg=Session+expired+due+to+inactivity.&cls=err';
          return;
        }
      }
      reset();
      if(!timer) timer = setInterval(tick, 1000);
    }
  });

})();
</script>
<script>
(function(){var t=localStorage.getItem('eb-theme');if(t==='light')document.documentElement.setAttribute('data-theme','light');})();
function toggleTheme(){
  var h=document.documentElement;
  var isLight=h.getAttribute('data-theme')==='light';
  if(isLight){h.removeAttribute('data-theme');localStorage.setItem('eb-theme','dark');}
  else{h.setAttribute('data-theme','light');localStorage.setItem('eb-theme','light');}
  var btn=document.getElementById('theme-btn');
  if(btn)btn.textContent=isLight?'🌙':'☀️';
}
document.addEventListener('DOMContentLoaded',function(){
  var btn=document.getElementById('theme-btn');
  if(btn)btn.textContent=document.documentElement.getAttribute('data-theme')==='light'?'☀️':'🌙';
});
</script>
<script>
// CSRF token for AJAX fetch calls
window._csrfToken = "{{ csrf_token|default('') }}";
// Patch window.fetch to automatically append csrf_token to all POST FormData bodies
(function(){
  var _origFetch = window.fetch;
  window.fetch = function(url, opts) {
    if (opts && opts.method === 'POST' && opts.body instanceof FormData) {
      if (!opts.body.has('csrf_token')) {
        opts.body.append('csrf_token', window._csrfToken);
      }
    }
    return _origFetch.apply(this, arguments);
  };
})();
</script>
</head>
<body>
<canvas id="canvas-bg"></canvas>
<div class="bg-noise"></div>

{% if session.username %}
<nav>
  <span class="brand" style="display:flex;align-items:center;gap:.4rem">{% if session.role == 'store' %}<img src="data:image/png;base64,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" style="width:22px;height:22px;border-radius:5px;box-shadow:0 0 0 1.5px #a855f7">Everblack{% else %}{{ session.vendor_name or 'Orders' }}{% endif %}</span>
  {% if session.role == 'admin' %}<a href="{{ url_for('inventory') }}">Inventory</a><a href="{{ url_for('vendors') }}">Vendors</a>{% elif session.role == 'vendor' %}<a href="{{ url_for('inventory') }}">Inventory</a>{% endif %}
  {% if session.role == 'store' %}<a href="{{ url_for('catalog') }}">Place Order</a>{% endif %}
  {% if session.role in ('admin', 'store', 'vendor', 'driver') %}<a href="{{ url_for('orders') }}">Orders</a>{% endif %}
  {% if session.role in ('admin', 'vendor') %}<a href="{{ url_for('invoices') }}">Invoices</a>{% endif %}
  {% if session.role in ('admin', 'vendor') %}<a href="{{ url_for('picklist') }}">Pick List</a>{% endif %}
  {% if session.role == 'vendor' %}<a href="{{ url_for('vendor_users') }}">Users</a><a href="{{ url_for('vendor_settings') }}">Settings</a>{% if vendor_plan in ('pro','admin') %}<a href="{{ url_for('vendor_map') }}">Map</a>{% endif %}{% endif %}
  {% if session.role in ('admin', 'vendor', 'driver') %}<a href="{{ url_for('calendar_view') }}">Calendar</a>{% endif %}
  {% if session.role == 'admin' %}
  <a href="{{ url_for('dates') }}">Dates</a>
  <a href="{{ url_for('users') }}">Users</a>
  {% endif %}
  <span class="user-info">{{ session.username }} ({{ session.role }})</span>
  <button class="theme-toggle" id="theme-btn" onclick="toggleTheme()" title="Toggle light/dark mode">🌙</button>
  <a href="{{ url_for('logout') }}" style="color:#ffb3b3">Logout</a>
</nav>
{% endif %}
<div class="container">
{% if session.username %}<div id="timeout-bar" class="timeout-bar"></div>{% endif %}
{% if flash_msg %}<div class="flash {{ flash_cls }}">{{ flash_msg }}</div>{% endif %}
BLOCK_PLACEHOLDER
</div>

<script>
const canvas = document.getElementById('canvas-bg'); const ctx    = canvas.getContext('2d'); let W, H, cx, cy; const BH_RADIUS      = 0.0;    // invisible — no drawn radius const CAPTURE_RADIUS = 0.60;   // fraction of MIN(W,H) — enters spiral zone const EVENT_HORIZON  = 160;    // px — disappears inside this let bgStars   = [];   // static background star field let freeStars = [];   // slowly drifting ambient stars let captured  = [];   // stars currently being consumed let flashes   = [];   // brief energy flash on consumption let logoPulses = [];  // EB logo pulses at BH center const ebImg = new Image(); ebImg.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAARgAAAD6CAYAAAB6dVixAAA+UklEQVR4nO19ebAdV3nnr+/yVllPErYsWVSBK5UKDEywAYOVmpAZsHbZstmSySQkk8xMiME22AbbgIUXYQNGXphhoDKVmn8mkLBam7ViA1nsBMwSbFIVpgYv72l9fov01rv1/NF9+p7bt5fvrN393v255Hfv7bP1cr7+zu9bjrOpv9910YYb99cvFXuc0oZAW6lteA3RyqW1mTAecrvEsSQeU7wuOq5r3uAI/pWpI9Sm4+hra4mNK+q3UrhAHKgnQIKTXprUD6GdpDZF6uhqN6mMjfo9ZAud9yhvbUW1UYorJCU4LELHOGUEg6oQoJQxWT+v91MXTJxf3q+ZI/iitYmS0ARVVMM6/jqOHm0oPESZtkLnJdJPuI3EMpR2VOqHxrCcBU3ekdfrr1uT6dJgogpmpc3oXCblVVuhlFG97stR0BjRZHKsKQA5XDI5TicHQ5pYObrIOpZHuspqKcNpdaL183NXehDBUr9viRoMoGk5FPdX8zJJhcTNi7ZCKWP7WA/FQp40mUDAZL0cigNpXDFalSkehtKuLkEjW78nTMxhWRLJkvVKMhVVbe46iSTT2oqQoMiI6O2skPdH1S6W89XIw7lHLpFMCoaufhKWScJtCda1ycP0lkU9LAWIPjORJC+tJ/OPp4rgMa6tSJbJiujtCRr9KMpSKcv7my3JK4nINlIEnikeRrZMj3+xi+V63qZAvZ5djna2Sd64ZZJwG8S6xrUVQR4mT8KgNwmXNrK4v6kaTCIMLpNsL4+yLpOnYz1kj6Lcn7RxdggY08shY8sjYp28lJGtTz4mEDLQgzp61zce5GhqE9BuPdLAw4RN8NLtqNS3aGruTY7lB5tEsjrJG+MTIwxuUulYHlHK2CBq87T06S2ZerANYySviWVSrsjcpGOWiN6eMBFH0c69aOMNQ43kZVBQ6XUIHMpYsiZqKciDwCj6A91Dtgg/P0ZJXvHRyZmrtWsrAhn3dB4zgTyNpYflB6Mkrw4BVGSrUabHepakHnIAPUskQGqZlAttRVMZ2fqxxxRCBkTREz7LEzbueyrJa3OZpE1biXl7W7UIZRjV3FsW9ZAXlExPBGHBk2CuFumHUlb0mGr9PB3TUb6HHtKgRPJ2QUBYmeJWRMomTs6MiN7esqiHpQSP5JXUYrJaHtnkYbLSaETR02R6EIWNzfb0kbwRkBY8gubqvAganTBhSRJtq4ceVKFM8nZBYtdGCoQFhCGHO6vHUixJougJkx5soxJ8chzAFVeaHHiqVvivShuUsjbK8Hh0Zx0ttPw9qL3/lgQk7nme4TglOHAAx0EJJbx/H11J/6tdrc577LYMjpSDP1b290P7y3b6NQA2jxkqcQVVoSJ4RAREUllVQeM4TrChfAst1JuLqLcWUG8touU2U1rOBu4SExhUMIFfcsroKw+grzSAankgoly8Jufd4wXUWguoNRes3eOSU0JfeTByzEnjLQIqADdZ/QkVJxxUtBQGchuOA8d1tWg2qvUf3VlH022g1prHc+Pfx1z9vPDDJ6PxmNGS9LUpI8xkz4lSr4QSyk4FQ9WVuOKSayIFTBy+uquFptvAYnMePz13AnP1afI9Vrm3JZRQLlUwVBnBlWs3CY1ZFjaFlpIGEyt4BJZbpjQbRIxDRtA8srOOlttErTmPufo0phbPegIGdAEjr1WYm4yxdS2P1aspeZ78vXUclJwyBsrDqJb7hdtqoeXd48Y0phfPYqY+iVbsEklCoMRc15JTxkBlGJVSf6GX3XFCq6JTO2GQadMmDyNSv4UW6q1FzDXO45/PPYWFxgzqrUW4aD989t7k6hOR3lOxxldyyugvV1AtD+ANr3oHyqUquS1ee/n5ue9hvnEBjVYt0GCkNBTCOTmOgzIqcFDC69f8FioOfcxFQbcG47/1TSyTjGorEmXS6j+8o9Z+8Ma/h7nGedRaCwBc4Ulha8LKaiBFHp8DByWnhP7yEK645F0Yro6grzTgEacEtLWX85htTPv8S0vomsiclwMH1dIAhqorMVS5CNVye8wmljFZtKlM8sYKnIRlkgwPQxmDbJm4Y96Dt4D5xnnM1c9jsTmHlttMfZiK9vYXqSlcw8L4HMefqJWVGKqMoL88hJJTxvv2lYKHP24ifI3TXp4b/z5qzXnvHiPZgqR6XiWn5GtdQ/i3F//7YMxFtiBFoZPkBXHiJ8C01chkGf7YXl97qbXm8YtX/h6L7MELPVh5n6xeT0tR4Hl1HLCJOog3XPwO9JcH4TglvI9gnv7arhZabhOLzTnMNaYxW5/GYnO+S7jovu6Op3OhrzyI4eoIhqsjHdpLEUDVhqI1GOIyiQLdPIyweVrSv6etvVzAfOMC6q0FyPu/5H2yejWFa+RA4HVqLyvRVx4UWxq1FjBbn8ZPzh4PNNR4cjdthLTz8szSAxiursKVazehrzSIklPGjb72UoSlERVarUgidXSXFa2fdKxbexF98Io5WVNr5U7geZpAWHt5L7c0isNf72qh4dax2JzDT88ex2x9CrXmPLFf+fNygjEP4cpLNmG4ugr9AkIxa4gKq1grkhaPXB08TEoZ3fW/sKPGmaXPB8SuTpMlkMfJGqqRe4HnBA5qQ/4yI0p7iZsQzKlutj6NmfqUtwRGPL+m69o7gfbCjdkp48/3l3Otuci2Fa/BpCyTKNAiRDghZUPQMLV5rnEe/zz+FBYbPrELl9BDNPI/WfMv8ML9lVBCteRN1CsuuQb95aFAe0lDW3vxrIO1Vje/ZubaOyihm9j98yVG7PKQXiLllcxVWVY9xJZGzXn887mnMFefRj3QXoiqs1Vh4tUUrlEEgZdQz4EDxzdLX7l2k5RZut70XiJz9fOo+cSu+PmJlHdQdsqcxrXKGLGbB82FQZsVyaajHKWMjEcvI3aZP8Ricx5Nt5k4kkK8+YswRoF6jHfx/EfaZun3EMzSf8NxLz8f/54gvyYvzEtOW+N689rNAbH7QY1LozwJFsA790QNJi42iQIRHobUjmQZ6rHPc8Tu86/8XeAPwdcuxJu/CBqUwrmVnJLPYwz6ywyP2H0PYWn0N75Zutacx2x9GrP1KU5D7R6l7BjDYGEM/eUhvHntlsIRuyqQWiJZNz0THe5k8XmO2J2tT2M+UJtteex6NaVqLTHtJKgTM1GZ9jJcEfcfaaGFxeY8ZutT+MnZY23HScP8mufz0k3sflAT9+K6rnRWyq62oEFz4drQEotkk4cxcYz3h/j5+FP+g9dKzQdSBGHi9ZYP7iSxnsBEHaqO4Iq1m4Kl0bsJS6Ov+0ujWmsePzl73A8JmDfOr3naSwl9pUH85iX/IRjznxmwGqlAt2BhiNVgZASPbh5Gtr7Isc/xxO74U5itT6PWWkCUq3hvqaOvP9HzCyZqedD3H5EjdmfrU5itT2GxMWeEXwM6r4njW7s8vmilVmJXJ+eigqRxpC+RJFIedJWV5GFsaDuM2J2tT2OuPh1wL7LenL2lTkQ9DRO1bZZe1bHMePe+9ODAr0cRu+gWLrrvgeNbjvrLQ3jTJe/s0F5UkBcyl1I30opEgU2rkaq24zXSLeQ+2+Gx+3dYbHpvNZMeu8DS1k7MRUsz/5HfCSbqDQSP3W+EiN2Zmu9U57aMCnU25r7yIFb0rcJQJV/xRra0n0gNJpc+LilEr4yACszSnMduPO/SEyaR9SycHzPxDlUv6lpmpE0Untj98dmjXEQ87SUiuyx2uHijN6/dEgjF/6bAvZjiSUy2QbIi5drHRfLYg0Gulzk8/8rfcmH6Zi0KkfV6wiS2poNSYDnivV9vIJilv8EtjX589qgXb9TqjpbWMU4e7Qhvzyzt+erIm6WLwLXEocuKFAmF1JNJPIyWpY8EHvTN0l6Y/vk2seuKCZeeQNHbX/RELUV6v1Ie9rbHLkvF0JnPx9R9YBHew9VVWFFdhf5KW3vJCqa5lrg6XRpMFlajrMzSc/Xz+Nm577ZjURKSDGU92Uz3l8fzcxzH4zCqqzq8X68naC/f5LQXL9XprCC/Rh9naNRwUMJAeQi/eXHbLP1fJZZGWS+JdPSfukTKC5mr69gDnFn6Z+e+61uOOr058zjZdPZn//y82mLwkzKVBnHl2s3C3q98vNGsH1NG413kr6nDZalTiTcqsmAJ1+2wIiUiFF2dWJTSnmR9pbYdp8MszeKNREg/BtvCRKXPwghMbpylmLQGuwiWI157+dm5JwPrYPf56L2eDhz0+Uujt6zd2qG9LHXECaUODSYv2kp8g/H+NJT+9mxfDIjd5175AdmioPrmdlDyXbk9ZzHa+0Hjw0/oLvoc3cDTNT4Jtn6hx8fu8N6vuwhLo2+xNJiNOczUpzwNtTXv32NzAjoYc2UIb7l0q1S8URE1l7Q6ycGO0CxoBIle3cfCaTBrTZ0eu4jp1QlMln2lAfSVBxHecVpnlJWutlzX9x/xdzn0sr15Pci1R6vXFi5evlpR/xFmlp5rTOPHZ49ioTlLSuItOs6ucbN4Iz9GihG7/4XAvWgRLArxSCYEC0PFhrZCKWPiGI847cW0x26g6ldGcMVaLzFSfoyO8Wi5LSw253z/kWOkOkHLCkuytmv9SIf/yHWEpdG3uKXRs2eOeCEBQbyR/rEysAhvz2P3XRgoDwfCJbmNpaexhMsGGowuq1FWpucosLHs2b7YkT2eEbt03kX2jNpE5RVrN2FV/1ov81ouBEw8XLhotOqYrU/hufHvB79FllXYC7t787QSyk4ZA5L+I13xRv5LhN0/nWPthOPlp6msxFBVb7xR/HjyLVhYWTEztYA/TJ6O8dHSPz333VCYfhj6CNESF6a/oroag5WLUHYq+LMDlY6e3NDnxGOuG1s+tQ3OEzqpjW/vaqDRqqHWmsdicw6NVq19nkYJYyfQXnj/kesI3Mu3eWJ3/EksNOfQbDWEyXv6WNmI23zRmy55V6Bx/WnC0kiH5iID04IlCmQztWyZLJdFAHA/tzTizdIqpB+Q/hCytI595UG88eLfCRIjffBAzE4xSqMhtkHYwuXxsP8I4zAEJqoMD8TvzsgHBl5LWBoBnUm8+Xw+JsbaOeayn13PM0snbZuS9ZLINKLGRjZTazM9q3r0ClqS2LagLINZW3sxO2EAB33lAQxWLurar8eKMJHAdzgLjHe9pmOJcB46SHHHkU9r0K29xAtFaVN/lIbKxRu9de22Du1FN4qyJAoj0kydBNv8i0p/9wXayzyeH/9B2+clyWNX9gEM+XB0bgvqaS9/flBuc3NTAilKGPMWmKitcs34xniaQNj79VrC0ug7IbO0t7+RJxRVtBOKhsru8Vsv3ZZolrYtHFTq6hIsDInR1JEgONxlvSwCPOHSsS1oRwYzDyYc10TSOlImvQxk2vh2QmCg2URb7Ynq5XoR837lo6WfPXPYDwloCFkHZc6vncTbGzPji/6E416Ws2BhZYz6wdjSdqLa6iB2z56QWhoB4qRmXFrHG5n2IrmVbXx/eq4jHxjo5UzxSVJS6/KC2ksnOYChSqdZmqq9BGbps0cw4+/OmMQXKfkJsf25HBbh3Uns/om/NMqMxJXwhdEtWMIgRVPbNj2rjuVejtj96dnj7QcvjUtQNGN6SyP5tI5pMHUfvk12rYfSCMLXN4jdkfR+bfNrUyF+TcOSLpHnczo2rmf8WlYkbh40lriysWbqKOTpWFL5DmK3MR394BnwiXDgRKZ1vDGFezG1VKL21bURmaJrPUC7vo5PhIfTGlC0l8c7hOJ3sdCYRcttoCWooXIDppVzos3S/zlHaTCz6Ceu3dSk30aOqS4TErLb3bN9MdgW9Lnx7yt77IqkSGRqM5/W8UMh4aIsOGKunayQ+lZIexF1rQfkhDUfb/Smi98ptDR6vMPaNYWZ+qQvFInjkH32nHaO3RW+UEwyS5OGgmx4Gl3tp5WR2zpWkegVLS/SVsfbuHGeZGZlUMq85jDupTuto27o0m6+GWGBid+IzIMuzS/gqiS8X3li90dnDrdfIlH3WaenMZd4/C2XbkO/HxLwx5ZzveRhSUQtk+oHkzfTc1L5T3PaC78taNSk0B3QGLWp+YclzdKdLZvjvzotMEesudaHvV9Z7E6a9uIC2M9pXD86e7g73siQpzEb80BlGFet244V1dXWd2cskmBhZch+MHm1FjF82jdLM9KPbUGi5g9BqSe3qblN3iUK34wwS8tm25d1rZc1S9ea85ipT2KmNulzL+bz+XjBjMz1oM0X/bEg91JUEle2TORdTWpI9pjptjq2BT13XIJ7cSP+pSNuU3Nee7FpsozqK+q36MDA9NgdN+I/Kly4fhpM73rxSZmStBfWw362pPOJXZF8PkpjRnvTN9714I8EhIvMi0OqjsDLQdfLLKkdOQ5GAibfzrv9pVGwLWhqmL4e6wjvD5HFpuZS19Rx8I3rmjGu9Z2t6faELXHZ9tO8X6PQGfbhO06GeBcj3ruOg75S23FShNgtqsaiMhYeiflgbJuXZctHbQuqugUJkP42aJtZO9M63qTIvZhePvGBgXNcvJHOOJ0o8Nn2hwXN0vtDZunFpuexKxMtLTRmfwncXxkS0l6WqtmZWoYdI+WDiTwmkKM3si2iqTqt/bsDYrdzW1DjHrtOO/qXT+t4M0W4cOdu24nx6772stCcDZYZNlzreTM+7z9CES4HIszSi8Roadnx8uOulgbI2stSNzunlQkf0+ZoZ7287wvT5STWTDazAnqsIyzzGouWDhOVWZO4UX19/bpmaKJ6S0nTrvUAgtQVYe9XChi/NlOfxA9PP5FK7OocM7Mc8drLB/aVhF3yE7tE9ksi3YKFQRsHk4Xw+VSM9mLDzBq1qTlJezEA6rWMM0uzc9U1MbsHGO39StVevHs8ix+decJzquOEoqkxO1wazGGCU11RuRZdZeLqaffktVX+U9sWtG1qLmNmtbGpuU4t6G84YvdHZw93TFThSSpyfRW9X9tmabY0mo13qtM1Znj3ub88iBV9q3HVpTsCp7oPhIRiLgWLQgJw0T7Tymh3tDNdnkF2U3PlLUhiNjW/xQCxqxNRgYFNlxAtrRoA6uckHq6uwlsv3R5MVDHtxQtaXWx4QZipwkVxzLz2ctWlO7w4qZBQNB25LFPHpnWIulxSWiLZEibhNj6xbYG0qbnunQhlNjXPmosBgL/mtJefnjsRsrJx0Lyk5KOlr1q3Xc0s3eD3NzI3ZoDTXqqrfWuXJxT/cF87I6FpZClYZLiWuGNaPHlNlY9rI25Tc9NbkMRtav4RX3uxJjgEgkX/OkTsMmHcclvSk5MiuD2bUclfGq32XOsFzNKR2otkEm/hcTtl9JeHceXaTRjwhcsfEHMDR/ebvRZiW7AwiGe06yioaKqWAK+9/Ozck4KbmqtM/+hNzT+SI2I36jd+KcksMCITVVYLZFajFZJLoyAIszbpcy9zQmORTzzO80Wr0VcexAf2ySn6ps3OusZgYpysTeErp1WYSPjChM3S8ZuaK6jOEWNiCZ4HqysT02CqQueS6mvB0sizwATaSwyHocsL1vPYLfkeu+KBgZ5QnPPM0mcOpe5soGvcbaG4Glet2xm8RMTbzJ5roXBEJrSa8G/Snrw6you2EdZe2pnXFNRmkX2HQ7lLPloQYncm8Hnxrpe3P5IZEz4AMNf6FdVVWNEntjQCEMQb/fDMIczUPKc6JhRNjZsPY7hq3Y7A2vWH+ypGidO8mp1ll0RhCO3syMO0MAnjLt8s3ZE9Por0S4BKYiTPSYwW/ZsHYverYWJX0rVeOOoY0a71VOGyb1cDC42ZdrS0xL5MMuOG0zZLe3zRMD6wv4/YV/aCRRd08jAuiEsk28IkCvyWGp1OYhF73ygm1Q4nRqqWBrCiuqoj+vfWQ33+cbuCgwreAjNXn0712AUUrW5cQmwR1/qucbtNLDRm8ZOzxwOfF7OuB52E9JvXbg6I3TTkKcl2ViRu2jJJKFSACt1t3MktjZ49cwRzjWlpp7owqImRZJJSZ4Vu7UVjMmwgljeLc60X1V7a1sFuoagqTOLcD/rKgxiqjGCo4gnFPxBYGlF7zaNgkQW1zYpqflwbAikcLS2TZEjKquBvqbEiFP3LtBfboCy9/oozS8/UJn0OY07OYxcQejZYtv2hysqu3SwpCGsvTZUk3gBoT2Y7U91bLt1C0l4KY3ZWJHpFBVNUeaFXsQ4pKNrGnYx7IWwLyqCaYIhPMtRf6Yyfuc2AcIm6JrLXmg8M/NGZJ/yJSnStd93uf1Q4TuD9yvuPiGgvNX8JPFufwkJzTvDF50b8Sx104AjI+DWmvcT1IDIaE6C0q1pG9FjSb1KxSJ0F4zUgVe3mjihil0viraouJ3ly8oFuaZuaxyFR49C8ARsA/J+QWTpIaxAljDV6wAZLo/Jwh/+IjPby47PHgpdIvFDU44JQ8tNgrqiuxtvXXRvkBo7qzSTJWgTrkOw1SI1FioItK4mObUEZRIQRe/DCm5rfnkDsst++uLPuTQw/lYRuIZKEWmsBi805nK+9ggu1CXJ8VhKo3q/sevH+I1Tt5fHrah2Wo06hqEeYdI052D98GG9bd20gFP8Tx73kwTqkS7hlQfACBCuSKStJmpD6OE/sErcFBfRYFFhiJJW0jrXmvE9EN5XGIwYXC41Z/PDMIW9pJOhar+r9+rZ1OwP/kV1E79d9uxpYbMz6uV4OetpLqxFpHUwcu0S0NHOqY2bpP/DN0nkQLLr61hVZndYfyUxtU5i0D0YvFYxuCwokWkJ4nxdG7N5O4F4e21lvp0Q47S1RTAmYqHN3XU/jq7XmO5zTqPVl+uejy1lg4PVE/xGg7VT3T6cPtlNIpIxN1XLo+HzRQHm4wywtJVgEJnDetBtV7YQC7Um/dQipj3d47Ga/LejHiMRu4Dlbm8Tk4mlcqE3EChh1c6vXSsc3blnG/priqYC292t4olLR4VRXnwyWwPx56XZDKDkllOCNedj3NO4rD+L3BeON8m52tsW1pAki8lW16Z3KJupc/XwQpk/iXVTfbHD83RlXCjuJPcppLz85e8zf43lBTIMx6NNjpL7v/TpUbfuPUJdGQJvYffbM0UC4mOaLwJZGfatx9frrYond+D6Wn2ARWRKFf1OLptaAcF8f47SXn5470fZ5CY9I82Rsk35DuOKSawLt5eME7eXRnfVQ9C8hjKFowiQEWe9Xhg5i13K09EBlGG9fd11A7P5HglOdKUuSFcGSsIwzJVjYb16wowGTaRTSBNftnFk6yF3StJu7hJJ/NYw43xMXbuEFSdQdY4m3BirDAUkqS+z+0+kDqSEBuq4Bbx1kxO7vC/BF9P7yYR3KQ5taOBhdy6eo3CUiZlbduUt47SXuHB8Olkae9abD98RgbmAT9al3jLfAvE0irUHLbWKhOYt/PH3Au16NOaht8eshlS+CZ5bmY8rS28yOmFXlSmxyLXG/Gc8HQ8XtwdIoPXeJzgdRR+6S8F7JTbeRKlyKIky60SbCr1q3U0p7WWjMYKY2iQu1Ccw3ZtCCeDZC8b2lnWDblKHqCPorQ/i9hKWRkCDQbAq2bR1KOqb6W2K6BptcTFzuEhXSDyA8iDG5S+6gWI4cJxQ/45nSeeFSXEHCtRDyfg37j4iapT2P3aPtHQKsREv78UZrtyYSu0uWxJXkYWQgZUUyidtCxK5M7hJZ0i8qd8mdRLP0F3YshKJ/59CysAVrUgtKtdO2yuWIcD3EroFo6dA58InHV1RXBy+R3wtpXEtVsOhsk/obDz0CRpAkDmtGIrlLtPiPuG7HZJEhdgG53CWApnMwLEzCcByPCB+oDHtJmfrkid1/PL3fWxqpRkuT0q2yHQLW4O0RZukiCxZd40grr91MLQuZZdatW+djc5fofpt1jouLn+E21pLXXqKFYt61EtoIXLCcKcPVVYmBgXFgxO4zp/bjQm3CD/sgjk32HJz2DgFvX38dLqquQV95EL/rC8WiCxbTXAsViWZqSgOm+Jlbt87ryV0i+gByHrtxG2ulQX/uEiBrYRJ3zUtcIinef0REe5mvX/B9hCawyJzqovrTJBABj8AP80W/u7/PjD+LgZif2L6gn4ehtpUmiFKtSLaJXeHcJRomkffgdcbPlJwy7iJqL5/fPoeFxgxm61O4UJuQzF0iD11aCR3tjcikid3mLJ49e8RzPYB5HyE+hcRbLk0mduPbt2d2ppSxdUwX/9JhRbKNjwZLo5jcJYYePj5Mn0+MRBUuD+1Y8LmEKd9JbC4hd4leC45UfR0WGP968VvlUsG0l7n6NBe0at5HyFsCD3UErb6fqHGZtKrIlMkbiZv2Wy6sSOFNzWXSYDKIbl7fz/wh/PiZTx0aiCnbLSLa0b8HAnO6N+aiaSW0+m3v15FgogrHGzVn8SM/n4+1JN5cLmWq9pJXrkVnfds+O9kJmIDDOGb1wYtK6+gdSxcRn/eJ3Xb070zszgZJyForobbR9n4dEvJ+ZYiKN+I1PRPnwUd4X9S3Bhf1rUF/ZQjv0+VURyibRxJXtB8d/AuQkYC5acuFgMMI4o0sPnh8/MzdMdpLFMLRv2nCJa9aCQWBMGbxRr7/iKhZ+kJ9Av94ah8WGjNK0dLk83D4aOldVp3qstpNUfaYaf6FbEXSiZu3znIchpfBzOqDF0rrSMVnfWKXvY15oZgHQaKrDX5/I0bspk3UKLTN0vs8s3QrPZFUMAQFoVj2XyJXr9sVmKXfZ8mpTrUda4JFYZkkwr8AGgQM1YTNfgu2BT190Cf9aA+eyuTh1+RXcWkd735ikFT/cwGx247+lRWKeRMkUeCJ8Levb5ulrxc0S1+oTQS7MzZb0WZpnb5O3jYz/u6MfWvQXxnG+yTN0jaFkG5SWaZNXUui8PF20u+QN64J35ebts5yWsAUl3+13aoJL1cH3v5GfJj+pw8Pk1vriv61IBS1tSGzXa5vgeHN0jfImKXPHCHsECAAglAcqAzjrZduj9S4imR21lU/rbxJ/gWwvETindMWmjNWNtbic5dQN9bi8VlG7Nba0dItt9GxLMqFIAGUTfsAOpwQZfxHmPYy61sH21Y2AUg6Tnr5adb4QnEI7/U1rryZnVX70MG1qIxDRNhYEzAf9rUXtrHWYnNe4EFSWx6FtwX9NHFpBHRG/zK+SGbbFIa8CJKocThOyQv+LA9hRd/qwAJzg4RZ+tkzh2kezhrOpe2xuwYbL7seg5UVwkm8tVl+DO6mqFWbiRinjJaSxL8AFgUMbWMtDRMntCZnZmkZ7eVBX3uZ5VJIUMeYZ0ESBwde6oqL+tZIEbuPX1fDfOMCZmoTwb5MuhwngXihyKyDG9dfH/BF79HoVJdns7NNy5HMcSsC5kO+WTrYWKuh7pxGTS3Aon/Z7oyy2ktS7pIiCpMwOvLVrm9bYN4tES399KnH28SuYetgx/5GfWswUFmB9xCI3bwIFlloESxELUZE2Gi3IlFQay4EFpj5xgXUW4up2fZVJosLF2VUvIz3lRG8bd1OqViURquGheas/yZ2USn1mU+ARWpEvzBi+wSt7LsYK/tehf7KMN4jSOzON2bw9Mnv4ELtFczVp9F0m2AvEaX7mXC+1ZKDSqkPb750C/rKA1o3rldFHkhcFcgsicJlrQgYFy08e+YIZuqTmFo8i0ZrMXZdru5T4tUvOxX0lQdxxdprMFBegWqpH/cIaC8Mv5z8IYaqIyg7VX/PHlvQYU0T0QS8XC9XrxNfGgGA67Yw15jG+do4JhdPt2OOIkakgvDz0VcewEV9r0LJKaNa6o/VuLLgY2Tr58VyJHs8E5L3N9a8HT/8lycwPv9ye6eARNAfxKhJVHYqWL24Dr+1/gY0WjUpa5UDB1eu3dxOhak6OTQJDRPwtssdRH95SIjD4NFsNfDC+edwcuaX/pJSxjtb4L67LvrKA5hvXECjtRj5csob0Zs7rkUT2RsHKwKmWurHYOUi9JcH4botzDdm0HTriXVENJk4AQM4+Pq/Pog/+jcP4ItP/ZrosFEtD6BS6sNQdaXy0ijvcJwSWHiAjHB594FB/MU1v0SlVIXjOFhszqHRqpM3npPdE6nWmsfEwilML57DSN9a4XF77S1tEpcKnfwL++y8d3DQZT+wSe1yhfjPib8R6t51+DA++clP4sUXX8TCwgJaLfVlUlzZUqmEarWKiy++GK973evwwsGD0eNzXbnzDfVvvS43dut1E/DMM8/g9ttvxwsvvICJiQnU6/WOc02D6L2vVqtYs2YNLr/8cuzduxf/buPG4LiT8tdoGV8roLQjekxH+aixitShHqencNOAB7Ztw7p167By5UqUy2Jr/CgkPYytVgv1eh2Tk5M4efIk9h49qtxfD+m4+uqrcffdd2P16tWoVqsolUpaYrXi0Gq1MD09jdHRUdx3330kPSgvZWSPUcuTf0vdYofed/izVQEDADfddFPHw2cSvJB57LHHjPbVQxtbtmzBq1/9aoyMjGh5kSSh2WyiXq9jYmICo6OjOHr8eGxZXWKOJFgSJq1OoUP9TaW9uOOUfqwLmM9s24bLLrsMq1atihQyut92zWYT09PTOHXqVE+LsYjbbrsteJHYFDIPPfSQUluqT58JjUVFiFDLxxHkMu3zn60LGACYOngQGzZsUHrDUQURr8U8+uijUn31II5rrrkG69evx8jIiBFNNXz/2VLp1KlTOBLSYrJe7thqU5eGk1ZHRIvJRMAAwB133NGlxZhaq7daLZw/fx4nT57EQ088YaSPHrqRtRaTF8GiU9tQ4loE+6IcjyvLPpeCL6HJrUMtS8IDO3Zgw4YN2gjfJLCHb3JyEg8++KDRvnpoY9OmTXj1q1+NNWvWWBEySVpMGCYEQ1d9SR5GR3mZ9kTIXqoWo6zBqEhKRvhWKhUhNVrGjM24mJMnT+LynTvJ9XtQw9133x0sh02T+hQuJmutpuhLojRkbkXicb9P+DIhY/INx3MxY2NjeKRH+FrB1Vdfjd27d5OWSjqWyLzZ+tCRI0J18yhYrC+JNGgxmZO8PCYOHsRll11m5Q3XI3yzAW+2tqXFTE5O4r777sPfPv00gOysQzrbVDkH0/xLHDIXMABw5513xpqtw1D18m02mwHhu5cjfM3Qyz0w3Hbbbda5GOZ8lwYTwiOoL7zBnGD7Gtqg1BHVXDpI3qyxZ/t2a4Qvr8WkEb66HZuWMzZt2mTUbM0j7Hx3OIbwzZPPS1bLpDSyV/Ua5ULAAMDNN99szcOXJ3x/7dprjfSxFAXRzbfcolTfphaTRPjmkWuhlqe2YWJJJKPFdM3krCbBfVu3psYp6QiCBLoJ38eOHRMery4URUv67pNP4vnnn8eWLVuk29i0aRM2bNhgVciwF8kTx45lJ1gEzdU2TNgiZK/Ks0dSFWw98Da1mKVA+NoSTv/wzDO499578cILL+BXv/oVduzYId3W7t27rZmt+Xv8hS98IbGsSR5GR5tGLUcaylqxIqk+3PcStBid4OOUHltmZmuRh3PPnj146aWXMD4+jvHxcYyNjeHEiRNS/YqYrXWg2WxiamoKo6OjOBhhtrbNw2RtkhYSJgpajF6SVwNTzn6L02J0LY949KKt03HsxAmMjo5icnISCwsLWFxcxMTEBPbu3Svdpk2zNbvHExMTuPfee/EDAbN1llyLbug0SVM0F4bckLwM92zdmhhtrRssTmlsbAyPHD5stC+tMJhjhcfevXsxOTmJer2OVqvVofXJajFAJ+Fr4x4zs/W9996bWt4WD2NTm5E9HqfFCJO8eSIWxzVEW1PBO2Y98MADYpUtTfKscPTECZw6dQrT09NoNr3Ul7xGoKLF8GZr2zljDsWQ+kWyHGXBv8hA+NVha0ox5zvbcUq/3otTChDWXgDvmvEawVEF7kpWi5G9x0zIhAlf2ySujZe5Mv/Cf1bQYrTopiYu2L2+851ta8PY2Bi+GDFp8qTh2cCho0cxNjbWob0w8Frf/fffj2eeeUaqD2a2tkX48oLxADFOSat2opGrFBlHFlpMQPK6gDVVX7SXm2++2SoXo4PwXQqC6O+eeQZ79uwJknZHJWdnk3VsbAz333+/dF+7d++2HqfECN/v+4RvFHQuibK2HIkcjysrqsUwRN5RmxMi6SLt9glfqm+MrjilU6dO4b8bNlvnWRDt2bMHo6OjkdoLAz9Zi2S2TiN888a1qNRNm/wigoKKWJJXpKKOgVBx7tChINraZpxSXszWtq/7Yc4sHae9MPBCpihm6zDhe9AnfG0RvKaDHyl1TGoxYWi/myYe/rvuuitVi9GVbpNpMWNjY/higczWulToKGI3CXwWORWz9e23355JnFKah68MsrYcyR5X0WJIJK+pN2NiuwTB8Ont23HZZZdZ309J2GxdULCrcTjCLN1RLmZZqctsnUV6zdHRUeyPIXyLxrWYInMpWkxcnVQNxqbQSerrlltuySTa+jeWkdlaVHth0GW2thmnlET4muZadEOrSZryWWCpVIo7QB1Q0m86wNr9VEKcku7dCMJm6y+FJk2eCVpZHEgwS6dBl9k6a8LXmuWI6NVreklkAmSSlzwQjZnT06BDi7G5n1LiA5IjL+AfEMzSaeAnq4rZeuvWrZkTvjyysBzliX8R1WLCELqDOqaEShufEjRbq4ItlU6fPo3/adBsbV0jCgk3ilk6DbwWMzo6iuMp24YkISvCl7orpE5tRgY2+Rcq4klexTepbaFzOmS2NrmxOv/w5SFnjImH95CAWToNvJDRFadk+iUCdFrCDhDM1lEQLq+wTBKpY0uLiWvXSEY7U22w35jZWnSrExlhxJut/0dBzNYiD6ossRsHpvWpEr551GLyaDmSPa7rtZy2VJLOaCc8EA1tMHzKN1ubfMOxC5dmts4PkyKOfQLErgx3dd999ynFKfFma9PbC7PEVCdPngy0GAZjXIslstekFpPWVmK6BuqgZKHSxi233GItTom9lcfGxvB6QrrIIliZvqeB2I0Df70o24bEgTdb2/TipuxtndU9NrUkUhlHktAvmWbJRUFt4xOC6TVV3nxhs/VXNBG+WQqdPXv2SJul08DnjBkbG5MmfMNmaxsBryy95j4J5ztq+TyapJU1l5ilkvF8MInliZM+7uJ/5CMfMfLwRQmjLrO1IVXdxpvxwIkTGBsbw8TEBBqNhlbtBfCuny4PX95sbZOLueeee/A9Bec7G8sk2eOiAkRlqaQWTe1fnCw0HQC4a8uWjnwiNpZKLNr6KxludQKoCaKHH344WBrp1l548NaZopiteX+ee+65J7GsjZeBaf5FpN/UviKEJTkWybQQkb1ZY9ze1jr2U0pCmvOdtSWPSFqK0PcDx48H8Ua6NZcwdMcp2fDwDTvf7Rd0vouCySWRLTJXdqmk9MrPC0dDibYmt58yeXmz9ZcJWdHyRvg+/PDDgVmaqr2o8lc6tBiZxFSy4+b9eVSc73Qvk2SPm3jeqO2nxiJlobmI4hOao62TYCra2obQeZwzS5vWXhh0aTGM8LW5VGKE7+P+i6QISyKR9rVqLvxnTmBKxSLlUejEEb4m/CZ4Z7I3Goy21vlAP/n00x1maZPcSxi6oq23bt2aSbT1Pffcg6cS0muGYWtJlFbHhBYjulTSdpeyFjp3bNmivCukjDPZ2NgY/iKHhG8YOuKNZMEvOVSc7wDgYx/7WC4IX6UlUdRvKc+eKv9CqaesuYSPua5YqEDWQqSzsNtV3pTZOgq8kHnkkUe6hxdRxyb3wve17/hxjI2NCXMvUv3GTBQ+SbiK853NOKUowle7YCH+JntclxYjI3AAoidv5DFVE7WCD0wcPm7RbM3vDzQ2NoaviMQpKez5K4NHH30U09PT2j12RRBOEq5C+NrUYmQIX1mokr0mtRjZfiuyGkteNZ2XDh7EZb/928HDbPJtrbQrZAJ0az9MsAwNDQXXQzc3RW2vWq2iXq/jy1/+snRfmzZtwrZt2zA9PY3x8XEAMO7Pw+KU9h87hl2bNwPw7okTKqvym0gdkfoi9WTrxpWrpPSlDabf1Hz7d911F+68805cuHABzWaT9NZWMWkyLeY3d+7Ezw4elGpHBtQRr1+/Hq1WC4uLi+JZ7TWXL5fL6O/vx8jIiFC7YezevRu33Xab9RfJQw89pF2wyAgbkeOUetQ2RAWOc8PAgMt+YH/5z7HHQkskcj2uvlD58LFQ/XC5Ddu24Re/+AVeeeUV1Ot1pEFlIpVKJQwMDOC1r30tPve5z+FPN29OPffYY5Tf/HMXrfukgCXEJK6++mot7Rw5cgS33norXnrpJSwuLnYJGZ3CkQnG17zmNXjkkUdww9atADonmBP6m/Zb7HHHEa+T0efUY7yAERUQUvW4+qL1oiZZXPnPHzmCO++8Ey+++CIWFhZStRjVTduq1SouvvhivP71r8dzhw9LCVfy9ZAUMGl1KW3kDZs3b8bzzz+P8fHxrheJbu2rWq1izZo1uPzyy/HII4/gnRs3AhAXLKmCw3G6f0upI1uW+lm2nHZHOwp09hdX/mO+zwSF8NXBR/DpNf9So9na5sSO6iuvgoUhL2ZrgH790q5pGtmbWt/AZ5Hx8N9lM2cLDYDUpIG2XsxoV0hmtjY1OfM+6W0iS7P1PsEXiZSwEThuWhmQmaPaPXlJx1Q1hggfmDh84hOf0Gq2TtJ2eML3f8WYrZUfgpj+i6h96ELWZmtdgkOnMMlCc4kqp83RzvYxavmPb9+ODRs2xHr46jTXysYp2RQOS1HoZJEknMUpfScU8KpN2Aj4SpnQYnQtlYKMdrZ5mCToFjpZ7Ao5NjaGKzXHKdkUOkUTRLwWYztO6cmnn9bHvygejytrW3NhSLwTlJOxpZ3IjgEAbtu6FevXr1eOtqZoO7wWMzo6iv8d3gZDt4Ob1taKCz5JeF9fn5VQEWpiKkAf2RtXX5cWY4XkTRygIsGb1XIpSosxlaGeFzIPP/wweYxxv4liuQodPmeMzfSaYcI3a/6FUs+05hLJwZjUWGShq79bNWkxVPBLpb9U3E/JlNBZaoJo48aNVve2jvLwDUNV2OjQYmwtlSI5mLQGKZ1SkLREEGpbIqydQYWLEdV2+IfvM5/5DHmM5PFoaMNmu7Ygu7e1rDbLxymlaTE6+RfT90lWcwkj9Q5kxcOYWC59VMD5Tgf4aOs3+a7laWNUQWobkpOoaELnxhtvxNDQkJW+ZKOt80Lm6tZcwse6gh3dmILej52/5kmwUG/I//OjrWu1GiYnJ42mL2g2m3BdF5OTk3j55Zex96tfxYYNG/D+d7yDVD/tnI7kJLbINEQSgS0sLGB0dNR6xj6mxTx+7Biu96OtGVwoBjO6bhA+wJdNqycDavvUY871AwOui27BEvU3KsCxq0xaO5qDHJPqRbbluth7+DDuuOMOvPzyy6Q4JTZuEfDlq9UqRkZGsHLlSoyMjKBarSq3LzsWU3Vs9EFBvV7H1NQUpqamghw4NsZSrVZxySWX4A1veAP+nst1IxXsGHU8Ij7JxmfZcuy7sysimjr8lxcOqWXS2tEU6Cdcj/3mn8NrBaKtVSdbqVRCuVzu+Kvah45x6UDext1sNoN/rVbLys4JQHe09bsFo61JxxWDIJM+6ygX+T1JwERpH6llktpRTfHgNSJXjx3zx/Do0aO44447SNHWWedQsV3eRh9FLx+FcLT1uzZu1Br5bFOLkS0X/h5ppqZcatUyUrdTwYIUPnaL5V0hiwSTy7WljCjnO/5KRl3VtOMdZWPCB1TuFrWdpHJJ38lmapEcvKqPp3bBFFTurP1/Dx0KtsHQtSvkcpycy/GcoxB2vns8Ido6VZhIjiFOEOgQJHHlkr6TzdRZazUmjgH6o61F0ZucSwvUaGseIsdFtRiTAofy5MZGU4sIi6IJFv7YR7ZtS4y2zhuWgkBaCueQBD7a+tuEaOu44zq0GJk6uuacC2I0tYj/S7hMUFbVg9cgbO4KaRtL4RyKhnC09XcJ0da6tRhbmkuaVkNaE9hcJlHK6D5205Yt1qKte1geEN0VMu646SfKlObCkBhNLXJyxgVLShY71WM2d4UM+s6hQOqNSQ+ohG/WWozseIRIXhWBkrXGQkbKQ/rhApitizjRljMo0dZxMK3FmCB5IzmY9JGI8y9dZRMmhqpg0anV/CtntjYdbb1UsFzPm4o4wldWgOjSYqh9pB2T5mDCGooUsUsoKwtTyyVbZmsbE7M3+bNHmPA9kRKgqioc0kBtX1VzYeiyIsmciE2uxvSxm7Zts7bVSQ/LA3GEbxZaTGJbxHJpZXlIvaJ1azWpZQS2KdGBj370o0JazFLRRnp9mEGY8P1Oyn5KurQY3QJHRgAlJ/2OiZ6mQJV/0VVG5lG7ccsWrFu3rqfF9KANcYmpTGox5PrEcmnHYklencskG0JDpAylYFTiHFEtRgTL8S3eQ2diKh1ajK2lkgofIz1zlLQaC2VUcSPRbL2cJ/JyPncZ6NZiZGBLc2FI2hG+o7CKQFESGopXXCSlYLjsvxCirW2gN5GXDniz9bdCcUphmNBiqH0klRP5HmtF0rJMIvAveZ86Nve2zhK9cdlBnNk6j5qLrFDhvyvNGFPLpDTIJDp2BGrxJT/s720dpcUstYe/BztI2xVSWHPhPysSvmnH9HAwhOTeVGSuqWjo2CThawI9wZdviJqtVUAlfEU0F5E+tVmRwo3beMTlNBnxsh/cnJ3ZeikJi6V0LqpI209JlxZDbTepXNqxpLLKr+NYgaLjWQra0L37i/gYwlpMXrbpyApL6VyyQthsrXpFZZZKpszT7HvXxmvU5VGeHi8H1PG0S9LreGU/uHkL3njdtZibm8Pk5GSwqZoo8lzHZLt5Pu8shWW1WkW9XseXvvQlqfouaK9fvlxSHZFjlO+VPAuOvOHn+w/gTdfvCgSMKEw/yHmf/Cr1TPeRlZBh+ymNjIxob5vfEbLrGOQEjuh3Z0d4XyRBDSbyr8u+J+/iSG+n3RKlXvtcosoIbvwW0QZlLMn148cRVf/g0/+A5Yjlsgy7ZuPG4LPezc9826kTXVZpQzXi904B44pN5Ni/koKh42/XxMyTgIlvhzaGdEGV3n90/aTxd/dDO4eliLRzs7k9q85N0drfuf/HCBiRPmS/0/dFyhxyfizUo5G/KlwYVVo6qb7sMR3llwqchH/FR/ss2tpDOsLFdHwvxR7tIRbkhzDlmqo/zGItdJeWEcVLH3k8b9r0TBeRqkIjDeHylaSDUsiLoJIch4h1yXh7BAGla6xxbZmYbHl5RJYKXBA81b1CmvpKbpb/LZ9uqZqeQLNvIpHgg/g22v9PKiHZcsx1zPoNnbQ8WZpLFjnQpwHxKknOKxkth/1WiSrRe8MUCzY0mSxBFTJ5G7cddF+dRGWFoMlQlB2qJpOc0S6lE1oFne8gubZEuQcAcAROnjIq1TLxx+R5lHT9qVhYTpqQ93jSzkoHzyJbppI7sZ+38SxT5FGTUUXSdMzLudKoEkVxaYiPifpNaOvYwkDjgEX0g45vZP5D1RKkfqyHImk9mkaVMkdUphBft6JtLhZAChXlreyg7SBnpz8HUfs2qD7KRbjWaciTkHETDAualJKU/tM1ljCErEhL4YFpQ5/mIFNWryNexLccWJBErUX51RrMgu7jIt9m5Hc3/rgqOq1IBjqQgqVBpGoyubgY9jWuvGh4PatRGAbFboIKQtWKksopbbwW/4NJEGxsVntXu/mqlpzlzMkUWROiPqZuwplkQW+I9Blppl4+bwWD8C+irofczmRxIj4VG0UVPm3YHakuYpeHetJv0qgIFyoDyVacB40CWU+Z5YkshI+YZ674SJTihmIqJ3npUhAhYBzhRnID4UFH3ERiG0ZJXwmCVnZixNVbzmRstuerrydhhzrFSR/taKcBhRRGHPJBbmochUWyXBXZX3c6ZM5XzHzcfrlnZY52XSAmCZ7UOFKXSEWwtmQJEZLWvvla9Jh9vaRnvmbI5gwjp7BCbGK4rNaEU6bSEnQjx4+bBaG7XNmWoggh8UdAfuRKvIsiKG3lM12DDDRcOZEAR9PISpMpOrISPvKPTjrnqaJByIwryngjO4ZS3IGkSmmFczRPCdDz6OkhfR2hi2di0ixH4SML9ec8H1c79jw0TOTsNZhiSaME5ONhUcdSOQ867Gs8Xg+yj76NKeN2fRAzWXeFClAqBceIZ1hU2SFtz3HF6lLKCo/F7ayRVD/umI5cfVGICqjMM5IsOfpblYeoZUnYEpVSIe6wC53R1Anw+jBoDNbRbLGe/Q7kw8yeDlHBlVeBJC8i6DVVzNHhupS2UstIDijRD0YX8WSmkaJMKz1QPVsZTSZrUARSXoVQN9J9XPKGrrG6noIcp61E/S7uaKdwP/P7KERPMZWJJ7VUctV6zaugMIk0IZQPAaQuUnQLJun2BCsGJG+eCad8D4BHXt5NeRlH9nBi/rM5AipUzNE6ylNJ3LhkaFE/i6XM1OnJnifBYJDD0WO+JpYhnMdy9Y8Jw47gSfdx0QUd/i9KHcaga4lUWE3GIIq29FBd2ulAka4XjyghI7fMyr+4ViaSIxoI/0TnYFyND43b8Ue5naWHdBFhkvTVAZkHN6+3U1zoOOTJm1QuC0I4qs/EcaQImQr7Iaqe7AB76EbqhOYO6pn8cam88wvqhMwD7PI4HlQFjjGiOKFhmievm/hVGfLtabhcQefpbSVK8fRSPWhAUqzRcrvyabyLVmI3rX6MjFBL1yBTL6HBvLydioRgUklevKU2KYsgfIz7l2WFCCFDDnYktGcXBb0T9AddnxKep8mVJfIueGxAZdqkajERhdJJXsWJ3Fmdxi5Ykx0Kb32tYzR2wvSRLiVSVhRxnql5gA3eRZjYFeg0MhZJlPQl34y83DWdiDwnvSLISFCkBqi+/fP8OOgWOroI1nA7ad91I679rt/9i5WswWh8AmSakuFxioKsBEKeLh11IuRlzKY0HdvmaKrGIjquqPIROztGfULib5RjuXlKEpG3KUhEAYcsAoqKnxWiJmXeYMw8TUC8FcnQldKqyQCQvnQazk/LTUsch5PwjVJDvkyRkCfLkY6+VR9NWfO0SDnq79IZ7bIwtbkmG5dBXoRUxj3kGXkRPGGIPDo6/F1k+tHRTvTWsbod6yIayJOcWIoQDbLMw6SziTwKHZMwbp6OOdYdKiA4EquCwtXUp+ZBRzM35vicjpYVugiP0LT1Ie/I0lxtm+iN61P3OGKtSKIEb2wbKZWK8OBFwoqQWjoQtUbkBTqFjk0hYovYTeqn25M3T3eWAHP6gSWQTkBtPI6GNmwj7/FGNsYjyrvIErvaFIkYpHryKg1KYEmTWiahgNAFKZgQTcJS13rikDSps7geRTBV64CMVvT/AfFuHORuWjNyAAAAAElFTkSuQmCC'; let captureTimer = null; let captureRate  = 20000; function setCaptureRate(ms){ captureRate = ms; restartCaptureTimer(); document.querySelectorAll('.ctl-btn').forEach(b=>{ const map={8000:'Rare',3500:'Normal',1200:'Hungry'}; b.classList.toggle('active', b.textContent===map[ms]); }); } function restartCaptureTimer(){ clearInterval(captureTimer); captureTimer = setInterval(captureRandomStar, captureRate); } function resize(){ W = canvas.width  = window.innerWidth; H = canvas.height = window.innerHeight; cx = W * 0.5; cy = H * 0.5; buildBgStars(); buildFreeStars(); } const STAR_TYPES = [ {r:155,g:176,b:255, weight:1},   // O — hot blue {r:170,g:191,b:255, weight:2},   // B — blue-white {r:202,g:215,b:255, weight:3},   // A — white-blue {r:248,g:247,b:255, weight:5},   // F — pure white {r:255,g:244,b:234, weight:8},   // G — yellow-white (sun-like) {r:255,g:210,b:161, weight:10},  // K — orange {r:255,g:180,b:100, weight:8},   // M — red-orange {r:255,g:150,b:80,  weight:4},   // M+ — deep orange-red ]; const STAR_TOTAL_WEIGHT = STAR_TYPES.reduce((s,t)=>s+t.weight,0); function randomStarColor(){ let rnd = Math.random()*STAR_TOTAL_WEIGHT; for(const t of STAR_TYPES){ rnd-=t.weight; if(rnd<=0) return t; } return STAR_TYPES[STAR_TYPES.length-1]; } function buildBgStars(){ bgStars = []; const n = Math.floor(W*H/800); // denser field for(let i=0;i<n;i++){ const col  = randomStarColor(); const mag  = Math.random(); const r    = Math.max(0.03, (1-mag)*0.12 + Math.random()*0.04); bgStars.push({ x: Math.random()*W, y: Math.random()*H, r, a:  (1-mag)*0.55 + 0.25 + Math.random()*0.15, // brighter so they read sharp cr: col.r, cg: col.g, cb: col.b, tw: Math.random()*Math.PI*2, ts: Math.random()*0.006+0.001, isBand: Math.random() < 0.35, }); } const bright = Math.floor(W*H/18000); for(let i=0;i<bright;i++){ const col = randomStarColor(); bgStars.push({ x: Math.random()*W, y: Math.random()*H, r: Math.random()*0.08+0.14, a: 0.80 + Math.random()*0.18, cr:col.r, cg:col.g, cb:col.b, tw:Math.random()*Math.PI*2, ts:Math.random()*0.004+0.001, isBright: true, }); } } function drawBgStars(){ bgStars.forEach(s=>{ s.tw += s.ts; const a = s.a + Math.sin(s.tw)*0.03; // minimal twinkle — keeps them crisp let lx = s.x, ly = s.y; if(s.isBright){ ctx.save(); ctx.globalAlpha = a * 0.55; ctx.strokeStyle = `rgba(${s.cr},${s.cg},${s.cb},1)`; ctx.lineWidth = 0.4; const spikeLen = s.r * 4.5; ctx.beginPath(); ctx.moveTo(lx-spikeLen,ly); ctx.lineTo(lx+spikeLen,ly); ctx.stroke(); ctx.beginPath(); ctx.moveTo(lx,ly-spikeLen); ctx.lineTo(lx,ly+spikeLen); ctx.stroke(); ctx.restore(); const g=ctx.createRadialGradient(lx,ly,0,lx,ly,s.r*1.8); g.addColorStop(0,`rgba(${s.cr},${s.cg},${s.cb},${a*0.30})`); g.addColorStop(1,'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(lx,ly,s.r*1.8,0,Math.PI*2); ctx.fillStyle=g; ctx.fill(); } ctx.beginPath(); ctx.arc(lx,ly,s.r,0,Math.PI*2); ctx.fillStyle=`rgba(${s.cr},${s.cg},${s.cb},${a})`; ctx.fill(); }); } function buildFreeStars(){ freeStars = []; const n = Math.floor(W*H/4000); for(let i=0;i<n;i++){ const col = randomStarColor(); freeStars.push({ x: Math.random()*W, y: Math.random()*H, r: Math.random()*0.18+0.05, a: Math.random()*0.6+0.3, cr:col.r,cg:col.g,cb:col.b, vx:(Math.random()-0.5)*0.04, vy:(Math.random()-0.5)*0.03, tw:Math.random()*Math.PI*2, ts:Math.random()*0.012+0.003, captured: false, }); } } function drawFreeStars(){ freeStars.forEach(s=>{ if(s.captured) return; s.x += s.vx; s.y += s.vy; if(s.x<-10) s.x=W+10; if(s.x>W+10) s.x=-10; if(s.y<-10) s.y=H+10;  if(s.y>H+10) s.y=-10; s.tw += s.ts; const a = s.a + Math.sin(s.tw)*0.15; const g=ctx.createRadialGradient(s.x,s.y,0,s.x,s.y,s.r*3.5); g.addColorStop(0,`rgba(${s.cr},${s.cg},${s.cb},${a*0.6})`); g.addColorStop(1,'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(s.x,s.y,s.r*3.5,0,Math.PI*2); ctx.fillStyle=g; ctx.fill(); ctx.beginPath(); ctx.arc(s.x,s.y,s.r,0,Math.PI*2); ctx.fillStyle=`rgba(${s.cr},${s.cg},${s.cb},${a})`; ctx.fill(); }); } function captureRandomStar(){ const candidates = freeStars.filter(s=>!s.captured); if(candidates.length === 0) return spawnAndCapture(); const s = candidates[Math.floor(Math.random()*candidates.length)]; beginCapture(s); } function forceCapture(){ spawnAndCapture(); } function spawnAndCapture(){ const col = randomStarColor(); const edge = Math.floor(Math.random()*4); let sx, sy; if(edge===0){ sx=Math.random()*W; sy=-20; } else if(edge===1){ sx=W+20; sy=Math.random()*H; } else if(edge===2){ sx=Math.random()*W; sy=H+20; } else { sx=-20; sy=Math.random()*H; } const star = { x:sx, y:sy, r: Math.random()*0.18+0.05, a:0.9, cr:col.r, cg:col.g, cb:col.b, vx:0, vy:0, tw:0, ts:0.01, captured:false, }; freeStars.push(star); beginCapture(star); } function beginCapture(star){ star.captured = true; const dx = cx - star.x, dy = cy - star.y; const dist = Math.sqrt(dx*dx+dy*dy); const perpX = -dy/dist, perpY = dx/dist; const orbitSpeed = 0.8 + Math.random()*0.8; const dir = Math.random()<0.5 ? 1 : -1; captured.push({ star, x: star.x, y: star.y, vx: perpX * orbitSpeed * dir, vy: perpY * orbitSpeed * dir, r: star.r, cr: star.cr, cg: star.cg, cb: star.cb, a: star.a, age: 0, trail: [], phase: 'spiral',   // spiral → rim → consume heatT: 0, dir,               // orbit direction rimAngle: 0,       // current angle when in rim phase rimAngAccum: 0,    // total angle swept in rim phase rimOrbits: 2.5 + Math.random()*2.0, // how many times around before consumed rimSpeed: 0.05,    // radians/frame — starts here, accelerates rimR: EVENT_HORIZON * 1.18, // orbit radius (just outside event horizon) consumeT: 0,       // 0→1 for final shrink }); } function heatColor(t, baseCr, baseCg, baseCb){ if(t < 0.3){ const m = t/0.3; return [ Math.floor(baseCr*(1-m)+255*m), Math.floor(baseCg*(1-m)+160*m), Math.floor(baseCb*(1-m)+60*m), ]; } else if(t < 0.65){ const m=(t-0.3)/0.35; return [255, Math.floor(160*(1-m)+240*m), Math.floor(60*(1-m)+220*m)]; } else { const m=(t-0.65)/0.35; return [255, Math.floor(240*(1-m)+255*m), Math.floor(220*(1-m)+255*m)]; } } function updateDrawCaptured(){ for(let i=captured.length-1;i>=0;i--){ const c = captured[i]; c.age++; if(c.phase === 'spiral'){ const dx = cx - c.x, dy = cy - c.y; const dist = Math.sqrt(dx*dx+dy*dy); const G = 65 + (1/(dist/Math.min(W,H)+0.01))*2.2; const grav = G / (dist*dist + 25); c.vx += dx * grav * dist * 0.06; c.vy += dy * grav * dist * 0.06; const speed = Math.sqrt(c.vx*c.vx+c.vy*c.vy); const maxSpeed = 28; if(speed > maxSpeed){ c.vx=(c.vx/speed)*maxSpeed; c.vy=(c.vy/speed)*maxSpeed; } c.x += c.vx; c.y += c.vy; c.trail.push({x:c.x, y:c.y}); if(c.trail.length > 60) c.trail.shift(); const nearness = Math.max(0, 1 - dist/(Math.min(W,H)*0.62)); c.heatT = Math.pow(nearness, 1.8); if(dist <= c.rimR * 1.4){ c.phase = 'rim'; c.rimAngle = Math.atan2(c.y - cy, c.x - cx); c.rimAngAccum = 0; c.rimSpeed = 0.048 + Math.random()*0.025; c.trail = []; // fresh trail for the rim spin } } else if(c.phase === 'rim'){ c.rimSpeed = Math.min(c.rimSpeed * 1.022, 0.55); c.rimAngle += c.rimSpeed * c.dir; c.rimAngAccum += c.rimSpeed; c.x = cx + Math.cos(c.rimAngle) * c.rimR; c.y = cy + Math.sin(c.rimAngle) * c.rimR; c.trail.push({x:c.x, y:c.y}); if(c.trail.length > 90) c.trail.shift(); c.heatT = Math.min(1.0, c.heatT + 0.012); if(c.rimAngAccum >= c.rimOrbits * Math.PI * 2){ c.phase = 'consume'; c.consumeT = 0; flashes.push({ kind: 'ring', life: 1.0, cr:180, cg:0, cb:255, }); logoPulses.push({ life: 1.0 }); } } else if(c.phase === 'consume'){ c.consumeT += 0.095; c.rimR = Math.max(0, c.rimR * 0.80); c.rimAngle += c.rimSpeed * c.dir * 2.8; c.x = cx + Math.cos(c.rimAngle) * c.rimR; c.y = cy + Math.sin(c.rimAngle) * c.rimR; c.trail.push({x:c.x, y:c.y}); if(c.trail.length > 30) c.trail.shift(); if(c.consumeT >= 1.0){ captured.splice(i,1); const idx = freeStars.indexOf(c.star); if(idx>-1) freeStars.splice(idx,1); continue; } } const [hcr,hcg,hcb] = heatColor(c.heatT, c.cr, c.cg, c.cb); const fadeAlpha = c.phase==='consume' ? (1-c.consumeT) : 1.0; const trailLen = c.trail.length; for(let ti=1;ti<trailLen;ti++){ const t0=c.trail[ti-1], t1=c.trail[ti]; const trailFrac = ti/trailLen; const trailA = trailFrac * c.a * (0.45 + c.heatT*0.55) * 0.75 * fadeAlpha; const trailW = Math.max(0.2, c.r*(1-trailFrac*0.65)*(0.5+c.heatT*1.0)); ctx.beginPath(); ctx.moveTo(t0.x,t0.y); ctx.lineTo(t1.x,t1.y); ctx.strokeStyle=`rgba(${hcr},${hcg},${hcb},${trailA})`; ctx.lineWidth=trailW; ctx.lineCap='round'; ctx.stroke(); } if(c.phase==='rim' || c.phase==='consume'){ const arcSpan = Math.min(c.rimAngAccum, Math.PI * 1.4); const arcStart = c.rimAngle - arcSpan * c.dir; ctx.save(); ctx.beginPath(); ctx.arc(cx, cy, c.rimR, arcStart, c.rimAngle, c.dir < 0); ctx.strokeStyle=`rgba(${hcr},${hcg},${hcb},${0.18*fadeAlpha})`; ctx.lineWidth = c.r * (2 + c.heatT*5); ctx.lineCap='round'; ctx.stroke(); ctx.restore(); } const glowR = c.r*(2 + c.heatT*8) * (c.phase==='consume'?(1-c.consumeT*0.8):1); const glowA = c.a*(0.25+c.heatT*0.75)*fadeAlpha; const grd=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,glowR); grd.addColorStop(0,`rgba(${hcr},${hcg},${hcb},${glowA})`); grd.addColorStop(1,'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(c.x,c.y,glowR,0,Math.PI*2); ctx.fillStyle=grd; ctx.fill(); const coreR = Math.max(0.2, c.r*(1+c.heatT*0.5)*fadeAlpha); ctx.beginPath(); ctx.arc(c.x,c.y,coreR,0,Math.PI*2); ctx.fillStyle=`rgba(${hcr},${hcg},${hcb},${c.a*fadeAlpha})`; ctx.fill(); } } function updateDrawFlashes(){ for(let i=flashes.length-1;i>=0;i--){ const f=flashes[i]; f.life -= 0.055;  // faster burn — gone quickly if(f.life<=0){ flashes.splice(i,1); continue; } if(f.kind==='ring'){ const BHR  = Math.min(W,H)*0.30; const burnWidth = BHR * 0.18 * (0.3 + f.life * 0.7); const innerR = BHR - burnWidth * 0.1; const outerR = BHR + burnWidth; const g1 = ctx.createRadialGradient(cx,cy,innerR,cx,cy,outerR*1.22); g1.addColorStop(0,   `rgba(60,0,100,0)`); g1.addColorStop(0.3, `rgba(100,0,180,${f.life*0.50})`); g1.addColorStop(0.6, `rgba(140,0,220,${f.life*0.30})`); g1.addColorStop(1,   `rgba(60,0,100,0)`); ctx.beginPath(); ctx.arc(cx,cy,outerR*1.22,0,Math.PI*2); ctx.fillStyle=g1; ctx.fill(); const g2 = ctx.createRadialGradient(cx,cy,innerR,cx,cy,outerR); g2.addColorStop(0,   `rgba(100,0,160,0)`); g2.addColorStop(0.25,`rgba(160,0,240,${f.life*0.75})`); g2.addColorStop(0.55,`rgba(210,30,255,${f.life*0.95})`); g2.addColorStop(0.80,`rgba(180,10,255,${f.life*0.55})`); g2.addColorStop(1,   `rgba(100,0,160,0)`); ctx.beginPath(); ctx.arc(cx,cy,outerR,0,Math.PI*2); ctx.fillStyle=g2; ctx.fill(); const g3 = ctx.createRadialGradient(cx,cy,BHR*0.96,cx,cy,BHR*1.06); g3.addColorStop(0,   `rgba(200,150,255,0)`); g3.addColorStop(0.45,`rgba(240,200,255,${f.life*0.70})`); g3.addColorStop(0.55,`rgba(255,255,255,${f.life*0.90})`); g3.addColorStop(1,   `rgba(180,100,255,0)`); ctx.beginPath(); ctx.arc(cx,cy,BHR*1.06,0,Math.PI*2); ctx.fillStyle=g3; ctx.fill(); ctx.beginPath(); ctx.arc(cx,cy,BHR,0,Math.PI*2); ctx.fillStyle='rgba(0,0,0,1)'; ctx.fill(); } else { f.r += f.maxR*0.08; const g=ctx.createRadialGradient(f.x,f.y,0,f.x,f.y,f.r); g.addColorStop(0,`rgba(${f.cr},${f.cg},${f.cb},${f.life*0.9})`); g.addColorStop(0.3,`rgba(${f.cr},${f.cg},${f.cb},${f.life*0.4})`); g.addColorStop(1,'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(f.x,f.y,f.r,0,Math.PI*2); ctx.fillStyle=g; ctx.fill(); } } } const NEBULAE = [ {r:60, g:20, b:140, a:0.13, ox:-0.32,oy:-0.28, orx:0.10,ory:0.07, ph:0.0,  sp:0.10, rad:0.70}, {r:120,g:10, b:60,  a:0.10, ox: 0.35,oy: 0.22, orx:0.08,ory:0.09, ph:2.3,  sp:0.08, rad:0.65}, {r:30, g:40, b:120, a:0.09, ox:-0.10,oy: 0.30, orx:0.12,ory:0.06, ph:4.1,  sp:0.12, rad:0.60}, {r:80, g:15, b:80,  a:0.08, ox: 0.28,oy:-0.26, orx:0.09,ory:0.10, ph:1.5,  sp:0.09, rad:0.55}, {r:20, g:50, b:100, a:0.08, ox:-0.30,oy: 0.08, orx:0.11,ory:0.05, ph:3.6,  sp:0.07, rad:0.68}, {r:100,g:30, b:30,  a:0.07, ox: 0.15,oy: 0.35, orx:0.10,ory:0.08, ph:5.2,  sp:0.11, rad:0.50}, ]; function drawNebulae(t){ const tick = t * 0.00015; NEBULAE.forEach(b=>{ const x = cx + (b.ox + Math.sin(tick*b.sp+b.ph)*b.orx) * W; const y = cy + (b.oy + Math.cos(tick*b.sp*0.7+b.ph)*b.ory) * H; const rad = b.rad * Math.max(W,H); const a = b.a * (0.8 + Math.sin(tick*b.sp*2+b.ph)*0.2); const g = ctx.createRadialGradient(x,y,0,x,y,rad); g.addColorStop(0,   `rgba(${b.r},${b.g},${b.b},${a})`); g.addColorStop(0.30,`rgba(${b.r},${b.g},${b.b},${a*0.50})`); g.addColorStop(0.65,`rgba(${b.r},${b.g},${b.b},${a*0.15})`); g.addColorStop(1,   `rgba(${b.r},${b.g},${b.b},0)`); ctx.beginPath(); ctx.arc(x,y,rad,0,Math.PI*2); ctx.fillStyle=g; ctx.fill(); }); } function rimStarCount(){ return captured.filter(c=>c.phase==='rim'||c.phase==='consume').length; } function drawBlackHole(){ const R = Math.min(W,H)*0.30; const distortR = R * 1.055; const distort = ctx.createRadialGradient(cx,cy,R*0.98,cx,cy,distortR); distort.addColorStop(0,  'rgba(0,0,0,0)'); distort.addColorStop(0.4,`rgba(180,160,255,0.04)`); distort.addColorStop(0.7,`rgba(140,120,220,0.06)`); distort.addColorStop(1,  'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(cx,cy,distortR,0,Math.PI*2); ctx.fillStyle=distort; ctx.fill(); const rimCount = rimStarCount(); if(rimCount > 0){ const coronaA = Math.min(1, rimCount * 0.6) * 0.07; const hawking = ctx.createRadialGradient(cx,cy,R*0.94,cx,cy,R*1.4); hawking.addColorStop(0,  'rgba(0,0,0,0)'); hawking.addColorStop(0.4,`rgba(80,0,140,${coronaA})`); hawking.addColorStop(0.7,`rgba(50,0,90,${coronaA*0.4})`); hawking.addColorStop(1,  'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(cx,cy,R*1.4,0,Math.PI*2); ctx.fillStyle=hawking; ctx.fill(); } ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2); ctx.fillStyle='rgba(0,0,0,1)'; ctx.fill(); } function loop(t){ ctx.clearRect(0,0,W,H); ctx.fillStyle='#000005'; ctx.fillRect(0,0,W,H); drawNebulae(t); drawBgStars(); drawFreeStars(); updateDrawCaptured(); updateDrawFlashes(); drawBlackHole(); drawLogoPulses(); requestAnimationFrame(loop); } function drawLogoPulses(){ if(!ebImg.complete) return; const BHR = Math.min(W,H)*0.30; const sz = BHR * 1.92; let glowIntensity = 0; for(let i = logoPulses.length-1; i >= 0; i--){ const p = logoPulses[i]; p.life -= 0.016; // slow fade — gentle lingering glow if(p.life <= 0){ logoPulses.splice(i,1); continue; } glowIntensity = Math.max(glowIntensity, p.life); } const baseAlpha = 0.0; const totalAlpha = baseAlpha + glowIntensity * 1.0; ctx.save(); ctx.beginPath(); ctx.arc(cx, cy, BHR * 0.96, 0, Math.PI*2); ctx.clip(); ctx.globalAlpha = totalAlpha; ctx.globalCompositeOperation = 'source-over'; ctx.drawImage(ebImg, cx - sz*0.5, cy - sz*0.5, sz, sz); ctx.globalCompositeOperation = 'color'; const tintAlpha = 0.70 + glowIntensity * 0.28; ctx.fillStyle = `rgba(160,0,255,${tintAlpha})`; ctx.fillRect(cx - sz*0.5, cy - sz*0.5, sz, sz); if(glowIntensity > 0.04){ ctx.globalCompositeOperation = 'screen'; const neon = ctx.createRadialGradient(cx,cy,sz*0.18,cx,cy,sz*0.62); neon.addColorStop(0,   'rgba(0,0,0,0)'); neon.addColorStop(0.45,`rgba(180,0,255,${glowIntensity*0.50})`); neon.addColorStop(0.75,`rgba(120,0,200,${glowIntensity*0.22})`); neon.addColorStop(1,   'rgba(0,0,0,0)'); ctx.beginPath(); ctx.arc(cx, cy, sz*0.62, 0, Math.PI*2); ctx.fillStyle = neon; ctx.fill(); } ctx.restore(); } resize(); window.addEventListener('resize',resize); restartCaptureTimer(); setTimeout(captureRandomStar, 20000); setTimeout(spawnAndCapture, 40000); requestAnimationFrame(loop);
</script>

</body>
</html>"""

def _page(content):
    return _BASE.replace("BLOCK_PLACEHOLDER", content)

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_LOGIN = _page("""
<style>
#canvas-bg{position:fixed;inset:0;z-index:1;pointer-events:none}
.bg-noise{
  position:fixed;inset:0;z-index:5;pointer-events:none;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 512 512' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.80' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E");
  background-size:180px 180px;mix-blend-mode:soft-light;opacity:0.10;
}
.login-card-wrap {
  position: relative; z-index: 20;
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: 2rem;
}
.login-card {
  background: rgba(10,20,12,0.82);
  border: 1px solid rgba(45,106,79,0.35);
  border-radius: 16px;
  padding: 2.5rem 2.5rem 2rem;
  width: 100%; max-width: 380px;
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  box-shadow: 0 8px 48px rgba(0,0,0,0.5), 0 0 0 1px rgba(45,106,79,0.1);
}
.login-logo {
  text-align: center;
  margin-bottom: 2rem;
}
.login-logo-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 120px; height: 120px;
  background: linear-gradient(135deg, #1e0a4a, #7c3aed 50%, #4c1d95);
  border-radius: 18px;
  margin-bottom: 0.75rem;
  box-shadow: 0 4px 20px rgba(160,32,240,0.6), 0 0 0 2px rgba(180,0,255,0.8);
}
.login-logo-mark img {
  width: 120px;
  height: 120px;
  border-radius: 18px;
  display: block;
  filter: brightness(1.1) drop-shadow(0 0 6px #a020f0) drop-shadow(0 0 14px #cc00ff);
}
.login-title {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0 0 .2rem;
  letter-spacing: .5px;
  color: #000;
  -webkit-text-fill-color: #000;
  text-shadow:
    0 0 4px #a020f0,
    0 0 10px #cc00ff,
    0 0 20px #cc00ff,
    0 0 40px #a020f0;
}
.login-sub {
  font-size: .8rem;
  color: #000;
  -webkit-text-stroke: 0.3px #fff;
  text-shadow: none;
  margin: 0;
  letter-spacing: 1.5px;
  text-transform: uppercase;
}
.login-field {
  margin-bottom: 1rem;
}
.login-field label {
  display: block;
  font-size: .75rem;
  font-weight: 600;
  color: #000;
  -webkit-text-stroke: 0.3px #fff;
  text-shadow: none;
  letter-spacing: 1px;
  text-transform: uppercase;
  margin-bottom: .4rem;
}
.login-field input[type=text],
.login-field input[type=password] {
  width: 100%;
  background: rgba(255,255,255,0.04);
  border: 1px solid #a855f7;
  border-radius: 8px;
  color: #fff;
  padding: .65rem .85rem;
  font-size: .95rem;
  outline: none;
  transition: border-color .2s, box-shadow .2s;
  box-sizing: border-box;
}
.login-field input::placeholder { color: rgba(255,255,255,0.35); }
.login-field input:focus {
  border-color: #d8b4fe;
  box-shadow: 0 0 0 3px rgba(168,85,247,0.25);
}
.login-agree {
  display: flex; align-items: flex-start; gap: .6rem;
  margin-bottom: 1.4rem;
}
.login-agree input { margin-top: .2rem; flex-shrink: 0; accent-color: #a855f7; }
.login-agree label {
  font-size: .8rem; color: #000; -webkit-text-stroke: 0.2px #fff; line-height: 1.5;
}
.login-agree a { color: #52c97a; }
.login-btn {
  width: 100%;
  padding: .75rem;
  background: linear-gradient(to bottom, #5a5e62, #b4b9be 45%, #b4b9be 55%, #5a5e62);
  color: #c00;
  -webkit-text-stroke: 0.4px #ff0000;
  text-shadow: 0 0 6px rgba(200,0,0,0.5);
  border: 1px solid #ef4444;
  border-radius: 8px;
  font-size: .95rem;
  font-weight: 700;
  cursor: pointer;
  letter-spacing: .5px;
  transition: opacity .2s, box-shadow .2s;
  box-shadow: 0 4px 16px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.15);
}
.login-btn:hover { opacity: .88; box-shadow: 0 6px 24px rgba(0,0,0,0.5), inset 0 1px 1px rgba(255,255,255,0.15); }
.login-divider {
  border: none;
  border-top: 1px solid rgba(45,106,79,0.15);
  margin: 1.5rem 0 1rem;
}
</style>

<canvas id="canvas-bg"></canvas>
<div class="bg-noise"></div>

<div class="login-card-wrap">
  <div class="login-card">
    <div class="login-logo">
      <div class="login-logo-mark">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAdoAAAHaCAYAAACn5IivAACvNklEQVR4nO29edRtx1UfuM/9vu+Nsp6s2LJsea2EldUroSFgGwx2Voekg2VNxmIISZrOnO4OOHjANtgmWNiygIDxAN00WemV1f90SEICeJAt2RI2kMFOwMwmayW9Ogb0LFmS9d6T9MZvOP3HvefeOnVq1x6rzrnfd7f0vXvO3rt21ZnqV3vX1Hz19nYLANAATktZg2vl0k+FWlTQ0joZWYrP4ZnO27Z3jh3nZJLjdpFnVk6lp3jINXFsZGWMckvsbaguNcivVFaSBwDQLOpHURqjbu7YQw9gdV2YnLJn4Ut1vInzzXNwYZt14QmA1Vx0yRvFuSFh/j394PqaDOg2Aj7Gy+mkztH0TQNNAExNJl1cVmmapbxpANo2mY6y5cGTyiw61P3YUB1iOQAGWxZeT66oI3Pg5kE1QNZ6/yT3aAzC6vxYJyUP+bOUsAGYg0/3F8m4rY/4ryRJ80P1gmvG7OT4FC+Vlnrx0Q+haVStXIq0NilersW+fOcIexLZUidTCUpa0mN/9EeZpO9CjWelAmSlfa9jSXk4nizHngZkpZiRqv85fxr7kvJ2/NlAMQLXnBGsIFOpkLhlSuoEDQ0J4Ep42nMr2JqOiZZ7DkyxND1edD05uxyZRWcq7/GGVmRpNBbjZbrUsDSYvPQ7l8vL2piR3EMpYGF6VrzRgC9V/hTNMIDlIrjkQrWtDs6fNH9Kp8+kAVfDW1ewhUxfFDjz3IDV6NXGaTZUnqwVv0bfwpOk0YKv2zecyQ9A3niw3jdOPe4BrBzi5iO5lhkGsFQhKNKCoZak+UkaEismDrgSntd5bbDt8RJgS6bh8pCPXASsSh1MdwOw45H03ns8qxLgSqXRNvg015v9ToT9spx6L5cnB2/G+v4seBjyh6HjjDHuDZlKpcQtExd0V4wV4JK6yHn8oVDnmL1BuRh6ElBl5ZuRUzyOPatsqcPwaqfy7m6IR5yGlYbHzt84CIqSSwFV8533ZA4gmyqThE/JcvqaP6l9SXk73kx7sdbCev9J86d0WDJBOJkLwNg5V5b7UCQfMEvXIYSMypDrkFasknwp3Q0Yj0vWZ0/pe/MkaaSgIjnm2qJkWpCV5MutzzX1v5ctCiNSPHTUsfeNKF05SfOzXGdPpggna8+1YCshMRg7hpAHMiRqQKZLyHrPi6u7odFIC6oaENTa0AyCkgCyFoi1NpuoCxGzwTnP8ST8lE5NLKH0uPxN6JjQoWSrkxXgZvWM5xqw5XxoYoBlyrU8T5lFF0szlXf8sJMWcLn63s/RCq4S+9rvN2lXsBiRBWQ59mPZmJjCxQ6Krw4dh3L2wyz4J82f0sFkpH7Gu82lS51j6WuDLSkXrogj+jAV030wnaUuo1LZAOq0yANUc7IaPK3c6x3k1BNUfp4ga8GelO6Y2EHxB6Hj0Kgmw5Se5IK0JM2Pc+MkL0ePj3i3XAD2lFnAViRXhpCllZQEWHNkAdQNCE+LtO8LVz/JcxoEJQFU6fcr+cYxGbfOyelIvnENtlhJak+DGYPQcQ5EqAfkffEeNqRlx2QS/uqE791i53H6GmDL1ZWk5/ByIC5Nh+lYQHgDrHXI2tDiyjxAWJNGC6glSNIvS9pipJfWp1IdD5JgBiaLaYYJKGPcAqV0OX/SNByy3EAJv8fLeLfacxXYMtNbdIsOjCJkEp25QjPQ3QDptKgE4HL1JXWKhz0t+JqOHftluSDLySuW1QLYXP5SecybSVsX3AvXAKGFpOBL6WkAN8tjhJK9wDaZhhjBK7WfkjeLfAa8lF7GXlJGLGLBecc0gIqB8Qac65En4Hroc8PGnuAqIU06yX3xAllN/ZvTtfxx88jJc2lmmAC7EKogVmDV3ARrmXI6Ej7GW53QoWQJ+IqBt1Z/rYDnKcN0JPdjA6DTJS3gltL3AlfWt0vo5gArecwMGZcE2RRx6nwvfMBscvQksgaC0LG0xSEpXKwrbVl4tEi45fUCXFRHEUq2gi3nA3MF2AIDo5rAriQ9pav5UDegXI5K3EspQHuXwQrIkvJIgTiXnpKVANkceQIrJx8NTgDC34SOCbmET+nFYDRlsNXIPXgSmUQH1RUsYLEB1HpkfTekMq6+JWwsAVdKrgViAP73z5VhZeDUiTl+KNM2iK0YpAXcmDep0HEKLD3tUXoSGQakohdygmDLyReTp+xLKyFSVtCrtQDpBoTLUC3AdQFhhV3Nt8exxfnuubYoGRdkJflI6n0uZljwhYMhOd6kQscl03PKy3lIKT7Fi9P2zhP9thKw5ehxjkvIcwOjODY416oB1qECboUC5Q3A1qESgMvV937GVkDWArHWprXRIq1PpVjgQVybFH5g+ocmdCzNkwu6HL6ElzxnLM6v+SjID1LQXysCWAZPWtn00jG9Wg0IbwB0PLLecw9Qzcm8w8YScKWI1bAWdBlhMmmZJdfNAbjaWCKVY/xN6JiQ5+6JhpcF28yesvE590NJkfbjU/EYIWSpTKKD6Q7SCDZi2IBzWZICYG2bY4Kr5bvnELf+0ZzneNL6lyIvLOFgB4e/CR0z5Sm+hMc+dwBb8bGgvzZni+Jx7LGB1dGrpdJugHQc0oKjp8wDhDVpJIBq+ca5+ZQEWSw/C65I03DzkchC3rb05eIWik2aLd3alpVvWmuom9JrEFmKj/FyOqnzpX7TQNO2aVl0XuI4l48kzepyGmjblq0fy6w6mK4k7YbGo9qAm9RXrG2c09OAugR8reQJuhIelTdHriEudmC40Mmw+o0VOqZkoTypswiLJv8S6clWCsNeyiZVdomMw0ulzZ3H15j7sDCZ+rhyCDmnz/nIm8AmS5dDjAUsuL8bkpH1vnkCrod+CXCl5OixcaEargw75/By/FBW6/vSYgbG28aEOT4pN7T+VPktqE3lHXi/TayL2OfKJDzueU9W0LNNUed5YrrePIlMokNdZy4NJ+2GypEWMK22S+mXBleKNAOguHlJQTdnT4tB2jTcbzyHCZ2cE/X0GXUceZVNpFe7FdLLk+FB5+ykZBqe5Dwuv6a1SX1UnNZvTlfDm4JXS76LjK4MzCY7jw2RpAVc7b3P2izkOFD21N+wIW9NXcM5z/GkGJTSk2KNNB0HE1P8jvSh4wi8rKCaunArWJPAG+nlbGh5LucE2ErIA4y1PBdgZepI7hEXODcAOi0qAcYWkCrFk8h7usYBUNx8LSArzauTW7DGYpfCCozHGnWcBFhmwVK2PFsh2jLMGTLAxezl9GKd1DmVvisr52OxHK+ySn+gHrzcdJ84HVtHuNoNaV8zQG9DarICXy3A9dAvAa4a4JTY4QAp1y7Fy9W/JcAVIw7gcvkNcEPHSFiYKuRYN4eTZ08P8c6xNCk+pZc7Z4NvIbBNygtNzpfKJDqYrub9w2xIfzfkQ9b7aQVzi76GyO+TSm8YACW5V5pzSWNDih8p7LHgEQf8U/yY8qFjBvjEabWVmvcNStml9OYnOsCVgit1XgNsLXKKl7VXyKuVfkC53w3VJ0kjSpteSpLN0WvxMHmR68/Yt553vByQUWQFUG5aaTlj3iwpYAKs5AJLgae2DDn5/IQHuBRvimDL1bWEkEn9xFQsLJ1EB9MVA6kifLwBbR8qCbglZFz9EuCalDt5s5L7oQVZzDaVtwY7KOLYzWFB7ppnGnCR3IgSN4SbL1cXk81P8veEusEpndQ5lh69DgXYqnQdQshWGRt8hV4tlZ/0d0O+tC6A6wHC1jSl30FP0M3xKPCtjSU5OYffnc89WkP/ZCzXvkTcP4tdSi/LJwZNaQFYKtNWEFKbXIA2gS7i1eZIA25qgNwMiipOVjC15pGVCZ+/BYQt3yDHptexRJY6l/A6vvRb98QSDvin+PH5zAKwkkKXAk9tGXJylJ8YpUylLwq2GQ9O8wFhcm4IWVrRcNJJgLV7Rhowztp0+N1QnqyAWzK99r0uycPkksaBBLQ5eiVAllMeLyzh6GIyijfDDFB86oZbboCWPG8cF3Ct4BqfW8HWE2B7cmEImS1jLGJB2ZG8XxuAPNxU+7lpKnctTyuXAio3rbWxIcWeWO79rCXYluLneLOUsObFp0A592exLS03eVMJ71Z7XgNsNXItT/pBYunZlUTCq1V/lJvwcVWSAoFGp5asBBBk5Q7eLNeCBHQl+hqQK0EcvJPweqOOpQArAUAP4MzZkZYhJ+fwl7zIu82lS53H+lKZFGwtcsvAqIGtHrPBZUw7lg8Qs+X9uyE+jQ64wmk90jJ48SRyS7m5dZPmvONJ62VMj/vHIapcXJ44dEzJQrkFUDUkyVMLuChPGUquBbYc+xJ5EoiZ+hyZRRdLowbAjVdbhGqAqbUcUpmHvtQuQL5hkLMlPc7Z0pzn7EtxRkoeeIHV9zFPHDqmboqm1VSiJZKyLS039yYueYR3i53HNjUvOedFyR2zAZgYGMWxkUyHeLUaEF4+iw2tBdUA3BrpLfoa0n7zpfL0AlkuwHoTB2NyOJLjrV3o2GKLC7ocPsabH8jBNj7XAG+Xt9YOm5cJIXNtcNJRupr3B7NR63dDOE0FcKWkbXC68ZiN31huOZbIsHJp6opa35EWJzDeLKcgzSiWWwFVSpI8vW/kIC0SSvYG2+Sxob82l0aaVior4dW6Ad3GQ54UWZ9Gtv5S9s9Ky+QNuJh87MaF9Zq4GJLCHeqPaxOTcXgAiU0FciDDASfNy+Z9czDbOR2uTMLDwqwS8C0Btrl03DTSPTo5MjWgOhFmW/u7IR153T/J+1Ra5gHC1jQu9UoiH64sp5PDHIy0uIDZ4Oil+BSvgU3omC3T8JZgywgl1wBbTr4anqfM4tUm88lM9SkNjBsAxskKgjV1tDKuPtdGMi0RaZGUj6oXpPbZdWSCxwFYb+JgCbe88fkmdMyUSXjJcwXYcvQ4xxo5i5fw2MXAKtCh0hQHtE342J2mAqYcsoKKRl/Dk8il943rHFB2MP0xAFaaFybLXd8292ZJbyKXNOlape1UuoaQxfyUfqwX6yzlTQPQtkn9gS5il6PXL3ADTdtmdVO2KN7KfANtm849V66cze4+YbrZ6yUIs1X6d0N2qgG40vWNOSS1KAUgj3wtQJzSk57n8mI9U+Vzw+quOG8JPqTq7MF+tCljFLJzQBj705DWlraVwm295F6mpVzo2Vo+0uVxgRCypwzT0VQUyV/lrj7pjHSWNNd0lEgLCqV0asks74N0nEQsd6lbEna8QJaq15umWf5piWtD0ghIXe8ydMwBDo4slFvAVEPcfHM6Ej4Frui5AWzVx4w9KrU86XQflg6xX+0GuA4njQG42vRaGVffwtPKpcdUXpxz6TVZwZWyi9mWlDXmDUYdYwlzGYUy6Yei/dPYz+lI+BRvamCrkUt5EplER/M5JW0IBkWV+t0Qn2reMytgS2Ue+pQ3q/n+NeQJuh0PrasLAaw0L009OQgdS0GHA3wWsJTY5KaRyFJ8jCc+Lwy2A54ghCx9mWp4tVia6oC2CR+bSHL9VhAU6RgrcWnqGu8Bp272OJbIsHJZABbDGOqPIixvDgaEhIaONfxY7gGoEuLmm9ORAm5OJ3U+SF8AbLNyZBGHLIgSPI5MooPperxLFEhLfzekp8kCrjG9h01vnkSuIcn1sa+DAFgPjGFjBtO7xc4Ho45TyhSfkvUVV5qWG7Qc2ZUZNRbbl4w6zvFzI4wxnexIYsNo5DiNRVfKG8ii0cKhjJOeo8tNm/xNlM9Kovxdcz48dNgA1xOoMQCS2pXIrY18rizLc9w9SUJYvQ+wKlM8UjlXb3fnptAxJVuUrtfJ7NEKCfNtIvu5sJ7mOlJ8jMc9j9M3AIB5thLifgicEDKHJ5VJdJa6jgtYuNImfOxO3vfEC3C16aUyT31OmhLvYKmGRKersW9Jl5QxGjrx+QwT5DLLFj4BrDUpBF9AgDdX/hyf4lnBNwW2ni3NHo8IIatB16mv1qPBkfwtOChqQ/VIcs8lDTp1emP+Fn0qrQSQPesb8bmgPxTTif+kOty8pWCb3I9WCkKgBFbswjl/IvsZb1dyrRgvpzM22GrkMU/68cZeaFKHYScwmEwzNcCbevnWhbxB1ItK5CUFaG7YWAKuFFF1B8c+B2Q5dmKZBA8sdqxgawsdM8HVApaeNjvQlQIuxaMAWAK+XmDLkitCyFKZRAfTnSxAbcLHYioFopL3qqROCRlXXwOukrpEm1YDsrn63AM/MKLyHfCYYCsPHTO8V09AlRK3dYJ5uRhoSsGVOi8FtmI5MThNDawKrzb7riin+iR/N+Hj0WkDuHyZ5d2y2tPWP5iMC7KYLW7ZYwySYhGmn6z3GdfADx0LwJVL2M3g/EntZ3WMgKs9J19QAdha5BQvZ4+TTqJDpZk6sK1becemDeDyZZawMXUd3HqJIhHoCq6HU352fc/UxcqT4lPzfGcxQwuwObK2LjxsUjo5wE3pep3nXnAMbFNkAmAihCyVrczSZRcBkzBUS9l2AUWnMh11GhVwGc/Qo77ysl0CXCm59JiUOfQ1l8CSnDzF751nsAPfjzYDsNyCedwEKUlAF5UxvducTuocS0+BZA78qWMJAHN4EtDU6nDTmoBSULkWAegNJakU4HrZ8wRMDtW4RrL+ccpnKWP2a0qBz4OofCkeBrbp0DEBsLkCcm9ADMbSP2keUjnHu+UCsFTmdSziCQZGxbIsMAvmBx8WAFv38q8bWQHS214RmXPYmLpGzzpIkldO3wtfJOlTfIqXAttZpFFkBJj2YqU2qZdYeh0NDAFXCq7xuRpsnfprszxkbm3OBkdG6YreB6Txo/oVDIqSlAlV09g+ROQNdqXLUDIvT1kJcPUiDghRZdBgjKcupzzUdc5CQRJoiILmCugFqhKSlA2TJfWFL8gYYMvJS8KzypY6ilWvXADQkUqWZwO409StoWP9tih9K7iy6ybiGEAPsrmyeWAMZSeHg9nz4HpnOS+Wm2Es57581j9JHjk5m094t6nz2K5UxgFbjn02z9Gr5VQiKsBSzl+tQVNpGBw2Kga4TgOhSgKuhz6Vlqo7tLpLPUeQ9QBXjCi8oHhY2sF+tKmMOGDFBWDPmySxm9OR8BuQvTQSGVuPOTjKkyeVDXQNazlT4GX6HTl8fJTJ8i6MoeulIyXp8pAWHiaXXnvv2AlkudiRwgUp9niBbXft+KhjRoZaYCtJEtCV8Ac8IdiiLyGRT64sEoBNVfBopU+s9sWRiUDYkLYmuQAyYfMo0lED3BIyrr4EXCm5ph6jQFaKQ2EaLRBTepKyJO00zWo/WkkmFPh6tDo4f5I8cnIOP8lLhJLjNNi5+bhQCHkpS1wXK12GXIHUOCiqJE29wTBVmhLg1rDnCbiWsmjqELZtgTeuxRsrcXCC4lHnrNAxhy9pcXi98BK7OR0p4A50RgZbSlfL0wIrCjQTmrvaS18pfLwBXh6Vvj+SRqHVnjWvmmFjqqziOkpQP0nK44khXNtcLMDOB5sKWDJOyWtXKhLQlfApvRhsuS+V5XiRsTvAhrZz+rFMUzmZwGeEQVGegH+UgNdyf0rZr2nXDLgO+VnB1UJe5efeR+pPk3+Kzz1fho45YJLjhzKvm+Fxszjl5fBZLRqhh0npSQA0dazhWWWULmeUJ2mj0K8HWWxvANeeRqQreBetQCnRkZIHiGnl6LEyyoflT9WfElyI01A6VFk45d+Ejgk+xUuCLfKS5YDTBLDM/loObyAjpvtg6VUgrLDhRoXDx6Nc0xGmYuBcQcdTJgGeHM+zzpac5/L2whIKPzQ4EMs2oWOCj/HIcwXYUpS1o9gMgSqDBFhzNAAsz5DvhMLHFhtHjSz3rFSayQGusH82J/OoD2I5esyo+7jnGuyxkBfYxjJ0P1rNRUrAtXH4k+SRk3P41P1JnUvB1nLsyRvICnq1XBu1fi1ksXlUgXcDuLb0UttWcCXtC+eTc8+5ZfHAjhwuSMoTytD9aCWZU4XXgCSHJHZzOtwbywXg3nFhsE3llaq0cxW5CHSFOmiaTFnF5OXVMsLHKrMONg47rTvgWu2VAGyPdxbjUfWRRN+CP6FM+mw5mMHh5eTd+SB0zAGXHD+W165cJKDL4UvBNT4vBbacvKg0oheJ6dVieXi+ByXA0Jp3Xylfkg3w4lQNcEcYCOWVlzSdtHHNtTvQZYaMc/YlZfDClxxmWOv/jtDQcY7n0bJoHP4keeTkKT7FGwtsNXIOTyrDdEQfpvK3lF3LR+t5HzZUD3C9yQuUPftnczINuHJBlFsGaVm8AJZbhhRfWv+joWMOL+RTN1AKkhyS2JUCLrclk3vpPMFWJGeEZVXA6uTVLtNOcVBUJnysMqewMQXA8KTa11PqXnvrWnW0Mg2R4GucacHNk5OG+0fZoPKWXM+RCx3n5NybSwJqTkZM/8BIDMDEEoXcvDlAURKYvH49SGR7M81nQJprrnWfjhLgevE8vnPJuaZOp8pgvXdcLBg/dLzYpk/0J82DkGt52Hmsj4FgrlzcYwkA59JyZHOBzKvF7C5/Dbv6SKgkIFtsHUXgrQW4pdOMAbie6S2A25MbI3XS85Dv8d1QGEHxOGVIbirABRuOLJSHYAnRwg4iWqSVgK8X4GrPOWCreUmzPOPAKIkOplsVQBzCx91987gOC/BuKE1HAnCV/bPWfCX6Xu+pBmS9AJZrl4MFmKw7Tq4MlUsYZ54FLw9Q5VIMvrlygb415wq2ymMuL1fRm4C1EBCV/vWgWsB7FADXco3rDrhW4lb0HBm33BLw1dRpWiyK5dw/ygaVN1U/h7LsfrRcXk8WgmtOz+EvS0zQxcqW04t1UudY+t6xcvUoCkx7aQQDo0zgm9Elga/S6k4lADlrgznN56hTdcA1rLftpVtDxwNwyfrH6du1gCwbE5B03DJx7GFp2aHjXMYdwOYGgGhvRo7Y4JsBXEnrhQPAmAzVE8w9k8h7PMHAKLaO8+hcNyoYPhbbYKad1P0bkaoDriE/L/tjAy5Xn7LBcRQ09SPF83iGOTuSOj8+D4/ZoeMk8GS81xLAyqFsvmEfMZKOw+Oe514sSatQDbAMXiyz6lBp0F/E8/b+tZAH8JbO5zDQGHVGCV3vMpTI29S4UdZbUgdFA/wawnBDigEpym4qgGZsBNfG6Y+inK4UcLXn3FacZHBUTo7qFfJqMd2pgoQnELPSKu77hvRU676WAmdOKJbzzXrINDzp/edgRXxOXYcVP6xgmzrO7kc7yEwATik5FyC5JL156DUh+rn0qXMsPfuYAFvKRszjfiicdJiO5XlSoCf9XRnWl6pnM9O/T6YtmGadyOP9qJW2dBpv3VEB18GblYAXVo6Or8GWXBoOJkryY+1H20D6xnIKWrsCofJNypA+XOnNdgFbxJZUHvNCIE/KECJ1kPeC88uxJSF1vgrbpdMcNtoAbnldaXrvd83zOXFAzQtfKLzgnueO6dBxIkyMFYwLro3jHzcfTNZn4h4799wMtkT+UoAd8AgPXgO+HkBWkzzKXRp41+2ecmkDuDb7WjtSwLXwMDnnmHPOyTfUs+pyykNRdj9aKcBiJAFHKXFtS8qOebfccyvYWkLI0pfSpdJnTLBn/xoHRXHKJC2rJi2nLIcNRGuRCXALT+3RpLECpSZPLiXrE4UzoM1PU5+l8CDmezQ8UjLsOL2pQOTFagC2FLBSROXLvpaEd1sabHu8DNhyAThnm5NOA8IakPIk9/I4LTnppXtYaB2vtXSZrQOhODrWRrdEX+pgcOrXXN2tKX8OJ3I86X0cbirAXLbPcsGp1oX2j5uP5Bp65xEopVpKWHrLi8sFUy5PKqN017GiBPC5DgvweuuuO1mudR3SlnqWtQGXex1e10uBrmd+XCzIyanyrULHDC9WClqxXNPqoIhrW1L2AY8IJXNl4mNGf7GE15Mxd5dhP6/MAhbi3xHCxxYAtjRYOLpHgdYBNC00ZqPMFXCZdRImlzgT2XIw85XgDqce1dT1AN30HsHi8zEvh+QlgJUiKl9J62UAtpn7FNv1OpaGkHPXIZVRuhpQqkGe5esaJebKz9BPO7X7O1WqDbil05TS9UhP1Zda8OXYoUA5V8dr8IE6p6gBgBmnH5LDC/nSloblj5MPV8a6yYJ+WxPAKuQxj5Qx58KxXyzPQVHSvBnkYdvSMPHSPczkcf1HGXBL2PG6nx6NSgvuYOk4+VjreXJTAU7BqIuUgKOUJK0UKVDF6ZfniX5bLL0LwBpCyBKZBRjcgZKY88vORzDARFPmKegeRhr7+tcVcK06WZlDPRTLufWoNi8OcbHBkpdoP9pUQTTgVpK4oKvlrU7yYIulEwFslB8nTcwjZUKvlnyelXbiQbMnfi22xtRdR/KqBMfMv1a+kmlHowOugie9JxzQ5QB6/CfJE+OlZNS1kpsKcEGII4t1PP44+XBlnAYGF2wtLxb3pfUAXUzHA5i8fz1IbdNjOcZNP+0oNBZYW74hL92SgKshTn0pqoMjPoUNHHmOp63XyZWhuAXhXlyJB2e5uRyeB9hqj3s8xnKHaDlz6ZRebQkg7Gfct6wuh6DvmFUsQxqrzjqSx3W52HBYA7t2Wi8yA26hGRAUSUBWY1tTXk1jIbmpQKoAXF4s87wBkrRUuTg89nkhsMXyovSkMkxH/YFMNHysSeudZgO4622j1rPxbsRpdC02S4AVlo/1mjT1P1fWyScZOubqcfPBZBSPaoCUAltPHhtYheCIgVnpXwvVBl6rXc9rP2w09j3R5F86jZduCRlHLk1LlUWDF9xzDq6Ex0cqdMzhS1s3nmCbk/d4woFROVtcXXGl7+XVCsPHItPStMLlGJM6m37ayVzHWOWYEuBq7XDz4NZvuWOJXQpjOFjBPZeUN7+pQKKAFC+WSR+6FZRzaaWAyz23gq1GHvOksqSOcMAPlR/315PQPBTTfCT5edmdCgjVII9rHdtG7bSl3s2sDmOMg4bHlVN1Mcc+ZpdjS4NhMQ2m93BAJ5c5ByBjMOWAI1efUxbtDZaAbS5dLl/2iyscGCXRodJ4A2YNYPa4bm9dq86GVrTWgFt4R6Gx3kktuObqw9S5V/1D5UMd52zPqIviXljugiXgKCWObUmZqetlPwBGiFAFsL2TBtWL9dk6yt1q0oadnjYzfCwyqUjb3R+J/Ro6606H6Rprg/UYgGtJR9VpUpDN5YP95fS59jEbWFpT6JjD1xTWAsy5dDk+pWcFWy3ApgAhBxJiYBUSBnJevxYibTpN89Ho5sqxAdw5eb4Dh8FGKbK+b1IZl5cjLghyMIMCXE4ZqDo8JnRlKCpzKZildKStDSkIS8rIadHEN5dz4zlgq5EHGeCyKJ0GRDyBkEMl8tfY8NatqbOh9QZLSwPYm6T9szkZp76mjnO2NeCtqYcpmykea3pPfC690CQ4dtvyWf4w24YyW86lxxp5zJPKMJ2eruc8WOfwsQcAWxoeHF2rvaMOpp7XPzbg1k5bqjFZyo4XkFnIqwGQS4duKsABIUwv5KPASqThAGgOeHP2U/ycHuc+pGThtXsDbI/n7NViaWr9ashiSwymjrsebQAXp8N0/esOuFodDY8LbJy6noslkjqekz4mduiYe5EouCZ0WGAqSRPkl7PLvZ5cw4MLxL17QaRNVdC5StsLWJMgNeLqTp5APEgrmOYjsutkT5t+Q3myLL+4tOFRjsppxwBcbroS90KCJZRNDfhjvDKh4whcJYAqJdQ2w8uV3uz4nLrhA9vK/tqYl5QpvFqPF531Wzh8LDIhSFsUTBULV6wT4HqWdWq2xrYxdcC1vMPa+lWDLak03Poes4fxRCtDZQE203fKpRg0LTZWjDzgSm92fC4+RsBWy8tV3hZQ6Z6pFziLgNnJtiStl24NnXUC3MNM6/gcRO+7MfrDzUsDkJb0HvakeSan93DBpwewmbSpQkrBVJpmoMMAXO255diDF8skOtUqC6e1lDU2OGXRNEqmojNl8iz/VG1ZaKwdhbzzkQIuxePWnVi+GF7k9KVlkfCSK0PFCdBCMAFWAqhS4t5EDHBRPeQ81lcdEyFkipeVGbxayr7Xr4U4IfJBGkX+pC5zucqjAKa1aWqAO7YN10ZoZaLKIQVZDsZgOtJ7IrFBrgwVnzcAA7BiARyDpK0QaZ4pwM02JBLnVrBdZZ8GWw4vdz8koMICxAKDojyB2AKi3kDJeS59ZrpRpC3HlGndy8+hww641u+Fm5cmHylOcPKh6nCurQaEK0PND2iAoC5aA6bSNDmdFJCUBluNPMeLZTlw9AA0FxIuX1gaROM0Xnatlc1hBlxP8rwXU7uvRw1wJXUlVVdLSGNL02DgrwylGFQUyzStDookoIvyAu821sHOLa0nSaMF43FkFoDq/WYGRWl/NeQKvCP30x5VwF3XcktoKtd4WABXY79pGvSPsqF1nHK8Qeg4eZ4BBA7AcigG49SfxAYmz/ISoWTNQ5Acp0LIST0YUhYYCu7j6kGmchim+bjqOvTTeoH6USbP+zM1W6N9n4Iuo9LvsMTBwcCU0vEA+JwNOnQsGKkb6lGVixREpekwOXYdqesN5bG+x7GUJ5F5AqkrSAtXVdIAo+TD96okagDuYaKpX+/UyucFVCXTavOR1n+YjnQEdw5sJeDOITx0LBidi/FimQRUuUTZlQLu/CANtsUAlhlClsowooAzaVOw840rMBtseOsW0TlCA6JK01Tvj2e5xgJcr3ykMm59qp0mxQVbKS+WpVeGIkLF3IwkwBqDcepPYoNblizYEv22ZoANjjl9Bz39hGyg67CSUgnyAGDJNB80H+Y9L6WjTT+V5+hBU7+WqYCkJ6m+t4plkOaF1Z1cHNEuzCG5huHKUEioOFVIKajFcgmIStNJypY9J/rhrACbkmsfqgm4nH4tZLEpaoA42YsbpdK8rGWdSsU9NToK98XzeyuVxrNBitazyDr60jyp6ZZUekrW76MVTHWRAKwGVLlE2c2VKafXO4/Alro/ubyyZSEGRnFkA11ieznR8xC0/LL5GFeJkqTxsrsBzKNNns9oaramCriks2IY0MTFIk1DIEWrPlrFfNKQJ+GnKAbj1J/EBqcsGC95ToBtis8GWCaPU1mrALQieZRTA5BeH9VYgDvV5+lFJa5v6vfMY0ehsckbcLXpPL4dzSJCXJpZQFYLsBoQlaaTAi7rPAO2WoAdAAEzhCECKqZXy/plzKnVkMqWYTnG2EZWh2PHkn4zIGptaKr336NcHt+vVdcTFMO6HsOMWt/6jAOy3ALmwE8Kqlyi7OYAV3WuAFupPDcwSvJieACghlhArFwlylu3pI71vh9FwC1xXVP3HD1L5wK4lTY6kL7fEodMIu/Vy8J6iatDrgyVknF4IZ9bKOpPYgOT5Xip81h/fiADWwkA59JSOtl7NKHKxtIA8PqQXXUEA+Y0+W9oenQUntsUrjFZNwpnxXDtsvJWpstu/M7x8qSebSiXermSdLmyUTzuPaAAVJpvj1fIq3X5dQ4fa9Jq7sXYOrVlG1ov8nyWY78X3g1irZ0cTqB1eYHuJHTjdw7IpjLKXZQEVLlE2eV4skCcJ2WZ/kGNh1vFq61IrHIhXrboWjzm0yZ0OHa0tAHVcajE/Zv6M/Eon8WGF+BK6tnuPJZz6n0NcWygG7/nDHGAK+RzvD3OH0U5XSm4xuccoKAANpdXUmb0agdpnQZFWUhjS5JGozvWgKh+gqlX2XXpKN+NqV77JABXubgERy6tpyWU3fgdaxVQBaGAUQqgWDpOHil+To8LtmElbQXYHDhYQMYTIAf5ZMLHYlvCtN66VsDUpi8h29CGUuT5zkwCcBnHXNvJetcB0ENCN37neHscXiwrUelz8uXwUsc5GQdstTyJVyu6pxU8J0v5inuvSh0yfaEBURvA9acS921dbE6FSjSsc06fxYa2PCG5hI5zPM5FpjxV7I9rh1s+7NwKtjldbvk46bhpvH81lLRhWMIwtjEJwC1k+zBXujk6qtddijzvp4ctUZ0m6OKhnClp3hr9ME02dMw95/BScklLQ5qWWy5XsFXIWTKBV1urYmoAIBU+FttgptXoinSE/bRTAsUNGB1umvrznUL5qPqWknl/z3EaNHQcn3NBimphJOXdlnycP4ldhF8CbLvrkABwzOM8bJeXumD42AL8xcG0gM6UZBsan9bl+UytnJp6wiOv7LemqCexFPTG74iMAqtQL+k9BH+xl5r7ywEvBrhYeXMNCe7DGOgwQsgcuwPQcdwP1vqrIQvwTkVHm54tMyySviE5be6vL3ncT2v9gNXzNYE8RbMUk+vRdeccXg5YJZQF3lz+mbJi5x7HFI8jw3TGqig8ytFL69BPy9mf1gq4ZPqKU3Q2IHH0qMQzn+p75AGM3Lrdgyh75PSenDGWl5YAV09Kgm4ko8roDrYMz0QDrJKKnPROvTaFz2ztV8p7LQ6YhvRTkm1oQ2OQ5zuptWVp/JdIY5reE5/3eBHA5ij2UnN/HDscwC0JtrAoA6shkpBpvFovL7eEfQ1AWsGQo5NsFFrSjyg77LRu175u5T0MpK0PaoCyeHpPDFoagJWApyZtDnCTehm55FjLE4GvZ3jSYZcOt5eUWI5RbE+g49U4qZ1vKVsbOnpU4v1xfb8V0bzuOIcTtUg0vSfrBRIAqwVWinJ2U4BLebcasEXlyChkq1dLpbH+ikk5zcfdezWu5jIlb3JKZdnQhqZCmvold1wy/5BE03vQDBkAm6PYS839ceygfOb2StKbmU3LXDFIosMZ+GMhDyC2pBlbZ1TZZuTxhjZEkua7GPNbSo46BmCCbODFptLnXHath8tJmwPc2LsdyB2OOTyOrMqLYZgrNqr36qSjTY/KDEsxSmkDwkeT1u25r1t5SxDZRxsfhyCbAjTKq/S+6Tm7WPnmB/5gi/KIgVEWwCr1KyE37xXx5qzAJUo/4i46tQB6Qxs6SjSFb4c9vScOb0kBNkexl5r749hJ8ZN6TmCbk3M9XUwHtVMYEMQAnJnmI8mHoyuVWdNPSeahv6ENHSVqxy4AMKf3cEA2phwwSsBTk5braXuBLQuAmV6th0cp9lYN83Mlabx0syA10oCoWt7oBlQ3tKH1I1HomAOylGfrXVHk7KLgGp8bwFbEE47OJYFT6dWKgVhgy1tXqzOWhyuljWe7ISlNwUOTUInyamyOed/4K0MlpqpYPdtYh/PHsZPik+cMsMXy1PJimQXwPEldHmVDoqRO7XvpAt7Om05vaENHkTBgtQCuNm1v1HEutJjz6DDQxexJwFOTllOe1Dm1rynVIKF4sMhDA6ikdyv8HWbAr9w15WbrFFq4oqqMGHkspQ2obmhDc+IAXRsdtzB+FGCbBBUGyObOKb6VQrvxzWwYvPC8AYC2aQDadsgnjjl5pmQxxbpkmkV5pSTOh2GDo1tDJ6QPvmYXDuAAoG2h++9QkOKZT5maZgYNNABNAzOYwV/9MDrzcED//O6D/jNuDwqWNKBFWbvff/iRrTr5FqDuO56qzbZt1V1lqM2Kabe7gySYOoCsV3iwo9wFNgkdjOcFtphNjDcXNNC0rRnoSpAFgDUNCaudpKxpoF0A0QEcwO7+Vdg9uAK7B1fhoN0nLI9D7SEDTi51DZ9ZswXHtk7AsdkJ2Nk6kdDD64n5M74C1w6uwLX9K9We8ayZwbGtk8kylwCuo0iS+xjqYulSX1kNwN0GKAOy2nAcRXHa1IVKPdn4nAO2krxCnsWrRX8XwMLV15DEw44bERy7UhlH54Ov2YX9dg+uHVyG33/yV+HS7tPiSljjAZfxmv1sakBde02cdDOYwVazDad2roeXPP9VSaDF6OfuPoD9dg+u7l+G337iYbi0e4H9jC3PdgYz2Jptw6ntM/DSm24VlVlL6wLeHuXUAiylZ5FbqBc61oAs14stHTpOAVvM9wBbVDdhL5XHSjCeV4sCsCAMXcrThUQ5NID7gdfswkG7D9f2L8Ol3Qtw/urjc6AFPtDqvcxyoISmrVzWeUrldYbPtmlg1mzBia3TsLN1XGzrAA7mz3jvAly4+jg8u3sODtDQsQJYkfs6a7bgxPZp2J4dX+vuiHUB7xSlyh57tbm0Gpk2zTB0bADZMUPHXMBNnXPAFpUn8qNAVwOoJb1VKg9JGo6uVkeS/gAOYPfgKlzaexp+94lPw5W9Z2H34Cq0sKqE63l2dkDi57Re5Zs1W3B8axt2tk7AV/2Jb4Kt2Q7bVujN/t4TvwKX956BvYNrS49W5bEyrqlpGtiCbWhgBl9545+H7YZf5sNMtT1ZSx6p44Ge6v1O03bMqAGyJUPHOcDNAiojX20IOefVdiBuBtDI+/YE5KLeq0KHSv/+u66tKuAnfwUu7T0N1w6uAEAr/nhqAZfWI13n8jXQwKyZwfGtU/CS538znN45A8dmJ+YDjBi08mafhot7Fxb9sweie6K5rgYa2JmdgFM718Op7efAztaqzCWAYuo2pxAqjj1Zz/vl8YX1+2gzo7okIFsCYDHyCh1nj5kh5BwvltUOF1PlWAnw8DG7zEFYnFMGrQ4mm1fAV+Dy3tNwafdpuLp/CQ7afbJSXTdvUJJSnKJC+ZpmAVjb18Op7TNwfOsUzJot+M4Pz8hK818E3uzvP/mrcG3/8vwZQ37EsfW6Zs1s4YWfgj/3vL+0LPM6jzgek0QAKxh5jIExdl66Dl710WZCxpxjKU8iD0kTOi4Btildq1eLpZH+akhjo4b3ytEJZe9beLPXDi7DH3z538PVrgKO7vHUQWue02EE/i6C0wHWSfiq530THN86CU0zg+9kTOv5F3cfwEG7D1f3L8GlvQtwcfcCXN2/PABZ7/vezH1wOLZ1Ek7vnIHTO2d63uw60FQ8WasHm5LFet5fj8XePHTsALJTDh3HPDXYJvISA2tCx827ZYaPWaYEaTTXnNOZn+CedY5W3uwzcHnvGdg9uAL6+bNTB615SnGKCQB/35u9Ho5tnZSFjA+uwMXdC/Bbjz+0jFjgg6CoEvKuaz6d5wSc3rkBXnrTrXBsdhJmzRa8buHNTjm860lTA1iNfcqbzX0jmq+A3Ud72ELHGrCNgSzOzwIyNamU96rRlabPyYberLQCXk/QIlNNDvjnnmHszf6VIGSM0b+8+wD22l24un8Jfvvxh+Di7nm4tn+Zma/+upplmU/BS59/K5zeuQGOCxoHY5MHaE8B+FPh45QnmyunVx0ssbNN7SqTO+acYzyOLEWeoWOJbMnLhJBjO2xvMDPVp0b4eJDWo5+W0PFO/5N3XQum8zy9HADlOdUDYIqgFaWYPPA3y4UeTi3CrylvFqssu8UpLu5egGd3z8+7BgDvf/e6983Smw3K3GzB93xka9Ke7BTAEcDPk8X0uGAbvw2kZ8ssB0XpebQITwqyUwodSwA1lScJwIQt9zAxRkT4mGVCkAbVSYyoFqVn6nSyLpx4ae9p+N0nPw1X9xYDoKBl5JCm6YPW9IE/zm8GM9iZzQHrJc9/FRzfOrX0ZilaebPz0eTXDob972XufQMzGA6A+p4jMgDKAtZeAKspA/VUMXnqm7ICbn4JxgxJAFhiV0oSTzbU44SKNSHkOH82wDGm+nhQqbBxDQ8Xo/d2IeP9y/C7T3waLu1egN2lN8sMKVYF1XlKcYp1AP5MugYaaBbTeV56062q6Ty7+/PG1KXdp+HaYgCU/Pok+g1sNVuBB35DsQFQU/NkpwqwYfg459VSeebOuem4OvgSjIrj1DnGW8qEC0W3AMmwJubJpnhqgA15yEIWGq+WC35VwsYM3ZI6qQYNla4bANXNp7y6fxn22/1sSdbCE1yHMgrSdf2y8/mnq+k838GYzvOvgr7Z33vyV4T97/pGzaxZeeAvu+nVywFQ3+0YMp4cwBoW8B/Tg+Wmy4FsPzrCt0FRbzCUN8iinq1hF4ZmbmB5HldGltAxN0RM8WJZsTAxli+y9jErbafL6Kdl2VHqcGU/EQyA+vyX/91yPmWYei08wXXwqA3XNmtmi37Ok4vw63wA1HcwQsb/ajGd59r+Zbi4ewEu7p4PIhbDUmrLGFO3POTxrVPwsptuW7sBUDXJC2C56TCvtjsHJI96X3Q/XXKbvFIg673NUWgzBbheYIvyFF4tptvZ4w6K0pClfCod5sIVWvqJYADUxd0LcHkZTqy1AtQ8pSrVIfNWl2kQwOq82dPb8vmnB3AAV/cvw8Xd8/Bbj39ytQAJtFDy/s/nzA4HQH23U9+s59ZvLp6swoY3wKZ0LOk4ZVoeM71ZTR7JPtoUjwuyUoDVPNiknQTgeoAtljbkacLFVvIMG3vpenioElk4n/L3nvz0ogI+IPcjXQdQnedW0aOuAFinds7AS266dRky/nZGyPjnFyHjaweX4bcef2ix1OLl4v3vc292BsdmJ+Frnv8/Lsv8DwqMMrbQWADrTdwyYF6txEaoLyFLKDnbR5viSUAWA1jLQ02FCOI8W4ClpxmHkinwTeWXBV2DV5vOEA/ZspJH+Xt5r7GutXxW2Y+HA6Ce/DRc3L0A1w6uQGoJvk0I2C8/6fUtAWvr5GL+qW4A1MXd83Bx9zxc3btUpP8doH9PmsXo6Hl/8vWuA6CmAGwAtnJ4ebJa2VJHCbbxG4J5s6k3SQO4rD5ajCcFWe+XCwPdZl4A1LvFKnRJCDlOo/Fqtb8sUmw1N9BV9tPW8H67AVAXdy/Apd0Ly75Z7epANYH1sIJqKr/VdJ4beuHXb/8wvQj/z6cGQMEQZL2fQQPzkcbHt07B1z7/L/e8WQt5AmwtkLSk1eaTStfzZAm7Yb2d4g/0Ge+PFXBFfbQsncQCGLmb4hY6TsgbJthqQshFvVqCLADs7b1aAZekBNj/494KUP8Oru7PvZySK0ABHG5vtdzuPN3807+4BKxvY6wA9a+jAVDPXlssTtEeFG3cdGU+tnUSrjt2A5zantZ6xmN5w94AS4EpZasHvEhfN+eJD9dAl6XnkrmPVgOyRUPHET8VSrYALFam1nPgjzJ8bAHeYjrEfdEA9XI6T7ACFN4vuwHVZLoK19dNjTm185xB+JWqjMMBUL/5+CeCHZh4jSltd0ETrGf8sptuWzYO/jdD36wHOI5lowbAepRFM7AsB7K5MnB4sQzto5WCbHyR3gCbomzoOOB1QCgBW2DwaoaLp+69cnQ8ZD+23Gv2Enz+y/822B6tZZQuTRtQ9c0PoIUGZtCNNA5XU/o2xnSefx2EjH/z8U/M1zM+GO7O41HOkFY7Cs2n88zn+uqn84zlfcakAljjlnQSHcqT5RwDrN5zTrnpLTPTx1JeR2gfbYpXAmQ9Q8c5kOSCLZqW0CsdLo6JlZ+in3ZgN7ONX236scV0nvn2aE+vBkC1MpDdAKtvfmnAmiVXU+JUyqsVoLot8Pr7CZd6Dt2OQqd3boDrdm6A49srb3YsKuUBeqQpDbDaMmCAy92RB9PivnUpPbKPNsWTgKwXwKbSpUAv5nPBFtXPlGMgQ0K+Km9VGD7WeK9T8FAlsuV6xrtPw+888curtW4zm32PDTql85vi9TVNM+/j3Lmht5rStzK82X8TeLO/+8Sn4creRWH/O7+cUamhgRmc2DoFX/O81XSe/1URMvbwZGsDbE3ilo/tySL2uN9GTouywH3L2H20KZ4UZL0ffgpYOz4XbFEdxKbEq9V6fusWNq4h+9FgOs/vPPHLi5HG/dWBpgg6nvnVv755ahktNkefnYSX3vRq8WpK4XrGFxdrVvP6ZfX3tGlWIWPLesbrDLA1PdkS+lrvPcfjHHN56H60mAe7YuIgWzt0THmy8TnnGLMT8iRerSeJgJexAUJs11oud9tN05vO061nLBkc01FtULXkuTYNh6CcM2Q7ubsZI41Db/Z3nvjUcjT58Hp872cDDRxbhIy/7qbbe97sYaeaAJuSUTyJJxvW4xRxwdLDRgvRYChRyJhxjNnM8SmShI5T58vjYOpPCmy5oJsqX84bLRE+nor3ihvMXweV3313Xl0OgPr9L/8aewSq1ZNrYLaI2swXXdB/woxUqfvDyC59je1y5aSDFtvdxh/8w7WBw9WU7maEjH9hMZ3n6t4leHb3/DxicXB58YzLNVSWZd4+BV/3gttV6xmvoyc7NsCWyCfU6SiHF1ia+JzyZjk08GgBZCFjKch6ho/VoePuGAHbOJ0kXLwwbPZqPcLGbjrCAVHess6bvbz3DFzeewau7XuuAAVIrs1yqsex2Qk4tnUS4slrnqs4e9lq28X804MrcG3/Clzbv7zMQWePl24Fsifh9M4Z8fzTbjrPpb0L8JuPfwKu7F8k+9815RyUu1vPeLEGczcA6n9h9M26AGylnXI0aThl0wIsVY6cJxvrAUOeI2u8hNOMXQ6G4oKiFmQnGzqOFrVIpQ151vCqlWp6rxydErKQMG+29ApQyxDo9hl4yU3zDcp9m4laypf/oD2Aq/uXFvNPP8lKs7RsCFWvliw805t/+lpGyPgXgpDx57704HypxeV6xv5l7ajbUWi+AtQ3w4mt00uQzdvYeLDa8qfScUCV0rGUhyunPNscT9ZH6wiypULHGrDN9WNywML7V0ISoHQPCReiriz33Xk1mM5zYTkAit8vq72i1YCel9x0K9xw/CY4vnVq4NFOjVpoYe9gFy7unofff/JXl7ykriHiEtucNTPYarbghHL+6WA940Vjqnt+nmXtUzPfH3f7eji147ueMV6e9QZYrR0NOEo9Ysq7Tenm+BpvGKPBghUx5QA1xZPqWwjzZEOe1GOThIvzRvXh414+zBWnsmUTzKedkizcnee3n/jlaHu0mOweTkezYHu063aeCye3nwNbzTb8g49u93Jqo+OsrG1RfdJG8PxzNn7x7j3YO7gG1w4uw9X9S7B3cG11nUUHVjVLbzacf/paRt/sL4YDoJ78FFzZvwT7B3viQW78snYlXvUnf+3zv3npgf/9TMjYC4ikVBpgveyWaETkPNlcGm0ZODKJF9xR70vIhpERbzaVPqXTYHaFf1i+XMBHjzObIHBenliX+tWQJK2kzFOQxfSeO69CuwiDhtN5VoNj4j8etdF/wzJ2fbMn4auf9xeXG5R/90eTwxlcKjPSBqMP70PdYKJu/mnXxylYGzi+NxzgmgPWbLAA/7cwQBYg9Gb7+wmXKGu/zPP+5G46z7GMB+4R6ZlKtChFVs9NKtMAFSbzejY5u9r7E/JmWXBdHtAhYwpkU7Y1lVQOdK1gm+PFMhZwMvbh1QCwpgGgpdQ7oLJNgEUsnQ+Ami8oH4YTuYNjALSVcQPHtk7Aye35+rxhBVwFVBX0S8GI3fn9uoAOGAtJC1RhA6dbTUmzndwvBo2DuTd7ER1Nri1r6h2YL6gxn87z9Tfd0fNmvckCBJq00qdI6jBXU+LIKB7nGDv39GItni2WFu2jTfE8QLZG6Bg7x46XupmBUaxwsQMl8zNMj+HolLg2S373LgdAXYbPP/lrqzmzuRWglFcQzwFd7Tbzl5be7Pfcv6Oy7XFfk+9pxItH7MZLFgLo70/+CuaeYbyaEseb/aVoOs/F3fPLxoFlBDaVNgwZf/0L7shO5ykRCi2VVpKGo6stPzed1D4nbBzW7Rx7HL6mIZCyifbRLsGV8GQsXi1HFlPqonLgGp+njnu8BdhKwEv7yyFJmqwOY+GK2rIU3RsNgLq41+01G6wA5QCqg3I28wFQx7dOLqd6YN4ZB/w0pLHxi5kF+MtueL8CrPles7LVlMLdeT73pQcWSy3uiUaTa66v21GoK3PXn/z3gr7ZDcD65cnRD+XYscSuV5PSMxrB76MleNrQsfTFwtLFPG4YOceLZZowryR8zDJXQcerUaQpQ28A1OMP90LGkrBh27aDv3xZ5gOgTu2cgZfcdOvSO3td580q5zri+flQuAD/fM/W+WAiHmC1iT9GqraFbjWlU9v96Twib3b/Enzu8Qfh2d3z877Z3HSexH9sattFI7NrTPUHQP29Rci4RsQqXTx5zt4hYqsdTahYmqeHPU4+1LnEs+142a+C8mZTPE7o2BMspIDKyae7bt+qlSYJ8HJ0xyq/VNbRu4MBUL/9+EOrCpjqaxSCai8ttIvFFuYDoF76/FvnSwfO/KZ6lHoOvT7O7JKFAFpQBRje3+XawMrVlFb97+ej/vd+qNsCqr2/BTUw3+ygtzzkYkchK5WMHWjTeOlq+2kpPU0oNvdmayiV1urZpvQHC1Zkw8gJXo644WMJXxo65hxjdlIyr18O9dIYlzGciiyn3xsAtXchXQEXmFPZQBOEE1fr876O6JstFULm5hUuwH9p92nzkoUAvPs7B6zhdnIcb/ZDvfWMfxmu7F2Eg3YPDgSD3KIC8/Sa9HSev2scAGUJFU8hn5zdEjKOPNaJ9amQMec+YW8N9TZpGgcAyBKMAHmvjhMytoRqcxTf8JCvBdtkhSnoq6ULPQRJC/Bqdcwy69KSmTnB77rz6qICvgy//+SvmleA4npBYTjxzz3vLy4r4H8Ygaz5PSC2UJTm9Qt39xfgly5ZCKBrtITrGX/t82TTeT7UGx19Hp7dPbdoHDDLoX33mga2FmW+btE4yE3nYRUF9HVYaXCWAlnJfCWgKwFvSldDEq9bam8GYAixCo+7cyq/RqCXs60Bfk3YlhMVkNrk6MozoUPiUttetnre2d7TrOkpHen771ZTPU7tPEc8PUVKXhXbv0mM2N09uEIuWWgJr6/u6+J+KVZTCgdA/caXHlg1plLPORMClpS3hbYXsfi6F9wBxxdLLf4dhTdraWxNIVRs1aHAiMvjeJSckK5X9Ih7DSkZ57p6Hu2ysmd4s1qQTdGSn+sTXnxoqdZ/zHcLF0derTYkOjXvVUslwsUAAD8ceLO/9+SvJKendOQ7TaWBGYTTeebe2fcqp/P0LZcJIQPEI3YfrLZkYbyaUrc2MOXNtgDwkcAD/43HHxiuZ1xo5aquzCe2T8PLb74Trtt5rnh3HitpvEdJGi8PNuslFtz8wOrJSkLGKfscvtSzjfXR0HFIOW9LC7I5cE0XIgD/RPiRGzrG9ENekUoyCB1K8unpCMKPJWVSytn64cV0nm5wzHwFKMv0FMjk1i/VVrMFx4LVgTjemTbU60X/JjGdpwMsKcDqVlPST+e5tn8Znt09B89eO7fomy2/n/B804BuytaqP1nqzZYGS02aKgArlGlDxbkQMjdsLAFcideu8WxjGqwMxRlxKwFc9LxpUJAlQ8dNs5j3yMiHUc7stUb3o2TYuKTOFMPFAH3v7LeeeEjRN9sm/mhazac8Ay+76dVwbHZy4M16hXo5RL2rHaUX4KfXBrZMj+mvpnSmtzl6zpvtcvhIb3R0sGZ16TLDajR5OGXrbwtAtnS4d5lGFBr3Ic9mrDT0qsmDK0/VCJwaIiXTeLYpHdKj5XqzGG8AbMKl/LAwASxsxR4u5l1QHm6sZ/VSNGFjjm5N76l0fvcsQsbXDi7Dbz3+EGN7NENINJzm0cygGwD1sptuU232bSHVPW0a+Nev3Y8W4L+YDLF7r6w0gxl7NaUU9ZfTXCxAEvXLFlkNqmng2Gy1AIlkANS6erCWslDpueFjytPlerIcm5BJIyFOQ0HiBcfUWxmKcxNTwIulokDW4v0NABcBW24IOVv5OWzkHudn1Z1CuNiqP/DO9sLpPD6gmi7HyjsLp/O83tg3WzqsHC7AfylYz1i9UhYzXbeecbyaEmek8Uei6TxX9+crQGl25xGVedE1cHz7lMibtQIUl0rlUzJUrNG32CsRMsbSUnyuZ4sdJ78USTgUA9wcyGbDwoGco7NiNKyy5HixTPuLG+7fA1YaQkcsUy7GsdRn9qlTWu8MllpcDoCCbnqKIIwmXQGqWe028zXPX63P+wYOyDJ2sCpFP//afTho9+HK/sVl+FWzZKE0DIutpsQB2Y8mpvNcZe7OkyqvtE95Z3aC7c2WDHNaiWPfqiOVaULFHECibEpDvzk9LshK5SkSxcq4YWQKZFNpMXDNyQb2GGCbs+FVeWrssXUz/dpm2zX0F89osNjCfn56CoAcVHtplxX1vALudueJB/RIG2XelMqrA9kVYM1D7KWXLOyWLUytpsShrv/92d1z8OuPfZwcAKUub6LM3Ujj0Jv9W8yt+9hZFk4zSYBNzgTIp5WWkROypcqd++OWg5sX53i1MhQx6CdFLMBlLnzBpVTouBeey4SRY31OWG+pa1jAQpOfVKal2uFiAIAfWk7n6XuznWbJ6Slby+kpf1nmzRYg7r3EpvN012rp38x2iSCrKXG92fkzvgi/8aWPzxenCBoHpcrcNLPFSONTy5WrqL1mpfVQ6TTW8K8mT490nLS50HDOTkrXEjJO5cfhSxsQHbGbeFxvtsdDQDYXFqY8WMxGzrMly5n5zeUv0afKIdEpIaul/0N3XAmm83QL4a+mp2gXUqC8oM7LObZ1Eq47dgOc2sZ357GSp1f8rzpvdjH/NAQsz3WAhwW2raa0ms7ThYwvLhenKFZmmD/n41sn4bpjz4WXv+Cu5eIUsTdb2hvVpLE0MKV5SnOyhoo5OpQnaw0ZS9Ny849lqePFjtbyaiAFMD1eBmRTtnKhYW7oOAZbKs8SRAKvsJ9vnUE1RaF31t87tdxUD4D+Zt/hbjNvdBgAVZJSC/Dvc9YGNq6sNN+d5+R8c/QX3LkELFHf7GJziKt7880OSpd5Pu1v7s2+/AV3zddhjhoHpXfK0aQppStNzwVTbvgYk0vKIAU7bniYAlhJOTjPpD/qmPmbIgzkUB3CHpUPFjruHQcbuXPCt7HO4FcRPraGi0tQ6XAxZuMH77iC7p0akimsmEjbBNNTXnbTbXBq+ww5PSXX5VCL/mUwnee3n3g4GpUdkHOoPdyd5+U332mbzrN3IdjsoFyZAQJvdue5i9HR88bB31w0Dko3iuZl8w0RS3QloVhtOTiEhYc5x5zycULGFg+X4mk8W1XcjBtGRr1NJG3H54SPc/Zy+YY8Tdg3Z8eqe1jCxZiNcO/Ui7sXeotTaD3V4V+iPMH0lHC3mTctvNkaFfCiIGzVfxkNgOoaJQftgcnro6IC8zHGs0XI+LnzJQsF03mS3uzBYjqPosypcqdotXLVaXjpTbfCiQXI/g3DAKgpeKXWMLCnjOJ5NY81eVsJqz28PNsZNrdV481iIeP4OAWSFKjm0mH5QFCeWF6CNMCrkilGHvcV02F9MplQP6QfXPTNLneb2bs4DyeqNyjnxxQamMGJrVPwNc9bTed504gDoDi8MMTejdhdAhaDtKH2ZrGS0nWWkPHeJXj22rlF3+wlUeNJU+5wech5f/Jz4djWSfhbH2atMJsow/hkBVjPfLnhYywN51hdDpDVBlh6Thksnu1gCUaKsvoMkI1taSp7rjfL4Yl/BV4JqskEf8+GgSuoKubSxtN5dg+uIKChBVRITv/pFqc4uXM9nN5ZjwFQ/2I5AGo+YnfpzSJ9nJb+6zBNt2ThfAUo+QL888bBpfl0ni99LFi5qmy5oWkWjYPnwstvfs2yMSUlTWXt7p0yvP0SXq5vZ40uLQfIqOvi1BgcPek1UY0JXZMvIE0YGdPH+KmLjvvLwvPueMkLpvx49bMN8mDoelLOpjQ/j/LlbIR9s7/zxKcWA3pke6fGxNqgHNk79fsKrADlSf0Ru+eX92u+1Kg+ZzLtYsnC63ZugOuOyULGALCMWPz6lz4Gz16bL07RNQ5KlTtcHvLlN9+1HB39Nz+8zW7oUH2E1jQc3Ro60utM6VM2QjnnmMoTKwMwyqGhUiHz3hck9e56JJgv6xk6pigVQsZ0pN69uiyVZB76Vhvv6ELGwd6pycExGdIsVNGB7HyxBd5uM55eqZZ+LpjO89tPPNxbsrBkCBZbspALsh++e6+/O0/gzRYNHTer6Tzz/uTT8Lc+coyZl5y8PVgvqtkXu+QF36GXB8g51+aZI8zD1XjVqWP2xu8p4nqzGF8bOs7Zy+UvBVRUnwHaHLva9FyqDaop6voaL+1diBZbGAJtClAtG5TvzE7AdTs39HabefPHjrlcVykKR+xe2r1ArgAFYAvBhqspSZYsHJS73Ycrexfhtx5/aDlntuyUrXnjoBu49bKbXr0cAEVR6Sk+7uHkSjIPoInlXM+PA7ZYWWQdTDy7qTJg5crpd2QOHQPAwJvlgJ8ldNxE/FTYODwOQ8gemwMchnBxDRtvD0LGn/vSg3Bp74J679SYcpVyODjm615we/XdebT0c/F0nv3hdB5LCBZ797vpPPGShRJv9sres8Fo8mHjwFTuhYVBuWE+cOvU9hk4tT1vHPwNQciYm2uJELRXqFhK3jbDHX2k10SFiaWh6/AN4ejkSAqyOd0WEtN7pOFjrlebA1lu6FhrP5VGFBZn2srpDAXp1avIdJ1MscgI176XjXh3Hs1m3ymvhwyDNjM4tvBmw91mOm+2NnEiPv88mM7z7LVziz7OS70VoDSeKmdKTbee8ant6+HU9vVmb7ZbUEPrqfb9FMznWK1n/HUvuI3lzY7plUp0rQOiLGFcLk/r1XLykZQjl47zFmHpqDylnu3ya1JXvIyt7yiQZWdFpOeEi6UjZjXA6ynzoDFCyG8Pp/P09k4tsxD+YOTsdn993rcUAFnPPt1wAf7f+NLHF4DFWE0JQASqwwKvVlMK559K+2bn3ux5uLJ/SRg10lSHzXJBja7/vfNmsRwkpSlB1hAxR2e0UDGjr9YCvLmQsRdJQsgaz3ZbAyQST65U6DgOE1A6VpKEoT1DvMX0leXn0NtSA6AWe6cC2MOIWPoGVqARVsDSkHH2fXLcm7ij/2cZMl4twI/2zTquqLQMGW+d7s0/1Xizv/n4J5eNKbxxYCh7cN3zKUjz6TzfePO3wImttDdbIvQqtV9DRyvTkFd4XBJCztnihIupMkpkWs822QRkA6pgxx+u55krDwWuGD8GSeqXQ95ArrHpoV/iOvq7zTywWJxCtndqRxJQ7irg0zs3wNffdMfSm31rMAAKu/6ffs3uHCDadvlbi64dXIGr+5fg6WtfhmeuPcVe/zlHnPvWLVl4eueG3vxTrjf7oddegyt7zy5HGvcbBz6gOihztzzk1mn4hpu/Zdk4+J+DvlkNuHgBiMae1o6nTAJuKTnWV5sD1FxeWHmAsBESlp5DKs8+I+sBrXfrjwOoGo86vOG5YxRECK9EArxa73Uynq2QKLD+gXAA1OMPwrO753vbo2Fk9XLDDcq//gV3qNfnvbZ/eTFga99UHhm1cGXvIvz6lz42DxkLVoCap5bfu3DA2Dfc/Jrl/NO7maspffjuPbi6d3Gx1+z9c2/2YA+kc6Olg+K6/uTV8pCn4W8spvNMAWC98g6Bq2R+Gp7lPkg82ZwXy8lfU6Nww8eU/diz7W0qwCHMe+V6sxRfGjrGjjHSAFBJwB1D38Uu0lhJ7TZTa+RsOGe2GwD1Vkbf7E+9ZnfZOPiNx+ah21JAm7r2tp1HAK4dXO4t8sBNr8l/fr9OBPfrNHwrc/4pwGpxiv/02P2rrfuIsllHmjeL/uQTW6d703lUACsAsql5ux7eqkdesZzj1VL2U+eQSE95t1LyDCGn9MnmKwqgxEuaSpcLH1tCx5JwMVeOlWPdwsU17f5AbwWoX16MMmZs6YYRt2JGNij/fuYAqOVKTNfOwbmrj8Ez155CgdY+TWVupXcWhKu731L92ACr1ZRiwOJSN53n2d35esZd10B4Xd7Tt2bNDGYwL/PpxcpVx7ZOwncJ1zMu5cF6AWyJUDFXXwKqUrJ6sjnvtiNN2TTh4BzIYrroW1oyjJwDXI4NVbh4YCztkXHsLGUJGyLPlhnCthAV6vWkDrAu7T693B6N1S9r9XRgvp7xqcV6xpIBPR8MvNnfevyTcGn3abh2cEXm0RacE1wk/WI1pVM7q/mn3JAxwGoA1Oe+9IklyJbuT4YuZHzsufCKF74WHQCF53H0ANYrVEzZ5ni1VNm4YAuETS/ihpC5nu3g6+K8YNzwMRUa9g4dp2ylvFYJ0GhDwmN4qqUAlJPX9wfe7G8/8fBqzmxcImdQWg2OOQUvef6rlt7sDzC82Q++ZjfabYaxPOS6gWpE2tWUOuoNgFLuzqMq82LO7Dfe/NrlAKj/ibE4hTVMa7FrBthMeLsmwHLDwFRZPLxujR0JSULIEs92CbSc0K324jiAagkdxzwu4HiFjUcD1QJTTdC8MvK3BtN5lnun7gd7pyqIO2q2A41ur1mJN4vNXW2hXXtATT2xBlYrQHWDibQDoP7TYx8ll1r0ugfhaPJuANR3CfqT+fn5gKdXXmPb9PBquWmw/KiQsdf1SgA2xaM82+w8WlSmXOsXA+zlea7ft23RCl8NXBFQlfAIp+ypeoWVU3unSqanaCtkbO/U0JvFrvH9y5DxfLRvb+6qYmNyC5UA1RSFI3a/QbGd3EG7D1f2L8J/fOyj8/u1dwlakG0akCKyPxnm03nCNatpm/XDvxzdkmFkrr5nqBjVdwohdzxAbMTOl5SoN9cKsh1l59HmiAoTc8LISz6xP2sb6HTb3XW6lFerCRuPGS6uCaoe9NZlyJjeO9WzQp4P6LHtndrbbaYb0ENuaL0eoDqk1YCxl9/8GpU3e2XvWXj22jl45tpTcHnvWTiAffHcaPHGAYu9Zk/vnIFTO2fg+PYp+OuZkLEIEJ2n0Fg9Si3Ajhkq5upKPFkMWDll8SLMljSPTl+8qYD1tWzi48z2enGaDnBTYFsifDu1cDHXbqm8UoTtnWoZHAPAqJCRvVPfxhlp3DTR+rzzKUghyK4voAYWotWU4vmn0uk88xWgPrEMGVMg69OfvFjP+KbbswOgvD1YiW5JL1XbT6shdagYOxaUXdIIAKKcFvIMIYfH7AUrLF5uKi0XZOM0KbC10FTDxTXtaukt0QCocO9ULmkHx6T2Tn07czrPT951Jdpt5tJyEXwNjQ2q1FSacMCYzwCoArvzxKP3uzJvn5o3DhaNqb8eeeCHFWA9bVpDxRbKhZC1YNvxwamMoT2JnBMy7ohcsGIgS7RQJEAZ62Mh55DiOLw2XJwEqkU/rTpc3DTmOYPSPP0yachQaU8d+mWS7J3q0ixq2x5oaAZAAej2TgVwuobCoBpT08wHjJ3YPj3fHP2YfgDUf3zsI/OQsWVuNADrneuWh7xu50b4xsR0nnUGWK9yUPolQFd6TJWTC7aA2IyxQUKcL4kbQs56tm1r24/W1JpIbBOH2Ysr+AYAWoNXqwbVjMyS99ieqqZMb779Mrp3qrd30y9XsD7vC+5aDoDSe7PpxsHUvVReCVro9mw9vXNDdgF+jLoBUJ999CPwzLWnFstpMsumvYblAiSn4Rtf+Fp4zs6NcGzrJPy1ReNg3QFWHUZOyCyATtnzsh2HkDVgyymPZx3KBdgUL6WjWrCCI8v+MrbWS9nN3cis16q0aSWW/YJTdEqB+ptvv5zdO5VN0usOVoB6+QvugusUG7pje6faaFxQxe75LNjQPZx/KvFmL+8+s5hj/BRc7RanSOXn1DAAmA90i/uT/9pHjhXplyuxpjCaFygBVljGEqFisydLXEMKbCFhzztkjJWFyyc928V3IVqwQiuT6GM3tpOFNzrn1WqAN5W+lL6FxvaKVXunOoDJvALur887a7bgHUxv9ifuvARX9p6Fi7vn4ZlrTyn3TtWTl5fKpy78ahgAtX8RPvf4g/MpW1B+jnG4dd/XvSA/AAq37xvare2lamWlQ8Uc0oaQJbyOD8Ky5Yh6oy0gC6AYdRyT5EIpbzZlK3xo3XnNcLGHvoXGDivH9H3LkDGyd2qhSjjcHi3coJwLsu+968qir/H8YrGFS5m9Ux0AceQFL1a785yGl910m3jObOfNXtq9EGwOUX6O8bxr4FRvc4i/yvTALaFOrT0tUHra9OJ5eLXZNEQIWcILZSFJGwVaHQnIAjCBdll4YYglDhvn+JTlgTfb/QZeLQeUpgKqY3ulWupP5zknXpwiJEklvOqbXa3P+0MfO4HoDu/jareZjy6nIc3LvG5eKi/9ajWlM0vAEq9nvH8RfmOxnzDnGfs1Dk6JvNma3qkmT4/0tef8Sr1abQhZArbALIcXaUE2pc9agjFFJcPIqVh9x+fcSDFgMUYes00lbKwDgHJp1cf5yaoVcLNYnCL0Zucy+t7+xGIA1Gq3mWcXA7fK7p06SO/hKTNsrFZTOiVaTamj1HrGoedf4jrCHYWec+xGeM6xG+H49in4Tq/FKRi6NXQ8PeASoWJJnmxPNtLTgm3HB0F5NcQFWJSXqCeyTVxP8J0rrEYa58LEKd7Y4eJSNtaJXn/bM8s+zuV6xhUr4HB93nci3myK4t1mKJCdqpfKoWWjpFvPeDH/VDqd55ndp+A/PvphuLL3rGl3HvZ1NOHuPHdXXZyC4y2OBbAlQ8VUfpbjnF0APtgCYjN2wKzE8UpZvKju6M6qrQyFpcsBL6bfxr/EVB+PcPFRA9WY3nD7xaCP8364olicIiRxBbxzA7xcsT7vP14MgOq8s7BxMAVA9bLR9Z02i5DxdTs0YKVoNZ3nw/PpPAf0hu7LIhgaB1uLxtQrbr57OZ3nOystTmG1Uw1gDeFjCnRL3K8BuMbnDLDllE0Lupy3VeTdIiAL4DAYCsA3jBynCVs1JcLGRxVAuY2Jjtf1cf76Y/cvBsfwKmALiIR9dvP1eeeLU7zz4ydZ6X98OQBqtduMtnEwNUBNUThg7BtfuJrO863C6TzPXHtqvv7z/kXYP0hP5/GcK900s/lymseeC9cduxGOb5+G71RO56kJxl7gZLFZIlRc1JONzxNgCwl73JCxZ13uBbIAyO49Hi8PB3xT3myqvzYGWy04FgPVStvVDbIFGGyVV8Ibf/3tFwOv8Dxc2b8IB1EFXGLVpAZmcGx2orc92g8/cJptbbDbTIXGgZsNxfvUjdgNp/N8m2Y6z5cenD9jasoWlxiNgxPbp+HrX3Bn0gO3epUaXa0n6pWe0i8RKraQxJMdpE146jnvFgh7Vsp9eRqQbUHg0ZYG35wcA4rSfbA1SOpZjkHhIg9X9p91WOSBvpJw79Sve8Ft4vV5/3E3AOraaneeg3av91FMAlABfBppjW7EbkedN3txMZp8NSpbQMoFSOb74964aBycgr+y8MC9PUZvwJamF4eKDWWxgq63J0uWTQC2nayjsfpoAXggC2AMHYu8YUHfQip0TOlPDVSnBpZa+t6FNztfsnAeMuZXqLaw8bGtk3BqezWd54eZIWOA/m4zXX+ydEu3kKYCqKlyNM1svsnC1im47thzlyN2v00xnedzX3qAt2KWw7WsVoC6EV75om+Fk9vXwazZquqdLnWMA6JKyJL6QkDC5FzAJMvDtMPxcrFrA6J8GtCVvL0cLzalF5679NFSpA0jd+escHGB8O06eJulaQVYn8yEEx0AJOqz66bzaLzZH1t4sxeDrfu4ZZwyoGLUwHzLwOccu1E1AOpDr70Gl/eegWevPQXPXHuq780WbBx0o8lf+cJvXfYnf4fj4hQ1dGrJaoWKPT1ZCly5YNvpAlH2UM+DuF4sJ98qQJsibQvKA9SOGlhq6R8upvN0m6Nf3bMv8sDd0q3bbeb0YgCU1pvN7Z26jqAaUzdg7MT2afjGF65G7H67Yneezzz6odUAqMKjybuIxXwK0o1wYvs6+A7GAKipAKyWXACW6dVqQZVDXp4sdn0AYAJcC+XeYC7IxrzRgDZFsVcrrX42AOpL1/avLEfsXt57BnYPrs43SM+QBTRaaGELtuH4ImT8DTe/RrXW7d7BNbiyf3HhmbWwPTtWfiN6lhF/UG6aGZzYOg3XH3seXH/sT8Dx7dPwHcIBUJf3noXPfPGX4JlrX4ZLuxdgv92H7qsxPc/M9e7MGtieHYOXveA2OLZ1gnzGJUDPkpdrOFior7EnAdXaniwGntTG8R1V6aNF3mUOyLYwMaCNKRc23gBoeWrhAD73pQfh2d1zcP7q47B3cBXtt7PPSZ2n32q24djWSXjJTa+CE1vXwc7sOLxL4M129F/P/Tqc2jkDW80O7Ld7xrJJyOet5HuG871mX3GzPGQMANC2B3Bp7wI8fe1JOHf1sdWaxokSWSh+P45tnYDnHPsTMGu2YGd2HPXAJSBUw0stESrm6k8hVFzUk03xMt5tmC4kzn2WvM1WkAWYONBuaHz6Mzd+I/z6f/44PHn5j+eLPZCeIf8VToHJVrMNz716M/z5F34b7B1cU41ubqCBl9706uXGAWaQmHCTroH5AhXHt06J+jhD2j/Ygy88/fvwxWf/6yLUrlntS/Dc2xaObZ2Ay3vPwN7BVTQcN6UBUSUA1gKmXoOirGT1ZLkNBw7ghjY8SAKwKX54vgHaDaG0MzsOJ7efA8e3TkLbHsDlvWdhv93NppF4thjQAjTw8//lx+Bv//c/Cj/96T8tLTbsbJ2A7dkxOLVzvTlkPHVqmhl0yy5qQPbbP3oS/umr/itsz3agaRq4un8J9g52yS6CjiSNkFD32sFleOrKo3Dh6hNw5thN4nLP7R3uwU5c8uyf9fZkKTlWdkDsSABXS7k6TAOyAADN95w+3QL0+0fjvtIlL1qrGNVzSttmfpOyxTKMXH23tDB/OKOkhdWLUSrtOx54AP7RP/pH8Id/+Idw5coVODiwh48x3dlsBjs7O/C85z0P/uyf/bPwhfvvT5cvumfi+xdcd9W0QdnHeE8x+uxnPwtvfetb4Qtf+AI89dRTsLu727tWiqTPfmdnB2688Ub4iq/4Cnjf+94H/8MrX7mUp+qG8LeozqIC59iRyjz0U2WVpJHIc8daPYlOjt/TcQBd6v3lAmyK1wLATFGmYpSqIDTpKd6GZPSjd9wBN998M1x//fWwtSXrA0xR7qU+ODiA3d1dOHfuHHzxi1+E933iE+b8NkTTK17xCnjnO98Jz33uc2FnZwdms5nLWtAYHRwcwIULF+CRRx6Be++9l/WdTkVHK+Pqs3lKcEjJpcdcW1i6lA6mR15H2w7+XPUFfOzaRwNa7Sfs8elvAFlOr3/963uVcEkKwfanfuqniua1oRXddttt8OIXvxjOnDnj0qDK0f7+Puzu7sJTTz0FjzzyCHzioYdQXa9vkwWwirChRmapgzRpuYApyVtyzdZ7IHW+UmDKAVVuntJnUAVoOQ8EC3FxQ18l1hr2/kDWmX7kjjvgRS96Edxwww1JsPX2fvb39+HChQvw6KOPbrzaivSWt7xl2aCqCbbvfe97Tbasb18JD9ajruB4c5Y8anqyHvWpNtrJpRbyeeQ87xzPBLSim6RoSVhaeGPTYQTk8/ffD7fccovJ4+ECcujVfvCDH1TltSE5vepVr4IXvvCFcObMmSKRi/j5dyHkRx99FB6MvNqxw8C1bHo16Kk0Fq/Wy5OVXCsHcL0inKwQtYAf89hfUqmQLUcu5XPymgqtm9f8tre9beDVlurLOzg4gKeffhq++MUvwns//vEieWxoSGN7tVMBWE/v0/Kde4EuR7eGJ+sdMm6RP64uRTkvNnVtKd6sVKXOeUjxbypdSlaiFWqiEbbIA1hcD7F7BMbT0o/edRfccsstbgOjctRVwufOnYMf+7EfK5rXhlZ06623wotf/GK48cYbq4BtzquNqQRADtIr+2k99DX2JIN5pF5tKU9W6sVqvFcNqErKI+G5xIa8PcvUjeHaGftDWBeytJy7gVHb29ui8KJm+k/XV/vFL34RvuI1r2Gn35CN3vnOdy67CUoPfuP01Y7t5XrWcSW9Vk2dKUkn8WRzaXP6VP4l62yuR5zi53jiL8jbm5R6qUlvuM1Pmy/1IRxVes9iYFQHtiU9nrCv9uzZs/CBzcCoKvSKV7wC7rnnHlYI2aPrIJzu87EHHxSlnSLAWsBUBboOXq3G87XeA0lYNiX3ir5ybFm82yzQunuHiYUZ4vTcB2Etj9cDOqr01P33w4te9KIqHs9mYNQ4FE73qeXVnjt3Du699174t5/5DAA4hIGVMk+blmvw8nSt5BVClvA6Pud6sT+JDmUfk1G8FgKg9QRVqy3sJki9Xn4BWl06Zt6HFZDf/va3o9N9YrKuGrW/v78cGPW+YGDUYb23U6G3vOUt1ftqu0UsKCrZkJZ66WNFzSSgW8qTpeppD69d63BZHTVpAwC7dlYzdZlY+fJhmXMfKqbbLsqU85JzdjhUqiI/DIB83513VhsYFXq11MAojw97Q3O69dZbi073CSlexOIBZGDUWF6uBhxK8ZLyoH72ere9PFnJNZYAXC5xPF1uucNz85cjuegOGLH0nAuwtE40Mg99C00dDN7whjdUWzEqHBj1p7/lW4rkcRgB+Q1vfKMpfU2vNjcwytqQLiHj6luicRInhJKP6clKro0LuB7Ay7XD9WJTvEHNOObL2PGxCx885MwgKImXKymfl76FpgQG995+O7kOssdmAwDDgVE/9clPisvrReviNf/ypz4Fn//85+G2225T27j11lvhlltuqQq2XYPq45/85HgAK5zmU6POIMHAyast5clKvVgukMa4Ifnj2sZkHB7qglhf3Oxvwqv1arWJPeyCxLJfcA5urYq/pld7GAZG1QLp//DZz8K73/1u+MIXvgD/7b/9N7jrrrvUtu65555q033CZ/yTP/mTWV3Pxj+HSnm3Vk/W26uV5KU5l16vh+cqJU0DAOO5L8HITzz0RrmtBsqbJbMuILPkPbbXYy3TuxlerSeF6yD/1BGb7iP5uO+77z74oz/6I3jyySfhySefhLNnz8LDDz+sylcy3ceD9vf34fz58/DII4/A/YnpPtZvRvqde+h78Up6tVpPlpJLrnNMwOV4uhrvdpZLmJQZFrFOeZ1Yawe74NzFcH/7iVtclku3TF7msVcBX4eRlR0P82q9wsYhbXb3oemTDz8MjzzyCJw7dw6uXLkCV69ehaeeegre9773qW3WnO7TPeOnnnoK3v3ud8OvCab71GpI1/hGrZE+TNfbk9U+F6nHGMs9gJdrJ+fFUtc2wwS5RJQOB+A6r5Rru6dn8GZRm45U6gMc2/PN0btuvz27u483desgnz17Fj7wwANF83KlSst1vu9974Nz587B7u4uHBwc9KIAWq8WoD8wqsYz7qb7vPvd7yb1SwCsdHccb09WK8e8WumxpAwlvFgukKYcNO4f1zYm4/CrrQyVSh+DLetmRyCb9VaZ5dDoTKX1q/lgS9GTDrv7cClc4OBHf/RHZYlHWpu6Fn3i4Yfh0UcfhQsXLsD+/j4A9D1Ei1cbTvepvWftx5DBb0UAllNAQr8W6JZ2FizgKvVic/nU/mo5XjUnTQsI0Fq8V668p9e2A8AdtDgWOtQLQHnVJQG21MfpQbVe0m4Ri9rrIP93m3WQlxR7swDzexZ6iJ8w9G1rvVrtM+7ANh4YVTsaVeN7pfKo5dVKysA55/By/Fhesp7kliHFx3jJ3XtyCecCPBXHHvpgOsBN/WVsq286Y+cbK3nYXCdv+N2LRSxqj049e/Ys/HQCPKbk8degj33iE3D27NmeN9tRGAV4z3veA5/97GdVeXTTfWoNjAobCB9lroPs2iB2HMsgKccYXm1tTzZXp3Ou3wq8Ehs5HeraWEswSrxBTSG6c8lN53iz3HKV9HI99FEblUKg0lze8IY3VO2r9RgYdRgA+d999rNw3333wVNPPdXzZkPqQOvs2bPwnve8R53XPffcU30d5G5g1K8uBkalyDMa5aFfC3QxXalXm7VFlMkbbDuZpD6X/knsSmQxT7RgRazD/cXsY3LqZkhfEk65KBueMg/9UjYseXW8exYDo7hza73WQX700Ufhfy883WfKgHzffffBI488kvRmOwpBa52m+1ADo8b8TqUNewlPIre8h6U8Wck1ewGuF3HKxOWrFqzQUO7l0LYsUsfsciOVO8fOUmYdkSjY2kpLYwHDEx/72HJ3n5rrIE9luk/t+/5AMJ0H82Y7CsF2Xab7xAOj7l8MjCoBsMlnV3iTAU6akl5tNr2wHFqw7fgcwC31LXHs5xzA1LW3wBh1jAIPEyS4rS+pe85t9WHl13i5JR7uGJ5vLbvveMc7SK/Wax5y59WePXsWfnqNpvtovJwUpQZA5ajzEK3Tfd761reOsg4ytWKUhkp5t5rnKZFbvFqtJ0vJuGAr8Qqx9BbgldiQljfkkQtWYImpX6oQOV3q4i0vWYmWJqVTGkxHAV8GQP7wnXfCi170IrcVo7jrIIun+6wpdXfjgcR0np4eEm73mu7z4he/eJSt9D6CDIyygoJGvxboenu12rw0XqsUVKUgmsIO6k9iVyKLeewFKzTEvfnaC6aOUbsKb5zS9ZSNoW+xm8vrjW984yi7+/yZIzTdR+rNduQ13afmOsi5gVFjfm8akjgRVHrWceEQsqW+p3DA4rVqiVMmLj87j5YLWFKvVnqjUzKplyz55VCJhz4G+JYG5B/KrIPsvXxlPN3nZyLwqHn9teijmek8FHlN9xl7YJRnYzerzxyTYfVaNXIreXmy1vvBBdyS9ZYF9LFrzc6jxYxwgCmlEx/nADd3wdqHa6HB9RjnEkvzdddXll9DHl6tZh1k7e4+2fdpQqtK/RpjOg9FIWhZpvvcfvvtow+MCqn0N+jN08q9vFpuHppzCY8jC3UorPBML3UGIeCx5tHmc++nlHqzUqDPped4s9yK0tvL9fzwpeRh32Ljh4TTfazUhZAfe+wx+D8LTvep7iFH7y5nOg9FoVf7yCOPwEMPPaQu3lgDo+IN4jHy9G41ZAXdEu9WKU9WArYUeGkwgvMntZmTU2nQebTaX6wAFNhaWguU/VQayXVwbeV0hoL8xgikzOhZ1Qbfx6LpPqV2PQLoV8JT2LO2RCX+McF0HopCsPVaB7l0YwqgP3L6o4zpPikS6xvCx5I0WgBmHTOjWVZwldwXDpiVdkikeXJwqSOfrwHpq+UeQ8SnWh4xnzpe8pwqd46V0q3PEvmVstHxuuk+29vbIo9HA8rhdJ//Y02m+0gqJu0AKIy6KIB1YNQUvVopEEq8MWteUrlXvaIJIXPy54Jtrv6n7JcCXa7HKy1/C4rpPSmj0pZLeGxtgUqAXOq9ovrG/s3SgOlpy7M8P7SY7lPS4+kqEGq6T+3WsSd9WDAAStO3fe+995rWQQ6n+3TPuVQEo9sg/otf/OLSq+3Iw7tN8ioNiirp1UrytTZKJJ5fTh/T04CvJi0FsLlrTE7v4f72LbaojHpw1MVichGoMcCRC8DZfJQ6JWQe+t423vjGN1ZbB7nz0s6ePQtfedddpL6mYqxNv+IwAAqj8H7de++9ajvhdJ+aq4J1Xq2Ht+pNVL61vNqeHacBnZZGhqbez1EKQC2ATJURMrKQb67pcuCkaSVxb0rOXsoDtYBoLn8rwFrz98ivJvj+YGa6T9KuwROKp/v8E6eBUWOC73333aeezkNRuGft2bNn1QOj4uk+NTaWOH/+PDzyyCPwYcUiFlz9El6rRo7pqjxZpxCy9d5wwKzmd8cB5ZwXG/OX03u4FyH1aimw9WhdUC9Vjif+lSyAjwp0L7eFXMFXOHI75r3pTW8qUgmnns1guk+hEGYNT+mjDz8MZ8+ehaeeegr29vZcvVmA+f3zWjEqnO5Ts6/2Xe96F/yKYRELNq/goChMLgVSFfBm9DzBlutAYWlLAC/XrrT8LQDMsOk52G/OeAvAAlsMcKnWDgXUyWMmqHmQpNGiBdjwHkvS9RWHz4iVTKiP0Ttuu623n2mNEHK3u88/Scy5rEkWQH7/+9+/DBl7e7MhhaN512W6Tzgf+F3veldWt0ajyAq62vJIHSaAvPNQCmwpvuQ6NOCrSUfp5a5dVcPlAIXbiuKAqqTlIGm9SRoROdIAqwlgnWWl9Dk2zt5/P7m7j9cAGmoRi9INsFVG/JxizY8+9NByPWNvTzYm73WQa6wYFS9i8RHhIhYpknhoFjtaALYcD/LIOCSacw4vxw9lmudG/WnsSeUhrzfqmPuLZbY64XlcXheNvliJl4dzDeivwhOUgHAtKg2+XBuc3X3Y9gkQC6f7/CzSj9ezx+TVove///3L6Txcb9bav+3h1Wo2iNeWO5wPbFnEgs0TbpMplZd439jAazyX8KiydPKa3x8HlCWOYDf2XlWQ2GCPh4BSrlVDyUQtQyJkXOqhkYAuDGVLPgaubAz9FP2g8+4+OSq1u0+Nj/9DwXSe0t5sR15ebTcwqmYIuRsY9aFFg6rG96/JQ9tgd/Vkw2PGKn85uQfYcgG3BPBy7VIAm5Kx3YgcgKC8DNhSBZW2JmKQlT507DeXv0SfKodE5zCBLzYwqsS8y3BRhq8uuLuPZ8X+qc98pjedp2TfbExeu/vcfvvto+zu8653vQs+HQyMosgKFF5pSni1bOAVTvmxgK0FcGNdCQBr0nDKlbue1ahjwU48OcODBxrYlQBuLs/sw41AlgOuVH5zs+lGA4c0+UllWhobfN92222i6T7JPBSLMpw9exb+6QQHRsXksZ6xlsJQrGURCwCA7//+75/EwCgLmCZ5zC03MZ62gS49lpRB0l+r1Qn5HKdLShiYWmxJ5SFf1LzMAUb2YTPCuNiNoG4SF2Q5ZfduPWo/orxiWtMToIvqJ6INpab7pCgE2w984APD4iXSlGjgYBTm9eGHHoKzZ8+K+2ZV+SLvVQda1kUsaq6DnBoY5Q6wTJ5WrgVjrs2cHiWzgG0OVHNkAUoNcfKTXI9tP1rgvRwpsOVcgOgiGSAbp8/ZtvzihocNDs6L4/WBhGVQg6lhDi1GP1Bxuk/btj3w+CeSdZArThUDAPjgBz8IFy5ccF8BSkIhaFkWsQCo69VqBkZpyTooStsg1wAzW4/or+WCraTu5QJpCdClHLqUrkS23QkbmN/cpmnITJrgF6LjlO7yuG0BAvtdgfI5Dm0OmTyQVXuzjv2FXl5ubVlp/T+6/3540V/4C8tKvaT3FlbCpQdGWd6cDmBPnTq1vB/efddcezs7O7C7uws/+7M/q87r1ltvhTvuuAMuXLgATz75JABA8fnA3TrIH/nkJ+HuV78aANL1lYUnSSNJL0mnTZvTi/FgIE/YlfAAKZcEF6i3Ny6vhSSNp5i/zTEeA2ssy/HiBwltOz9PAG5H7JuTCEPmLpZjU+Jp5kjs7TJ1a3hSNfML7b/jHe+At7/97fDMM8/A/v4+y4uzTAXpvNqvec1r4Hfuv19lR0PcEr/whS+Eg4MDuHr1qvg6vfW3trbg+PHjcObMGZHdmO655x54y1veUr1B9d73vtcdYDWgK5Fz0nFtaIAXoCzYcsrSkeY+xTa0pAXYUNb8/VOn2u4ilr+LGzvgBwZyvPg4e0540ElijipOgauURw0SE/0m1lxuqTSxTqY82vSsdEF6kX4si9LHerfccQf8wR/8AXz5y1+G3d1doMgCKLPZDE6cOAF/6k/9KfjxH/9x+PuvfjV57aiMw1tcuzTtpwQjZ0vSK17xChc7Dz74ILz5zW+GP/qjP4KrV68OwNazkdA1EP7kn/yT8IEPfAC+7fbbAYBfl1H1W48X1ZtamzWOJTIAGEQ6KX2Mp+Fr9SwkcYw4MhbQ9mTRL/c4dT7g50CX6FvkgGx4nAXXXrZOQEtU0tivFai15chdhzRd7hpi/Z948EF4+9vfDn/4h38IV65cIb1a0drTCd2dnR143vOeB1/5lV8Jv//AA6pGhvT5eYM0x8bU6NWvfjV8/vOfhyeffHLQoPL2xnd2duDGG2+Er/iKr4APfOAD8Jdf+UoAkAMsCaBB/aWpJ2sDKtsZgiHQctJjvByfknnop0j6nUhAFgDbJo+x5R0FZKn0OZBsF/m2bTsH1cVfx8MqjRSfW55cmQBwkOVSDsC5abU6JSpYz/ww/e9fzLnkDIzy6K/sQsiPPfYY/DPH6T41AU76Xk+BpjLdB4B//6h7Sg2KItMXOJaUh1MX5vS59XOOT8ly+pY/aT6Scrcg2PidevEkYMt54bh6OdsawJXcC+pXQpr85ZngDSit7RK2/vBjHyPXQfai1HSfUiA1dfCrSWNO9/mwsEGlAl2BvHSjWPuNDupXJdhq+J1MCroliCoDBb4AmXm0HK9WcoyBoqYyxuxpy5i8RsMCFQljQ1Ymb9SMUccss3qQSN96in7wB3/QdbpPzvsNB0b9X8h0H/N7IJj/PHbFUovGnu7jBaCeoKqpWzm2tcCrBVvJffJ0vrxI6+zF6Tsa7EfL9fY0lT5VqPjiML4kH8lLyXkBvX451EujWIFmijKu/g/ceSfccsst6IpRntNctOsg1wTJwwi+Nb1agP46yL8UbSzhBrqCudbS+pRDHsDrAbY5ngVwQz1P4JXalOARALEylOaGch6aBqQxHS7ISvJx9WYFJAFjju5Y5ZfKMP03vvGNVfes7bzalzqvg1wTfNcNkEOvtvY6yJ/6zGdEAJEjqxzT1ToNFj3WuXHje6os0vtl/ZPmIyl3C9hgKEQ5x5OAbVgoTQWMASy3DNIPKb4vojIzFunWfoSldGqBN2XrLbffDi984QvNu/twvN/Qq33kkUfg/1704y1Tei8U4Wptfanbs/bGG2+EY8eOVVmCk7tBPIASdAXRJ6ljILUp0SsJthJ+LB/7W+GWE5MBZAZDLUFAMJIuPs6dpwqqbXlIXpDUcY8n8GYxAOb+ckiSJqtjHAhVC5hj/ZRXW2JnH4A+2L7//e9nlxHjSWnsCmUsCvesrdVXmxoYRQIok4fJtQ1qDTBr9FTnguUnqfo/R7VBl5sf994Omo9Z0EX0pK0kr5uVsiUF2Z6u06AlCyXzM/TPcnRKXJtXfm928mq5FIaQ/5lkHeQElQLfwwbIr3zlK+Gee+5ZNqhqD4yyAmiK5+HVWo65+bmcI/Umdo8sgBvqeWEJ16FLpeHKBoOh4gTzg3bIYx7nbGtuUu5maEBW+pHF9yt7DYKwsaa1awVYSV65kdM8Q/rGgqWvVur9hpXwj/zIj7DLyC6Pg42admvR7bffvvRqJc9YG90I10GmvFqLVxPLSz8nDfBa8wGA1RoIzHyosknrQ8ufJh9pufl9tIzRdBTY5gDXclNSMnFr0OjNYsBpAVQsDy9d7YdYQpbT/z7BIhYeFO7u87WLJfuoMlqItKEEk3UD39e97nVw6tSpKnlpd/exgi6m63XMzUMiw/KgcCKn1/E5gDv2e8wpA3WNvd17MMXcYtQxL9aHhDzmaYnz8KWAk21sCGxaBs/08mHOPc2WjdjyaqqykP6/xe4+165dg3PnzhXdNm5/fx/atoVz587BH//xH8P7fu7n4JZbboG/+k3fxEpPXdODE1m7uDRxvc2DgwO4cuUKPPLII1U3tw+92g998pPwrYvdfTrK1YssebAgP1WPWolrXyKjzlFeYhe4XL3PwYTwTSq91rGXQ9Mr8989daoFEKz3mVjPMz7mnFN8jCSVNtvLTQwUSgGXyGsl1gT2ssOxwVmvmbTjvJlALh12H973wAPwtre9Df74j/+YtQ5yV24Jhfo7Oztw5swZuP766+HMmTOws7Njtq8tS6k0NfLg0O7uLpw/fx7Onz+/3IO3Rll2dnbg+c9/PnzVV30V/Ptgr13VpgIpOaO+nPIax5xzlIesXU/V+RogtYCv5g2SOg/bXYtE01rJtaJS54DkYSWpZ5sCWa69ctUqjyTlqKFT2pMN9d98xx3wpxb7mXI2Q7eCTjcw6plnnoHHHnssGbKeKhiWsFmy3Pv7+8u/mpvch4tY/OKDD8K3R10FpbxaL9J4slLP1eLZAgwBl/JgOR4ulqYkUXnk5M3fSezeEx6jrSKlZ0vxJYRdmAZkOZ5rTpaya/FkQ09SnTZjw1oGsXer3H1mKVuU4YOf+AS87W1vY+3uM/YerrX1a+Sx7vopinf3+eZXvtJ1p52aXq1WT3Mu4mV2ZuNgQelwMUbctwvFosX72ZtHS3mG0uPuHLOr+URa4NtMnS+PmSAb2+eUz+N3UUhGjvkyY7paHVW15rh85Btvu63qwKh1opJh7MNMqUUscnUaR97TZczakBLXDlU3W85FPGRUcqdP3sPoryRJ8snp9fa+TiUMf+PjwEoyHZY5WhjhX85GLj9NI4Hice5LCZIAK2ehitiultwBepm4n/r//djH4JZbbskucDCF8OzU6Shec4riRSw+lNndhwMIGtLWTxY9j3MJDyD/zklAlIsNpexQABtf5xJoNTcwNsZ5SJ4tEswWCbKKfSNz4BbLREBYyJ4kjVWntgzAf3cfKW1A6nARd3efkCRyqVdbEnilb64FbJP8jHcbptOU08Nxs5QLu66Z5KYljxlgK3kIFOUuNsXPgazkOnN6K2Y6BQWcSVCUemS5cjnoTk32pjvuyO7uMzU6DMB8GK4hR/HAqJBEoKrMX1sfctJLZFLnhcoD5ROA26Ud863jgjIVGk8uWIHxtGCL8Tq+RwuEVXZBqzIlz+lJwMuDWPkJ5s+idq0rQhWkN73pTUmv9jAAwmG4hnWjeHefX2bs7iMCYMMKexpAJZ0OwblER+pYSQC3BvBK8uH2PQ82FUhV4FywjWWpB+N5k7AbEvO4IMttIHBADgNgr18OSdLU0PGWvf6226rt7rOho0G53X1EoOpdMGVeEpkX2Gr4ADzADe1YwVfqzPXSCgd3sftoWeCUWMUo17qx3hxM3i9SKwZZLuD2ZMwVnFhkXHJPA8bFdIj7YpVhXm1JmiIwb8rkQ9yBURJQjR0SyoakXrLoac4xHUmdSdX9HYiJBzQK/6TEKRcmIftoOYA2ANtEyJK66dabk5LnQtpWwI2vmdRxpNi+BliLAywzPZ1B3sr3rsF0n3UEnKNMnN19MJIAsIY8gLcE2OZ4WsAF0IOuF3Hzp64T7aPltmRQGdK353m7MABuE/lbGg85cOIAFwaM2l8WKfpnB7qKlhs3L236lOy/BNN9Su/uc1joqF43l7CBUVog7aVziLBReVCymmCb43cyVp1RAXTDPDj5cBsSaB9tnACTU2CbA1zN7aLSpkLFktZdKr8sz9ubNb5EGnD29nK16S2yWtN9agDUBgTHp3hg1MPERhBWkKSIa7+kJ2v1Yqk6X4IJMSBKAdicnihrLDP30aZkXMAN9bl/GKXykLw4ksZGzOPccDMAF7CrbZFrdErLXn/HHfCiF70ou4jFhjYkIWxglBZIe+mUgzMtepSuNr3Ui+UCrqpOQwBUC6jScmFyUR+tpbUEkAdcLeW8Zu45dYzyDN5sEiiDgUPUr4Ys5VPpeA4QY9D3fd/3ibzaw+KdbvIoQ/HAqF/KrBgFoANMLzuSujkn4wAppiPhU7JYZ6w3g5s/dZ2sPloL2OYAV7VoOpE+lacFZHN2MF4sq/2SdPdFk/9SV9k/66WjuWevu+02uPnmmzde7YbcCNsgvqRXy07P1KNkWrD18G5ztjC9ksArzYPbkMj20XqALVkYpqu/BFbB3CUKdE2Aq/BmMe+UC4jW9BybHN0aOhzF1I4eUq9WQkfRq9tQf4N4D6+WA7YaQOXWdZpzK6/jewBurJ/6K5EulT6nE1Kyj1ZaWcaZ5lo73tUIt2WVKqP2GCKPESsXpdNPMPzgLACKZqOwWR1gDfQ65nSfowxoR/naNeTt1WpIA7yUrDTYWgHXck+tYJqzqdGZUQ/Q2irKPQStB5ZLn+JLWnpYnjl9DniVBM9+Rv1GgAVYTeBpvEDJ/pOx7n9m7O5TgzaAdngonO7zC9E6yDGJG/EMr5abR07P41zCy/E7GRe4xvqSuPlTDYsZNmCF5dkxzjmFkPxhlANe7FwKwC0ACmQpO2ygEgyC4v5KaJCW0T87dQjxnu4zVdDclKsOYdN9Sl+lB/DWBFtp/c+Rx3olgVeaB+faADL70XKPsXPNDdeQJC8NyPb0MiFjzs2eStWjKY9H2SVe6ioNP1Wo+b133ol6tYcNBDZUh3LrIAPI687esXFgFCXzOJfU81iZPAA31uc6ZRZHDrND6XQ0B9rIq9WCrRRwNcDLvZk5ngZkJa06TIbpuAExETbWAOtokOSQccmBUSVo0wCYNkmn+1hI4+RQYCnJE0sv4VkB1/o1WHAmZ0+js+qjVYIt9+Fwb6y2xcFtXalBNhMyzoESCViZOcDaXw3VBFadZyvX/e5Xjzfd5zCB5mG6FithA6M6sjgs3MXqOY14jozzVC1gyykPF7jGeAMlQE01LPrTe5QPOnWuAVwNSfLyAtmcTYwXy8b2GNH8vZp+AKCDVCdalCH2alVztw8R0BymaxmL4uk+Hp7X8pgZQubWx5I6EMtTwrM4WhRJHC8NaWxzrg0AYDslaBLHElmOF2bekaQ65rQsOHxuC5Grb/VmzV4qM2w8pWq2AW55Vpr8NHPd7371bfDVr/0WuHTpEpw7dw729/erge2UQF297NyEr3vMRsPOzg7s7u7Cz/zMz6jSY3VjTi+XRiKTnkt4FB+IcubkuTQ1SYoXAAHQLm9O20LbNGqwBQaPKpSGNABLnYfeLCpH0quAN0PrBKBTo9/7yEfha7/17iXQSql0hT51ELSkK53HWGC7tbUFx48fhzNnzrjbbtsWmiZdY2qBV3MOhA6ml+NTslCe0xmDNADbUfNdJ0+24cUsj5v+eM/4gqXnXJmUuACb4nFBNgWuZl5mSk+KR/4KPdrkb9udG6cbteE5v1yra0nppMuE34+ULl2WfHq8HKn093/mP8BRpKMSnn7VK1+5PMbqyly9iMsWdW+T1tXZ1J1beTk+Vy7V8yLJW0zpNt918mQLgDwsI9hiPI1OR9pWhSfIhsdS3lLmMHd2VVYZoKG/SoDs/Q4AakpAi9vhlYEGbDr/dPpc+Yf58K7hMBJZoU34mCcL/kWAVpKHx7mVx5Fx5F5pMNJ8N1SaTj4MHYfHgjBy6jzMqHToGLMjBV0JyGryhoX9HHhyaT0qVE1PLF+a5BpujKQPWJpeK/PQPyxUox4Zj1ZX1wJAk6pQEyStl7X1OJcHCT4l48hzaWoSJ89YJ7lNXk8xM+0HO8dAp0RrO2e3NMhK85Q8IPZ9Wv/apRqxP2Dintpb0TILQ+18+in1a9WkKV43v4mZLz2n3pXnK0svcSZy+XO8wKlFZrhlwnS2Y6Xk42Z4tsDgxTLI6GCkaU2keMlzYrMACnApHizy0ACvVaeOEQdSlsPbwzPZYwC1V1kxWyVAZyqvyGGheT1KPCmmV8vLK2/W4tmCgB/KMHlKj9L1Jsn7Tulud0opEO3d1ATYAvAeTKwnLSSXuK0rCchyWjBaHjePtSGnCykbFm2gAeuG9PMSeoaCe+mQhGOHi6WV3KF5r4XEx0bmHVWCLQWcnmBL8QGRceQp3ZA8wFf7rnLxId9HGx3HYDuQA37TuC0YKUkBTAuylpDxipH3ZsVg3DJ0NjRZquHZjknc73xq5a5Dw7uTxVMG2HLw2BNsQcDnlE8CuKl0tUgTZUS3yUOBJbHbDwYaOQ+zJXQw4qRNyTCeBWRToIkCKLJLUgkS55NM4Nkc0tmS9k0CLAaQqO376+AyfT9rw0i/TtQQf4eJ5q8n76pYkTihDa4Op/7M2ZfUzZjOlBpg3DJhOuzQMcezBZC1cGIdK3Ef+vLcAWQ56XKk9myn9BYCTK88R5Sm6NlaaR1GGnO8SXOzgZeJyow3r+MDIcPkKT1K15sk7xalu9zShAsuIUhxPceQ7/1h5OyiXiyAG8iyAHek2mAqlRCbHAss8Rd7Z0gZNN41V1sr29A6ecFOpSK+EcsnxG30ayOYuXwljoklIsq1KS0PJR+sdRwq5EYZNwArsGqGY+e4rRlMJ1curU4XwsX0LCBrbf2oPVsrrQEar4uXlhvIVCa/9LAua5W+DveaoimBbQv42GInJ5XIn++FWtPn7FJ5cr3cXLoapMGgbRagErIulAyQfiApfq5QWsoCLIAKZM3UlrNZSH3iJINdiTZH1wr6/fSJs4xHXes5aiv+w/We0cQDK9ndzNaz3XnA9AZqCYBidTvHyeIM2upoCo0miYebomwfrUQWercA+M1PySzE8vqIradyIGvycp3CPFU8WwtVKgQJNpO4GfU98Kl4/JtRxjEVhIgMwnLBVwrSUi+WG9WcIuhK31FKn5zek5JB5pwC3FShioWOMzvvSM+LebxEGeQKgqRVazwCDgqXZZi7DZ7mqfU2cim1snUhScU6NeKDWIVwscCQNVRMyShQ5UQ0uY2DFFnup+V9o9J2cjR0zAphJAxKAJdbWC5xATbF04aSUVmb1in1UKdcOa0NLW6iF5jVAcVVLocBhAHq1BVlqW6w0wLcUi/VYg8ImxbPteZ7IXL2FjSLmdwwKpbh0GtqIRyh7H1DenYXecUyqoyc6xLJWtl1su4jlbk0P5Ytxus+Qs03hT4bP8Kv5nBdpw9ho4xL3iv+K64riSlMiSRm1ykK4nhxmA4XA0rhhZa45cF0kqOOpZ4tMHg9AIw2NTaFjhMdobmHTPG8QJci/xdo7s9M5cUUkbjQCd+NaaPo4ChEuUQoGEtnCb+tO+XCnePlLieqziUTGPPjmOVkSYWTISPHdDn6HmRq/CQo2Ucbn3PBlT0AKg7tNoJblxlhZAHYFE8FupE32w7+ZdhA7HLKIaF1r3CnESp1LEWli/GoqMa/73zyDIHmcrACk4XaFoBTjXqWg2uL0ssBck4/Ju1zthC3ThdN74GMHNNJFWggN0w+NIGXwA5Lf0K1T7YoEyrnWCQZzCT2bNXl0crqNzm8BzCuL40T4E+CV8SUgKrGq5XkIfGAgWkzl74kcUPfIYmm92DnwODlClHio5WAqca75cooYqVFlEb3bD1CvlOhCsXCr37C98WB1iWcLff29CArzWsMT5SrLwFbEOpy9UuTBXcAFNN7Uuc5XkdVRx0LZBrvNufNDsPG+WOvMq0tOVxY007n/ozl2a47jTXSWA9gvuFiTh3LslHAq+XYkeYDCv2O1rKPFgNYb0+2VAtFBYrMtGwbDjUBaoJhW3SNGeX1qsR9YMdncFQj6v4oAZhHEYS112v3DqfgY2Wuw9P9FZDGU+7IK6pZu0uDiz/k7j2QOY/1Y+PeoWPJjdECMBUyzgGXdyto0p7tZApipcMCUYflOvjkDcDcHLU4VgP/lnkEmXEjkDk+JZPoYOk6styjGl8AJ49YxyV0jAFr7dAx15YkjJy1w/IO+1NuRHkIC+Tlea9rda2GmtbLszWUpe2n0ISQ8bWIbLRuk8bKALD/vdV4gKJSEAmmBrZh+pDGjh94OHjbsZK1nxYS/LgANUPHXH2O99hmhF5VEdeLrddyK+gp1YjdTJjWxQeVAvhUgVlf7/BTWkCGU8eK8yvgRnPLBU5ZpxuV5Ujz9lJptnMP1+rJSlqWpUcmkt4ewSNDyIiMA+xJHcPFSq/VNQOS1gVefOgoDo7iAPNUwXhItnDxGDQoazsPmEi8V+p6ufej1H3LvT2lsURio9MZ9NHG5xxwtYaOY11PouyqvEWlN+sRglBTIeAel9JQYwEgVQi5teU6VcAsSRQYTwOI7RDhDTRqe4qEnmAL8uzVVPrNkQBsR7Pl4v8ZxZaQ5/RiWa3Ph5OXKkzblvMY28EBbVub3+jV2OgFCGkqvspUyjE+Nch/NUvApZINaE2ljvIE9Qo3f+m1T+qzZ1ILfPzCdOah48X6XZxQ8ZihY4qsnqUGZPMvaZvUy4aNld5yOn8HI7G9KX0pBeM/VQdHMTJaxxByCcLA1tcDrhcupurY4hmOYLK2hyslzZtEpVmFjpVgG2YiBVxJQb3IArJa2950qDzbgrRuAGQNeXvQOt2vkFIArAPfqVb/K7Jg5byuHxrI2eTkpylT+HRKvL/UoFzPvCi9/vQeAdgCyAEXEHkNMoV727SeZwg59BZdKzsi1C21FfyY7Rw+oqGy5OAoD9J8m1N9nHLwHdZ9GFmByZswBwgtx0TANkwbkodzVuK91HYTDKf3BGAL0B8UFZ5jvBw/VYCOSr2Y2ocRh10tD5UdNhba33i25YkEtkDoA4INNM6B0NI0pYgVRXX7eedkBV5v4F7aExouDbaxnamQtZ4GAJglvbRo83TKUA6sJO61RJ9rj9JB+YQBGliFV5JQ9/YcvV9evT2HT3GZOW0r26qntTbkQA3xd5SIqlM535W14R07Ety8uWWbElBKqE38SdJhhE/v6cAWCSUDgxfLIKOD6Ws62S26bUJo+TA4Hmw4GtArHOLu2SobHRtKU39qkCH9ISFqGskUaGrhYjeKCk9di0d4fSzyfJckdTG98TsSSk6liTOnQsdjhJxIUDR6gaWB0MPWqBXXVGpNIfGBzS/0e9jAVEuSLqjDShbQwtL2+AXBFpi6JckzUqrRHezeA6nzBdh2PKkn6wG4VmJ5igyQ1XqzFiXVS2J8s/rJeVV+tYpvKl5gsQuWwLqcDgtAlR5VaiGrN8dJjzk66nyFiSXqYwDu2OAaErky1PI8CiVDQifmcWQcuYVYfQoJJQ3ItqgECSG3eGhZE0Lm8rh5yBXXiJLX5AvFHGtjeK3W72zKr4M3+HqFP1l1rEM+3PxRflAZa8Ge0u9orAGwJdJS6ejQcXye8W7jDC2jkWtUBikvFks7hfDsGMCoMYWmmXINzaSxgHFKt07qxYxNpTzf0uDIyc/Dq03qL5glwDZM15HV+7dQKXAN9dCN37FzANq7xdJT/FgnJs++Gs1yZDk9sefIzIjv2eb8aYNnO5XaMktTgyImrWGRJaT5xmtRzkGYCnkDudheBbAN09cmVyeC0J3FjBSAoKASTQOSVPCYfo5a5E9ko5WDLD9kPD8jQa0dppOEjbNU6I31fymVn6XD9blUXtlyNJkzTgq9zjrRlKb7eORdw7PSOgJafqquyqlOscGSIsl9lGANpjtLZZwF11gnQi4MbD0BV0M5gO3KIeGz8zWm97ap9myteU7pC5wKWI+cw5RpKgAck9aj4ZxrqbidRSVtBfkpkBQwvezOwhPNi9EHXMg+EKqSLwG6FMB2eXP5lo8H82Y55aL0U2BmvpcJA1P+iA4DScBkKuBTk6YIviWpRKNa3dgWgu2U6gpJeTTeLqWX3fgdOwcYvuBzvYV290Aa+YCoUIfSy6Zn3C3pC0eDbJuVYxlKABU1J3yrq34EgsYFx44XpXt2y/X39iwbsohLWHq06tRpzGk+cf04Vp7VyrGo2xtmZpz6viRZIhCe9tjTe4DQSfLagNcQuozCeipbQVZKlFfNtqOQS7PmNFTWoQJOUhWwPjyknboxNnmCb00w9c4Ls5fLh1OGYPIJuxzAsOtBmuesqVcler0+2tiz0oWSh9xlxR352ubwQsImN0lOruFlvdlMSFd6nCIvEK9F5fzFSsS6AFt5GgcbtSk3uGkKV1KjPNI6U+tFuTWoFbKljqICV1TZYruatBZ5mD9GqtAx7dm2EO+SkfJ248MxQ2CYXPNCaz4mbzJ9nIJQL6mTUSgVrZg6HXYvGCNud1EtWocpPh6k9ZJZnu3iH4l3O0gfUa1pYdb6TeLl8leGEpzneJDgx/KcjoSs7r5LS5LpzXIomfaw1g5rRkcVPL3Ic468Vxly9UJpp0BrXxoqpvLilqVt012EGir9zK24wLUR6iSn93icp4PImG5aRxoO0KaR8NN6bXS+OtGUQwvGlhfU86XyzNuVkIyGdUPhQKfggqcQch2TxgxDc/Ozvr+e4eMS+YvqMO+YsDOVBlkMf8QrQ8k821QQuV9Y7kfj/ew0N1IUEk6ArPv7xwByqwduItJW3w9E1af04YrKkvdzeV4wPjbam6Z0mykac6QxRZoIYMn8Ofm6ebaL30ZawRcmL4dFKxuEjuP74wW2MOCn8ytN2tYbni4BFIynKvVgBzqZPNbVs93QuCT9Bqf2rA9Tn2sK2Lg8qV2uLUleUwFcz4igGoDbFt9UIDYieQDaFlVHY7XWJSCLeqstIRdQaedywJtIzaQvRsZHrHRtR6mv1n16njNN2euNydvLLeU1a4AdoC7glqhrVRHQYDrIdk8AuCeL6WG8/vnqjHO/vUC3VDweDXYy63iOB5ulBJhPIbTe0/Eq0JRqRo+yKG2sK4Af1pHGViDjpLd6tSVCyFydVJruwGvQVNJ+gXSiuhBxtAbTe+I03BAypgMQQmwKevNU+mP0ANk4lOvx0GWhZT4X5U2wFh+3SPWgbV1B1ErrNNKYIqp+LOVhaskDbIGhh6aNvCmNl2wlV5Al6v9kHy33AchbXEOwhUx+JUkVCsB4mZtcyptVil2zQ2UOjQ5uGTzJE/BWtjysHi0oHjPkm3IUapEFjDXeq0dZXBoQbXCvJxRaJuu+hAKWJtlHK/FkrWAbF670faZuMg9k29W/gq/RGo7FlLTXFCtMripvs6dqO+tMHt/HOt6OMcC39OAqbZjWyzum7Eijji51d3yTHQFB8vySukQ9OeTPG8gtRH20uUy9wHaePf4IS3i51hYMF2Qpb1Yjk4WQ+eRZaVhDMGtBFVzzWn6rxWuaEtUG3zG9XQ5pvFovsO10QaAvMtqRwrgaYAUeK8VH59FKwVXS8uqgKj3DFi+49IFzSQqIGpAt5c1iKux7wFT0srdOoeQN9WkKYyooKu2FYvl0eVn7aeURQh7VAttOH4RpxMZTFGUorVfNkcGM/sCjrQW2c9lcWgpArfaG8pYFspZ8k2CZyc8aDuHytPbVJGxYrCjyC0eu+Y9W7+rhHWVcirzCwFZ7HLAFoe2igJvJ0LM+5uhw0s+gtRnheG5t1k5LyP2Jkx8XZDlpzd6sQE+UTmHUy95K1f4Zlnt3vKoIDztTGrOqoybzN1YZpkjWBrGUz5VzdVJpStbxLejzKAWyMX+747YN7snGBiivNRcyxntmm+ItIP1NbdF5odKQsfiheYMhIp+sZzsFqhzvPmpeMMB4I41re7zeHuwY+VtsxPdXPT3ISB4OjqRBsz2QNqtTbggZ0wFEL8UPLXg8jDg/va4eZHX5BbJEKGR43A74rLyMb6uXPa/GRTLZIUMrTicLvpXH+tHYI4213ptHv6w2P45NrSzWA6Yux05N8vDcJSDbQmowFHKnNWCL8cICpSf64NN/ShBunw+yHB2PELKEPEJFEj2vdFaaItTUG1Hs5y9NEbRrgu+Y/buSulRig5sOmGnH9tAl5FXfSUC2+/LTC1Z0nlSTB1cr2IaFG0Jr+ceXvaGtbJs/9xBywpvlEEs/o1Qkv4p2LDY9vWsPGjuEzAXtsQF5jJHGljy8azeNPU9P28u7LUX2qCYtp/jbqdu55LS+YAsJPi4v9/jyN7Pt/mentX7Y3JBnPoSszMsjLWFUlGcB5G6HrLo0PcfQlfLT9OpffA3glYCuFtSkEULPELJEJ9QFgX5J8nYYNNHIkE/v3rMAnabpsdTTeqgHFxZu1WNbaWRqxovFbHh4t1ER3KlFT1DWmnu2eV8wBt58nl5+5dj+6TiEgXBNAC4NvHFdOLVwak2w7fQ7qn0fNM+2NMgCLIF2fivDGzoA09YXbAGRpQu7SiEJZbCJAFjMpgfIch+i5TjFdKtsPGutI4BDRxNuhzQmAHuFgCnbObJ4sFonRlIWT9sdlQDdIhE6po4k6snevQdgAbawYnLBFhJ8SoaVaHURHo+tzYaJFxpsvvWjlXuzsgSlGhMeMouub+ICdox0lMA5BcAlwbdW/663l6vxMqlIItfxsYyQDskK3BaqCbIAvd17hl7tSoZYa9JgC4k0FKB3JAHdPsl8XQ6oWUFW5M22uMyl1VaiBjkqtb+FnO5R6RDclB9lTfAt6e3GxAVLCahawsQlykPZqU3cPD1BtgVkUwH2w2oDXpPRiwrC6aOVP0gecpZoyXiArOYFEIWNGfY8eGoZkmDKAHCYSNsHNxbF4FsCeGuCbpiPFVRrgS0wdadAHgCbk1P8aDDU6jaHN5wVIo7CyphemDl3UBSlm6M2ZUyQLyUzh5ATyl7eLGakhM3J0KTDxocjCMwfW1GPSgOvB+haPEHPULEX2Ha6INCvTVanQ2sr1kd370klYg1+iuLAnJBxmQFOvuqenl8czrV6s1l9Zh4u4WltOl4wYkRSAmQmyeGA3DRxuojKl6Ec8Hp6umg9akjvkU4D7KAsizdZAFGjw6nzE7v3rLavo8CVfEmiSj4OL8eFMj0k5RvvHSqg9CTn+TzaxFH5FpxnhGBFfNg5rOB0FGhMAA6Bd6qgS5GnV8tND4o8O6oJuubGvlKHm+9gZaiUIRPYhvxFqXqyKNScYKcLZSAtSEr52XyIkLFE5pWHOh9jWrcKqmfI4DNu0Lwq5bqXyuRXFnSp79gyhYdr0yrTliVO19FRmdqTljXpBStCrzaWYefA4CXTIyX2fkhenp7Fw5WEjLky6bGG2sSJW3hmg4VZ8q6g1uW+1Zp2UwJ0S3q5qBOD8C2yWA+Yurn0IUn7gT3I6mRpZC1EoeM+2Pp4srkXAxAZppsizw/SM4yMercIUNXwZl3tF6CplMOFJnoxVs9kLKrh9Zbo1015uaU9SSlJ62KvMtV8r0o7Wpis42UWrIj9WhvYApJPiZZSCRueIGspTzv4l29A4uUmr4sZima/jA4PT3pv+QZL0foNg5riKGOA8v2jq7EqfoA7tzckj1Cx1XOt5d3WJC+ApeRU2lmsRHlaHE9ME15tg79axMkvpyMCmRbX8fBmPcLGU6n+p1KOPpWpVtahsqKoyfyNVQZf26v/fOzxSVqXWusSaX0xzW9VXrYSIBvyiQUr5kdeYeQwc2poeUdj9VFZb2yPJwBZM+gK33z2C6b4otzD4RXtmWhShRmXxhppXKqPt9RAqrk9v/EoNTzbUB+EaUqR9IlYGx9cLEB37/ECW0jwKVmuwJw0ubTWdBaQ9SnHMGwcgiHHs7VWD9JwMduI1ubahI031FH9kcb++XiGlnOkCRVr7MU6ILRf0kHi5OmdVitP8bMLVmjOAdKAS7VsPcIpVvK8sSmQLe7NOtEgL2PmR9azNZClolrXe1BvpLFvHp5ebg2vVpKPBcxDmtIAKo8QuhQLEgtWpMAUv93csDEFqGO0huJ8NTqlQJabp1doV/NiqT1bz/A2Ipw22JQdEGX9fqZy72oAbynQrRVWtoSJJWALTF3KxpjELYPWMcjJkgtWSB8elxcWZqw+2lQeWr0k0CSYfqHaPKp4h41TDQYL1ffYBYC2CT8vyTrlrhSVBl5P0LV4uVJQrQG2Ut0pkUddT8kpD5fRRzv0alNgKfViua0kjxCE5qNR3VQmyLp7s45U3LM1FNr7OW5IT9yGcs0yeOYb1n12W+X7cq1gC4SORndsEjsVSjknjIwuWJFKFIeQuZ4wZRcycky/FGlveCmQJa+X8GYxWyzATtj2IDfPtjqKlg35HhaqPdApla9XfiW8XA7gaupSjT2t7RpRRw1JnxFH3wqyAACzXMXOqfRTOpgeVeAxqzBL+TwWcsDyDM8Gz4ZhUHtP47y1dlv0RE/unu0mbFycas+xLZGPl03unFxuJU7xuXKuTirNFOruqYIsgGpTgXi9KDxsrAkZ12wpqcAiElhCqdqQccwoghMKo1U/tkMGakfRV67l+Zb0dC32SoSUOWHiElN7wnSatFKy3DGPBocEZFtA+mipkLAEbCHBx/SpQtceTZkFPkToBbLa8ConPEyGjQXXZiFrCNnds61KaWgdIww3nXuyXgOeQnulAFcTQvYAW4keljamWuNrrLY86t6Yim8qQPE7mtJIR7I1Uxhkh/ptzGCntZKmZZfkTak2h6CMm7DxpL69mGoMePKw62FL6uHWAltg6nJt1SYPgKXklIe73baLm5i4k3lwnfu1cVLswXBDxmN2rJMPBAkVs9IK9DSedJxO7b1nrlFrm503V4a3OzZUiKYwyhigTBjY267Vy40BV+tZeoFtpwvKcoxFkvtfEmQBwj7axV2XebLzMw/vNlW4Gg+VDZBMgMvxdSFk3H3VgLsWjE2ebUUPXEpTK886Eme8RY18vfLzmtrjCbiW+tRrao9GvzapHQylDrfu7/fRLqRtUx5sAZHlCuv1cEUAQyhzQ6ectNlzwtO0eLNYwkl6tooGDycBP22ib3WD1kmqPc2nVP+r1Z4X4GIWhiNmVpLuX8+pPXFJpgC6mntrrd8k0c3k7j3Q+oItJPhxgabWT6QBWAmfdy24lqc32wYM6z0epEcaCBtsOpq0riONfQY9WW3gtWQaKOMaOp+71lsdA3Qtz6GUF4vJWshtKrCoIJumn4Dqj8UeFvUQpxKSCEEnq+PAz+lovVl/ajNnNXLky9I6yMQZxFDdBkC/bFPqKqlJ6zTSeBqAmyZeGJnOXerdxmlDGiMKabXhDbIAiXm0AzBt+4Ol8BBxysfFM+b061RvHSkBNifjeHPp85WLKfGGOR4sWSBJ2pyc8WaLPqCKKMHOaorIlSFteLAmlRrwFNr2AlyLrRKAywNbOncvx2cKn4cHwFJyqp4nNn4PzoM7LwFbSOim8sDKEZIn8MYeo6QcXLkGZClhLr3mhdKk5+hyrt2ShzX8syGapjDSuPSAJw+b9j5Yn3J0xAdbOvepRBo1VLo+k/BZmwr0ztvgPLr7KbBN2UoVxtJHqxr16OBtWW8+DkZt7z5L86dkOkXh/fCuib2b/SNke5hoCiONvUF3CoBbE2wBYsDFc18XwPVszFNyfv3fGjd+X1iM+3EB0itHAdAfqOZBeocfLd6SlD/UwUHWA3R7xy1DJ2NXK5d6u1PwbJM2Nig8oJojjQ/jKGNP75YbNeSCLUTSqYCu5l5Z6w1pPc/c+B0/B4BVPy6shKllGsOCVO2jdQJXSk9y81EQZRbExZtVEgmuE/VmN7g4DpUe7BTn4Qm66w64XLBd5cn3q8cEXe19qV3Pd3zWxu8ssO14PS+pBWjSc7w4HmxccPbDdAArqa4PyLa0jiDvWCYN7YaLZbDvFaLo4dkqsvXLoJfcM8iXJs7uLhiV3PfUg47iKGNteo83jQO2fT15ruq6Wmm/VHrPej7ky/tokXOMB23k2yb6dRPsbKFjpnRQlYRK3fihgA+yZm+2xQG4ONAZDHvl4RKWc7tgC6T6WhwLoEsC7xTCwdb0HmAvAdswT0t+U6CxnKmYb+ujXfxSvC6QDBCMXkYKVbyP1tGmB8i2kUAKsipv1kBZm232VFSOIoBf4EWZSoXiQRRA1wLi0iONjyrgypyaZvnvOlINgM3JYr5PHy2LN+dQDzss4FTj/h43fskLkFb6AUlAN1TieLNakNZUAtbr1pInbBwmwMUIX+iv7NUftv5Xa3prOJnr3c7r63aZ5zqQd13lVdf799EmMmwSWpzWVVzgEg/b68FIZTHIctJpy9qmmI5EXIY+21aftmjV73CthwmY04Mey1xhif5Xi62xpvR4eLeS+nRMB4iiEo177zBy+T7aAX94Bki6lJ0Uleyj5aRXhZAjdLKGjLkeKN9THUolXq5GXtSzLdEQYGSH/R52Gk7v87/yKQ16GiskbPFueXXvMIexQdfqzVt0tB5upT7amD+EZMvDK1V5WcDEE2QpYpWDMIqBKKsszAJbgHGSnu2G2FQaeL2mw6wj4HqEksP8NWnDsniTx5tiBVhKTjlbFfto+xnnemvHbDF5hP68QVYCxElZO5R5VXNWm1U8W8+GgNONm0L4bcxGSCngPSyjjDVgq82vIwvgxjamQJKylAPZ+b+V+2hTMgyS+3qYHSsV8R4xPgGyHJti0GVkwvFmUUAVeMpsKvC1TqkCmAqV7nKRUAi83qA7NuCuk3cb5rl6Ih5W65EnwOZ0JFhg6qMFBi/HX8nwrYtTdlI0+X5aBshKQdXs6Vq1ETXNvbLwaJmsokA1e4L1qnw0xJkZUCZfX9AdG3DH8G49npGHh1uL3KNghI4UfE19tBJeWIi0bCX16CvwIJeH0UdaNI0ENDnlyHmzLE9VmKcl9KJT1Nk73NBYh3Lftn9efqA79ijjml6qV591bGNKoKu9ttog20LhPlpI8DH9UNoGKdexj3YpdwRZMRC3yUPV9SWPGYbcwFeY1qvS34Ayn2qAbwnQHQtwawGnd9xlbNAtVWdwdTQgC2DoowUGL5U2VbD0A5unjC/A++F6hxyGQNRm02kePnmOgKwmbymZwLXlNTI8CiO2uUFdMWGNbx/b3fyF8QF3HbzbWt+6Z/1cu8GsrSs5dbu6j1bKgwSflg8l1E0r1bIWAWIUt5WArBhU43MluISl5XizGi8Zz1tv4TB4tjU8gym0E7xGBPdt+ni5h70P1g62PAtTeM8AZOWwOAfcun07XPLfE2xBwE8VLh78n0+ZtuFBFoDNpdeArJSKgBAzoRiI2+ypJGuRsucHyaGx+ri4+daqKEt4ux5e7mHugz38w/f8v2cbyK6OFqFjGdgCg5dKS+mnC5vyZ8tWV6pQg8GLTfFV3q7Zm/U7pmiMBtE0jU+Lxhtp7JeXF+BqU0+5D9ZzkNRUSHotpQAWk7XQGwy1gkWLJyuf2iOfmtPvubWDrulBJdBtCiCre1GIO2H8OtHkLS43e7YK/dr21oHqjjT2sW8NK6+Td1sjzZRIU3aVA2WUdTxRHy0QOhgPS58qIAc208HZ8kG5Qb5GcNPypCBr9WalJLFTBAQVRqlGwIaGVBp8p+LlHtY+WHmapnf/anaDeNVHFj2LAxXNo22jViANpBgAxzyOjCPHaej3elAS1B28RzfvTeiEasA0BC8PYG7RE9zWND3bdfcL/KnEgCdPu00EFpoyaABNmq5WH6w89Ly6f6l01lrX850pDbA5WczfhhagbfJgC+A7KIqSpQpqB16+JfRDFABsTu7m3Q6dakPYIyN1ePurebZGQ1OBTUuFNdVr8CqXfUqOrQ/XMqWnPBDOqSRA5xorU3j31I1+oTxfv/el2x2vBYCm6RvwGIGc42N55fRC0lVGSR9VlMz74Wh50nONzOtYXAhO+oye9to1ilx7tUJtknxqVoze3u6YgHvY+mA9wXYM8o5ueTpRANHKUG27eIGaOTRS4IoBcszL8VMFnNRUBAHA5nS8vVtpvyzXmx3oOd9kERAT6WVCx3wUacaa1kMRd+R/yXyt+YwNuBoQBGG6DdgOyb3+YOhonaheH20naNrFUUODbY4HAr5Upzi1vR+uukim9m6Fb5gEdHt6wkYGlkcybZuWSr1TSTlEdqfTWB+Nao009ut/tdnQAm7NqTlTzKMWlaoHuDoWJyq/BGO78GwbHdhSfEBkqYJSum7Uyh5oidZPlpcon8x7jc8z3izDhspDJbxxhQnxc1PnUyjNulCpftfY/tiAW9O7lQIhKNKU0i/l1XpYHKseTzXVGNN7WoA28GyJftyYl+PHBdX003LSkfYUT7Vk6wflKUBW/QIZvFlOftr755F36bxK250SlR7wZLFpm5aj925Lg60mzdTAtuS34QWwlFxSl2/HCijYdn22EWpKvVtAZHEBqwzoECa0hh/GBtlhPog3m7kIjjebBVSmba68TQjMH3HCwFEATQ8qMb3H7qHq02tA5LD0wcrKsl79tdaGfk6euhfpPlriHCAAXABomy6DhF6mkNywsWvIuAC4UnpSmQZkKdJ6uqU/naPg2aZozPEHta5zeqOMp+3dTg1sSw6O8gB9TfpSzhJFgm3y+tzeWRvxmn7aiMWSpfQ6ElVShYCVqy/xYpN8JsjKgbSuNxt6nq6tyYxN1UdBJJJWalOkMUYaT2WU8RjereadKQnQ6wy22nfHCrBSiu+DcAlG3spR0Eb8hge4mDynH2XDvlulW1OaVhEHZDnptN5rnF95zwcB+6ymd87l81onqjHSeAqjjPUjhcuDrSZN2bDwetoGge1SDY+OoiUYOaOL6ZWjBmnbPr+nHyVkgS5ypWOHOSkdkXeLgKwUVNPnCcsEqHO81iwlPE9zYyd9GSxe2qAg7+XRlCdE+FDJkcZjjzLWgaA8lDw1sJ3a4KgSNHYJwvswA8hXfm2SN7wErILLgUsbHiT+2uCvJ6tI3GwpnTFAVppeYotK0ztWAVidR229B2N/zGNQE/1527TYsOQtTydLpcujHEltS/Ql90Zmd91059qzjhFXcHSlngZbNeASlMJib9LkwQFYCci2SpDl2k/6tEpv1oskNtvBAT/9UQTFGlQKdMdIK08jB9uyAFfOdkmaAiiWJOb0Hux8zsmGjSM+EDJMnqKxKk6rp2PxYrm89Hk61ppLqwFgzJvt6/CfntW7LpaJX/KiFULN72TdBz1pQ8lTGpE8FdtTCSFzqeR9mEnDkSk/1tuLHSlKnKWiIeQqIJs4T+MuSjU926x9wgO35i2RSSgOuXp7glPNd0w72nCt3DOU5zSlsHAp24c5hCwhwfSe/nm/UPMhUgDDgnK82NzFxZVczVCAKqQplGP9l/4gm/ZpPQBG7s3K8+DoqhsrjqiNRXOmSlhZPRsynqOMp+zdlvZsp+KpbmhOknuW7KPlnA95aHByyadk3JBs6s9CFptc7zwpKwyyWUnCK3T1Zp2+WgoUednwC2NteKwTyOaolOfrMeCptncr0y/7Bkylf3fj1cpI3EcbF6TPm6eweLFhZSa54JqtMW6DICurALJx00cSMuYCq85THTbKJEDu6tlumvEs8ux7De1pbdXtg5V7tgDA9m5LeqpSmkJ/7Tp54tz8xX20NG/lw3G82Bx5eawexC0L6eEiCli6UiCr9dw03qzYG8ZMZhJ7vyPme3CIydPT9fBwa+RZoz+7lP5hibJYacx7xu6jjTOPdYZ6be8oTh+nweQpPY6+hTQVKcvLMnqxKb4HyHqArgeYSu2YPVtGo2NM0oQha4/y9Ox/1dqo1wcr92xLLmpRzvvceLUS4uTfW4KxS5Q673gUAPf1+ilygMuRY/o5osDdQhw7Mchx0ttBFs9fE8FIyVA90puNmwEyL9kKvlIq5dmW6svj2C0Fxh6gawXcowa2EpoC2I5NY5VVtXsPDqx9HkDXY9sgsjTFN8JSJdWseJN6Ai8W48t5QzCznrMApy3TiLHaTN4rQcPHSqUHyEgpVR5v8D3cfbDTAdt1AjmA9fJqPW06Te/Je7cA6ck/4UVIwsY1qy3pjU6FJjn2/IA3AbKMi9B6tlyb0mNJhjUqGsn9mBqwcigusxfwegCuBjileR4VsJ2G7rgLWYwByqLde2SebIrfopUQ5eWmdEPyqNq0N3+QTugt+YBsDLX9EwuQ+nmzttdb4uVy7x03bY7WEVgp8gbew9kHWxZsNzS+x+6Vv/P0Hjztit8u9POAm7KZo9oPg+t9eQEsxvcAWS3otpgSpqc5FjxYtmqbPPTN45BRf8cu/V04fH2w5cB2Gt7n+ni1Uw41s6b3cCpmjIeDRpuVh+kpvVqULUskyF/7dEFW0zCIZWk9vyco82yHGqU826NCzeI/mw1dFEqTbmr6pWxPQbcEjZ2/By37aAHsI45z3m2Kv4KKVA/ukFIVX6mHUMo78gDYFb8syLKAlbhoL29WAnpZXUQ4pmdboyIp0Wjw8HK1nsX0PNVxvbmp0Nj3YaqDoky79+R4IOB3VsKL4VY+klCBRF+SuQVgczKOFzs4KwSySTBM5OXmzTKSyDzbadBYrfN0N46n/WZhU2718PTBlgGZaYR6x/2GpgqgXJuq6T3A4HH4fVlfWwO6OfK8odx+Q23lz/ViB2dMkKWodDjZ65iigW5LyAU8Lk057JX7LvU2bYC77mAroSmAbQk6jPlbbW5DuwDT4Kur58mmZDgnpJoVWOzBsfUVchxkhxItyFqANHcv0oBYxpvVJq1RAUwZXHOUajzrbekAV+PdTglsxwYZKY19bYc5jB7SanpPu3jJF2+61ZPlgepQtpLntPEHbqnk0MctDGNqdCRe7IDjCLKsMiby8/RsvdL25BklD892XcEVIy/Q1VakUwJPqf66hZBL0BS9yjFtboew2AJAE+AbBq4W75aShfK5DqWNpzWRE7hSenkZAbALhhYoVKCLgHo6naKKRa5HYQZylrzek8MGsCmyjm+weLdTAc/DTGPfh6MwKGo7hrHleWCxbfz7aUMZJu/rtAu9wlWb0PNRmsrKsZduTJDNeZBuni3zBos9W0bjAJOXiJxQNLUxCR1ZvdzSG6OX1t94teOD8rrS/w88AQKjgC8bBwAAAABJRU5ErkJggg==" style="width:120px;height:120px;border-radius:18px;display:block;" />
      </div>
      <p class="login-title">Everblack™</p>
      <p class="login-sub">Order Portal</p>
    </div>

    <form method="post" autocomplete="off">
{{ csrf_field }}
      <div class="login-field">
        <label>Username</label>
        <input type="text" name="username" required autofocus>
      </div>
      <div class="login-field">
        <label>Password</label>
        <input type="password" name="password" required autocomplete="new-password">
      </div>
      <div class="login-agree">
        <input type="checkbox" name="agree" id="agree" required>
        <label for="agree">
          I agree to the <a href="/terms" target="_blank">Terms of Use</a> and <a href="/privacy" target="_blank">Privacy Policy</a>
        </label>
      </div>
      <button class="login-btn" type="submit">Sign In</button>
    </form>
  </div>
</div>
<script>
const canvas = document.getElementById('canvas-bg');
const ctx    = canvas.getContext('2d');
let W, H, cx, cy;

// ── Black hole params ──
const BH_RADIUS      = 0.0;    // invisible — no drawn radius
const CAPTURE_RADIUS = 0.60;   // fraction of MIN(W,H) — enters spiral zone
const EVENT_HORIZON  = 160;    // px — disappears inside this

// ── State ──
let bgStars   = [];   // static background star field
let freeStars = [];   // slowly drifting ambient stars
let captured  = [];   // stars currently being consumed
let flashes   = [];   // brief energy flash on consumption
let logoPulses = [];  // EB logo pulses at BH center

// ── EB logo image ──
const ebImg = new Image();
ebImg.src = 'data:image/png;base64,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';
let captureTimer = null;
let captureRate  = 20000;

function setCaptureRate(ms){
  captureRate = ms;
  restartCaptureTimer();
  document.querySelectorAll('.ctl-btn').forEach(b=>{
    const map={8000:'Rare',3500:'Normal',1200:'Hungry'};
    b.classList.toggle('active', b.textContent===map[ms]);
  });
}

function restartCaptureTimer(){
  clearInterval(captureTimer);
  captureTimer = setInterval(captureRandomStar, captureRate);
}

function resize(){
  W = canvas.width  = window.innerWidth;
  H = canvas.height = window.innerHeight;
  cx = W * 0.5;
  cy = H * 0.5;
  buildBgStars();
  buildFreeStars();
}

// ── Realistic star colors ──
// Real stars: O (blue-white), B (blue-white), A (white), F (yellow-white),
//             G (yellow), K (orange), M (red-orange)
// Weighted toward K/M (most common)
const STAR_TYPES = [
  {r:155,g:176,b:255, weight:1},   // O — hot blue
  {r:170,g:191,b:255, weight:2},   // B — blue-white
  {r:202,g:215,b:255, weight:3},   // A — white-blue
  {r:248,g:247,b:255, weight:5},   // F — pure white
  {r:255,g:244,b:234, weight:8},   // G — yellow-white (sun-like)
  {r:255,g:210,b:161, weight:10},  // K — orange
  {r:255,g:180,b:100, weight:8},   // M — red-orange
  {r:255,g:150,b:80,  weight:4},   // M+ — deep orange-red
];
const STAR_TOTAL_WEIGHT = STAR_TYPES.reduce((s,t)=>s+t.weight,0);

function randomStarColor(){
  let rnd = Math.random()*STAR_TOTAL_WEIGHT;
  for(const t of STAR_TYPES){ rnd-=t.weight; if(rnd<=0) return t; }
  return STAR_TYPES[STAR_TYPES.length-1];
}

// ── Background star field (static dense layer) ──
function buildBgStars(){
  bgStars = [];
  const n = Math.floor(W*H/800); // denser field
  for(let i=0;i<n;i++){
    const col  = randomStarColor();
    const mag  = Math.random();
    // Smaller, sharper radii — max 0.55px for most stars
    const r    = Math.max(0.03, (1-mag)*0.12 + Math.random()*0.04);
    bgStars.push({
      x: Math.random()*W,
      y: Math.random()*H,
      r,
      a:  (1-mag)*0.55 + 0.25 + Math.random()*0.15, // brighter so they read sharp
      cr: col.r, cg: col.g, cb: col.b,
      tw: Math.random()*Math.PI*2,
      ts: Math.random()*0.006+0.001,
      isBand: Math.random() < 0.35,
    });
  }
  // A handful of brighter accent stars with diffraction spikes
  const bright = Math.floor(W*H/18000);
  for(let i=0;i<bright;i++){
    const col = randomStarColor();
    bgStars.push({
      x: Math.random()*W,
      y: Math.random()*H,
      r: Math.random()*0.08+0.14,
      a: 0.80 + Math.random()*0.18,
      cr:col.r, cg:col.g, cb:col.b,
      tw:Math.random()*Math.PI*2,
      ts:Math.random()*0.004+0.001,
      isBright: true,
    });
  }
}

function drawBgStars(){
  bgStars.forEach(s=>{
    s.tw += s.ts;
    const a = s.a + Math.sin(s.tw)*0.03; // minimal twinkle — keeps them crisp
    let lx = s.x, ly = s.y;

    if(s.isBright){
      // Diffraction spikes — 4 short precise lines, no fat glow blob
      ctx.save();
      ctx.globalAlpha = a * 0.55;
      ctx.strokeStyle = `rgba(${s.cr},${s.cg},${s.cb},1)`;
      ctx.lineWidth = 0.4;
      const spikeLen = s.r * 4.5;
      ctx.beginPath(); ctx.moveTo(lx-spikeLen,ly); ctx.lineTo(lx+spikeLen,ly); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(lx,ly-spikeLen); ctx.lineTo(lx,ly+spikeLen); ctx.stroke();
      ctx.restore();
      // Tight pinpoint glow — very small radius
      const g=ctx.createRadialGradient(lx,ly,0,lx,ly,s.r*1.8);
      g.addColorStop(0,`rgba(${s.cr},${s.cg},${s.cb},${a*0.30})`);
      g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.beginPath(); ctx.arc(lx,ly,s.r*1.8,0,Math.PI*2);
      ctx.fillStyle=g; ctx.fill();
    }
    ctx.beginPath(); ctx.arc(lx,ly,s.r,0,Math.PI*2);
    ctx.fillStyle=`rgba(${s.cr},${s.cg},${s.cb},${a})`;
    ctx.fill();
  });
}

// ── Free drifting stars (slower moving ambient layer) ──
function buildFreeStars(){
  freeStars = [];
  const n = Math.floor(W*H/4000);
  for(let i=0;i<n;i++){
    const col = randomStarColor();
    freeStars.push({
      x: Math.random()*W,
      y: Math.random()*H,
      r: Math.random()*0.18+0.05,
      a: Math.random()*0.6+0.3,
      cr:col.r,cg:col.g,cb:col.b,
      vx:(Math.random()-0.5)*0.04,
      vy:(Math.random()-0.5)*0.03,
      tw:Math.random()*Math.PI*2,
      ts:Math.random()*0.012+0.003,
      captured: false,
    });
  }
}

function drawFreeStars(){
  freeStars.forEach(s=>{
    if(s.captured) return;
    s.x += s.vx; s.y += s.vy;
    if(s.x<-10) s.x=W+10; if(s.x>W+10) s.x=-10;
    if(s.y<-10) s.y=H+10;  if(s.y>H+10) s.y=-10;
    s.tw += s.ts;
    const a = s.a + Math.sin(s.tw)*0.15;

    const g=ctx.createRadialGradient(s.x,s.y,0,s.x,s.y,s.r*3.5);
    g.addColorStop(0,`rgba(${s.cr},${s.cg},${s.cb},${a*0.6})`);
    g.addColorStop(1,'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(s.x,s.y,s.r*3.5,0,Math.PI*2);
    ctx.fillStyle=g; ctx.fill();

    ctx.beginPath(); ctx.arc(s.x,s.y,s.r,0,Math.PI*2);
    ctx.fillStyle=`rgba(${s.cr},${s.cg},${s.cb},${a})`;
    ctx.fill();
  });
}

// ── Capture a random free star ──
function captureRandomStar(){
  // Pick a star that's not already captured, somewhere reasonable
  const candidates = freeStars.filter(s=>!s.captured);
  if(candidates.length === 0) return spawnAndCapture();

  // Prefer stars that aren't already right on the hole
  const s = candidates[Math.floor(Math.random()*candidates.length)];
  beginCapture(s);
}

function forceCapture(){
  spawnAndCapture();
}

function spawnAndCapture(){
  // Spawn a fresh bright star at a random edge position and capture it
  const col = randomStarColor();
  const edge = Math.floor(Math.random()*4);
  let sx, sy;
  if(edge===0){ sx=Math.random()*W; sy=-20; }
  else if(edge===1){ sx=W+20; sy=Math.random()*H; }
  else if(edge===2){ sx=Math.random()*W; sy=H+20; }
  else { sx=-20; sy=Math.random()*H; }

  const star = {
    x:sx, y:sy,
    r: Math.random()*0.18+0.05,
    a:0.9,
    cr:col.r, cg:col.g, cb:col.b,
    vx:0, vy:0,
    tw:0, ts:0.01,
    captured:false,
  };
  freeStars.push(star);
  beginCapture(star);
}

function beginCapture(star){
  star.captured = true;
  const dx = cx - star.x, dy = cy - star.y;
  const dist = Math.sqrt(dx*dx+dy*dy);
  const perpX = -dy/dist, perpY = dx/dist;
  const orbitSpeed = 0.8 + Math.random()*0.8;
  const dir = Math.random()<0.5 ? 1 : -1;

  captured.push({
    star,
    x: star.x, y: star.y,
    vx: perpX * orbitSpeed * dir,
    vy: perpY * orbitSpeed * dir,
    r: star.r,
    cr: star.cr, cg: star.cg, cb: star.cb,
    a: star.a,
    age: 0,
    trail: [],
    phase: 'spiral',   // spiral → rim → consume
    heatT: 0,
    dir,               // orbit direction
    rimAngle: 0,       // current angle when in rim phase
    rimAngAccum: 0,    // total angle swept in rim phase
    rimOrbits: 2.5 + Math.random()*2.0, // how many times around before consumed
    rimSpeed: 0.05,    // radians/frame — starts here, accelerates
    rimR: EVENT_HORIZON * 1.18, // orbit radius (just outside event horizon)
    consumeT: 0,       // 0→1 for final shrink
  });
}

// Color interpolation for spaghettification heat
function heatColor(t, baseCr, baseCg, baseCb){
  // 0=original, 0.3=orange-hot, 0.6=white-hot, 1=white/blue flash
  if(t < 0.3){
    const m = t/0.3;
    return [
      Math.floor(baseCr*(1-m)+255*m),
      Math.floor(baseCg*(1-m)+160*m),
      Math.floor(baseCb*(1-m)+60*m),
    ];
  } else if(t < 0.65){
    const m=(t-0.3)/0.35;
    return [255, Math.floor(160*(1-m)+240*m), Math.floor(60*(1-m)+220*m)];
  } else {
    const m=(t-0.65)/0.35;
    return [255, Math.floor(240*(1-m)+255*m), Math.floor(220*(1-m)+255*m)];
  }
}

function updateDrawCaptured(){
  for(let i=captured.length-1;i>=0;i--){
    const c = captured[i];
    c.age++;

    // ── PHASE: spiral ──
    if(c.phase === 'spiral'){
      const dx = cx - c.x, dy = cy - c.y;
      const dist = Math.sqrt(dx*dx+dy*dy);

      const G = 65 + (1/(dist/Math.min(W,H)+0.01))*2.2;
      const grav = G / (dist*dist + 25);
      c.vx += dx * grav * dist * 0.06;
      c.vy += dy * grav * dist * 0.06;

      const speed = Math.sqrt(c.vx*c.vx+c.vy*c.vy);
      const maxSpeed = 28;
      if(speed > maxSpeed){ c.vx=(c.vx/speed)*maxSpeed; c.vy=(c.vy/speed)*maxSpeed; }

      c.x += c.vx; c.y += c.vy;

      c.trail.push({x:c.x, y:c.y});
      if(c.trail.length > 60) c.trail.shift();

      const nearness = Math.max(0, 1 - dist/(Math.min(W,H)*0.62));
      c.heatT = Math.pow(nearness, 1.8);

      // Transition to rim when close enough
      if(dist <= c.rimR * 1.4){
        c.phase = 'rim';
        // Lock onto the rim — compute starting angle
        c.rimAngle = Math.atan2(c.y - cy, c.x - cx);
        c.rimAngAccum = 0;
        c.rimSpeed = 0.048 + Math.random()*0.025;
        c.trail = []; // fresh trail for the rim spin
      }
    }

    // ── PHASE: rim — orbit quickly around event horizon edge ──
    else if(c.phase === 'rim'){
      // Accelerate slightly each frame — spaghettification spiral
      c.rimSpeed = Math.min(c.rimSpeed * 1.022, 0.55);
      c.rimAngle += c.rimSpeed * c.dir;
      c.rimAngAccum += c.rimSpeed;

      // Position locked to rim radius
      c.x = cx + Math.cos(c.rimAngle) * c.rimR;
      c.y = cy + Math.sin(c.rimAngle) * c.rimR;

      c.trail.push({x:c.x, y:c.y});
      if(c.trail.length > 90) c.trail.shift();

      // Full white-hot during rim
      c.heatT = Math.min(1.0, c.heatT + 0.012);

      // After N full orbits, begin consume
      if(c.rimAngAccum >= c.rimOrbits * Math.PI * 2){
        c.phase = 'consume';
        c.consumeT = 0;
        // Edge burn — quick purple flame at the rim
        flashes.push({
          kind: 'ring',
          life: 1.0,
          cr:180, cg:0, cb:255,
        });
        // EB logo pulse at BH center
        logoPulses.push({ life: 1.0 });
      }
    }

    // ── PHASE: consume — shrink and vanish into everblack ──
    else if(c.phase === 'consume'){
      c.consumeT += 0.095;
      c.rimR = Math.max(0, c.rimR * 0.80);
      c.rimAngle += c.rimSpeed * c.dir * 2.8;
      c.x = cx + Math.cos(c.rimAngle) * c.rimR;
      c.y = cy + Math.sin(c.rimAngle) * c.rimR;
      c.trail.push({x:c.x, y:c.y});
      if(c.trail.length > 30) c.trail.shift();

      if(c.consumeT >= 1.0){
        captured.splice(i,1);
        const idx = freeStars.indexOf(c.star);
        if(idx>-1) freeStars.splice(idx,1);
        continue;
      }
    }

    // ── DRAW ──
    const [hcr,hcg,hcb] = heatColor(c.heatT, c.cr, c.cg, c.cb);
    const fadeAlpha = c.phase==='consume' ? (1-c.consumeT) : 1.0;

    // Trail
    const trailLen = c.trail.length;
    for(let ti=1;ti<trailLen;ti++){
      const t0=c.trail[ti-1], t1=c.trail[ti];
      const trailFrac = ti/trailLen;
      const trailA = trailFrac * c.a * (0.45 + c.heatT*0.55) * 0.75 * fadeAlpha;
      const trailW = Math.max(0.2, c.r*(1-trailFrac*0.65)*(0.5+c.heatT*1.0));
      ctx.beginPath();
      ctx.moveTo(t0.x,t0.y);
      ctx.lineTo(t1.x,t1.y);
      ctx.strokeStyle=`rgba(${hcr},${hcg},${hcb},${trailA})`;
      ctx.lineWidth=trailW;
      ctx.lineCap='round';
      ctx.stroke();
    }

    // Rim phase: extra outer glow streak around the hole edge
    if(c.phase==='rim' || c.phase==='consume'){
      // Draw a glowing arc segment showing the recent sweep
      const arcSpan = Math.min(c.rimAngAccum, Math.PI * 1.4);
      const arcStart = c.rimAngle - arcSpan * c.dir;
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, c.rimR, arcStart, c.rimAngle, c.dir < 0);
      ctx.strokeStyle=`rgba(${hcr},${hcg},${hcb},${0.18*fadeAlpha})`;
      ctx.lineWidth = c.r * (2 + c.heatT*5);
      ctx.lineCap='round';
      ctx.stroke();
      ctx.restore();
    }

    // Glow halo
    const glowR = c.r*(2 + c.heatT*8) * (c.phase==='consume'?(1-c.consumeT*0.8):1);
    const glowA = c.a*(0.25+c.heatT*0.75)*fadeAlpha;
    const grd=ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,glowR);
    grd.addColorStop(0,`rgba(${hcr},${hcg},${hcb},${glowA})`);
    grd.addColorStop(1,'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(c.x,c.y,glowR,0,Math.PI*2);
    ctx.fillStyle=grd; ctx.fill();

    // Core
    const coreR = Math.max(0.2, c.r*(1+c.heatT*0.5)*fadeAlpha);
    ctx.beginPath(); ctx.arc(c.x,c.y,coreR,0,Math.PI*2);
    ctx.fillStyle=`rgba(${hcr},${hcg},${hcb},${c.a*fadeAlpha})`;
    ctx.fill();
  }
}

// ── Flashes / ring pulses ──
function updateDrawFlashes(){
  for(let i=flashes.length-1;i>=0;i--){
    const f=flashes[i];
    f.life -= 0.055;  // faster burn — gone quickly
    if(f.life<=0){ flashes.splice(i,1); continue; }

    if(f.kind==='ring'){
      const BHR  = Math.min(W,H)*0.30;
      // Edge burn — stays tight to the BH rim, fades fast
      // life goes 1→0; burn lives in a thin band just outside BHR
      const burnWidth = BHR * 0.18 * (0.3 + f.life * 0.7);
      const innerR = BHR - burnWidth * 0.1;
      const outerR = BHR + burnWidth;

      // Deep purple base glow hugging the edge
      const g1 = ctx.createRadialGradient(cx,cy,innerR,cx,cy,outerR*1.22);
      g1.addColorStop(0,   `rgba(60,0,100,0)`);
      g1.addColorStop(0.3, `rgba(100,0,180,${f.life*0.50})`);
      g1.addColorStop(0.6, `rgba(140,0,220,${f.life*0.30})`);
      g1.addColorStop(1,   `rgba(60,0,100,0)`);
      ctx.beginPath(); ctx.arc(cx,cy,outerR*1.22,0,Math.PI*2);
      ctx.fillStyle=g1; ctx.fill();

      // Violet flame core band — the actual burn
      const g2 = ctx.createRadialGradient(cx,cy,innerR,cx,cy,outerR);
      g2.addColorStop(0,   `rgba(100,0,160,0)`);
      g2.addColorStop(0.25,`rgba(160,0,240,${f.life*0.75})`);
      g2.addColorStop(0.55,`rgba(210,30,255,${f.life*0.95})`);
      g2.addColorStop(0.80,`rgba(180,10,255,${f.life*0.55})`);
      g2.addColorStop(1,   `rgba(100,0,160,0)`);
      ctx.beginPath(); ctx.arc(cx,cy,outerR,0,Math.PI*2);
      ctx.fillStyle=g2; ctx.fill();

      // White-hot inner edge — razor thin bright line right at the rim
      const g3 = ctx.createRadialGradient(cx,cy,BHR*0.96,cx,cy,BHR*1.06);
      g3.addColorStop(0,   `rgba(200,150,255,0)`);
      g3.addColorStop(0.45,`rgba(240,200,255,${f.life*0.70})`);
      g3.addColorStop(0.55,`rgba(255,255,255,${f.life*0.90})`);
      g3.addColorStop(1,   `rgba(180,100,255,0)`);
      ctx.beginPath(); ctx.arc(cx,cy,BHR*1.06,0,Math.PI*2);
      ctx.fillStyle=g3; ctx.fill();

      // Keep the black hole core solid black over everything
      ctx.beginPath(); ctx.arc(cx,cy,BHR,0,Math.PI*2);
      ctx.fillStyle='rgba(0,0,0,1)';
      ctx.fill();

    } else {
      f.r += f.maxR*0.08;
      const g=ctx.createRadialGradient(f.x,f.y,0,f.x,f.y,f.r);
      g.addColorStop(0,`rgba(${f.cr},${f.cg},${f.cb},${f.life*0.9})`);
      g.addColorStop(0.3,`rgba(${f.cr},${f.cg},${f.cb},${f.life*0.4})`);
      g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.beginPath(); ctx.arc(f.x,f.y,f.r,0,Math.PI*2);
      ctx.fillStyle=g; ctx.fill();
    }
  }
}

// ── Background nebula clouds — subtle, low opacity ──
const NEBULAE = [
  {r:60, g:20, b:140, a:0.13, ox:-0.32,oy:-0.28, orx:0.10,ory:0.07, ph:0.0,  sp:0.10, rad:0.70},
  {r:120,g:10, b:60,  a:0.10, ox: 0.35,oy: 0.22, orx:0.08,ory:0.09, ph:2.3,  sp:0.08, rad:0.65},
  {r:30, g:40, b:120, a:0.09, ox:-0.10,oy: 0.30, orx:0.12,ory:0.06, ph:4.1,  sp:0.12, rad:0.60},
  {r:80, g:15, b:80,  a:0.08, ox: 0.28,oy:-0.26, orx:0.09,ory:0.10, ph:1.5,  sp:0.09, rad:0.55},
  {r:20, g:50, b:100, a:0.08, ox:-0.30,oy: 0.08, orx:0.11,ory:0.05, ph:3.6,  sp:0.07, rad:0.68},
  {r:100,g:30, b:30,  a:0.07, ox: 0.15,oy: 0.35, orx:0.10,ory:0.08, ph:5.2,  sp:0.11, rad:0.50},
];

function drawNebulae(t){
  const tick = t * 0.00015;
  NEBULAE.forEach(b=>{
    const x = cx + (b.ox + Math.sin(tick*b.sp+b.ph)*b.orx) * W;
    const y = cy + (b.oy + Math.cos(tick*b.sp*0.7+b.ph)*b.ory) * H;
    const rad = b.rad * Math.max(W,H);
    const a = b.a * (0.8 + Math.sin(tick*b.sp*2+b.ph)*0.2);
    const g = ctx.createRadialGradient(x,y,0,x,y,rad);
    g.addColorStop(0,   `rgba(${b.r},${b.g},${b.b},${a})`);
    g.addColorStop(0.30,`rgba(${b.r},${b.g},${b.b},${a*0.50})`);
    g.addColorStop(0.65,`rgba(${b.r},${b.g},${b.b},${a*0.15})`);
    g.addColorStop(1,   `rgba(${b.r},${b.g},${b.b},0)`);
    ctx.beginPath(); ctx.arc(x,y,rad,0,Math.PI*2);
    ctx.fillStyle=g; ctx.fill();
  });
}

// ── Black hole — pure void, absolute darkness ──
// Just a subtle darkness — the "missing" stars are the tell
// Track how many stars are currently in rim/consume phase (for glow visibility)
function rimStarCount(){
  return captured.filter(c=>c.phase==='rim'||c.phase==='consume').length;
}

function drawBlackHole(){
  const R = Math.min(W,H)*0.30;

  // Subtle edge distortion — always on, very faint
  // Simulated as a thin noisy halo that shimmers — starlight bending at the photon sphere
  const distortR = R * 1.055;
  const distort = ctx.createRadialGradient(cx,cy,R*0.98,cx,cy,distortR);
  distort.addColorStop(0,  'rgba(0,0,0,0)');
  distort.addColorStop(0.4,`rgba(180,160,255,0.04)`);
  distort.addColorStop(0.7,`rgba(140,120,220,0.06)`);
  distort.addColorStop(1,  'rgba(0,0,0,0)');
  ctx.beginPath(); ctx.arc(cx,cy,distortR,0,Math.PI*2);
  ctx.fillStyle=distort; ctx.fill();

  // Hawking corona — only faintly visible when a star is being consumed
  const rimCount = rimStarCount();
  if(rimCount > 0){
    const coronaA = Math.min(1, rimCount * 0.6) * 0.07;
    const hawking = ctx.createRadialGradient(cx,cy,R*0.94,cx,cy,R*1.4);
    hawking.addColorStop(0,  'rgba(0,0,0,0)');
    hawking.addColorStop(0.4,`rgba(80,0,140,${coronaA})`);
    hawking.addColorStop(0.7,`rgba(50,0,90,${coronaA*0.4})`);
    hawking.addColorStop(1,  'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(cx,cy,R*1.4,0,Math.PI*2);
    ctx.fillStyle=hawking; ctx.fill();
  }

  // Absolute black core
  ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2);
  ctx.fillStyle='rgba(0,0,0,1)';
  ctx.fill();
}

// ── Render ──
function loop(t){
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle='#000005';
  ctx.fillRect(0,0,W,H);

  drawNebulae(t);
  drawBgStars();
  drawFreeStars();
  updateDrawCaptured();
  updateDrawFlashes();
  drawBlackHole();
  drawLogoPulses();

  requestAnimationFrame(loop);
}

// ── EB logo pulse draw ──
// Logo is always present inside the BH at low opacity.
// logoPulses add a brightness/glow burst on star consumption.
function drawLogoPulses(){
  if(!ebImg.complete) return;
  const BHR = Math.min(W,H)*0.30;
  // Fill most of the BH — logo sized to fit inside the circle
  const sz = BHR * 1.92;

  // Decay pulses and compute peak glow intensity
  let glowIntensity = 0;
  for(let i = logoPulses.length-1; i >= 0; i--){
    const p = logoPulses[i];
    p.life -= 0.016; // slow fade — gentle lingering glow
    if(p.life <= 0){ logoPulses.splice(i,1); continue; }
    glowIntensity = Math.max(glowIntensity, p.life);
  }

  // Logo is invisible at rest — only visible when glowing
  const baseAlpha = 0.0;
  const totalAlpha = baseAlpha + glowIntensity * 1.0;

  ctx.save();

  // Clip strictly to inside the black hole
  ctx.beginPath();
  ctx.arc(cx, cy, BHR * 0.96, 0, Math.PI*2);
  ctx.clip();

  // Draw logo at combined opacity
  ctx.globalAlpha = totalAlpha;
  ctx.globalCompositeOperation = 'source-over';
  ctx.drawImage(ebImg, cx - sz*0.5, cy - sz*0.5, sz, sz);

  // Purple tint — deeper at rest, vivid when glowing
  ctx.globalCompositeOperation = 'color';
  const tintAlpha = 0.70 + glowIntensity * 0.28;
  ctx.fillStyle = `rgba(160,0,255,${tintAlpha})`;
  ctx.fillRect(cx - sz*0.5, cy - sz*0.5, sz, sz);

  // Glow ring — only visible during pulse
  if(glowIntensity > 0.04){
    ctx.globalCompositeOperation = 'screen';
    const neon = ctx.createRadialGradient(cx,cy,sz*0.18,cx,cy,sz*0.62);
    neon.addColorStop(0,   'rgba(0,0,0,0)');
    neon.addColorStop(0.45,`rgba(180,0,255,${glowIntensity*0.50})`);
    neon.addColorStop(0.75,`rgba(120,0,200,${glowIntensity*0.22})`);
    neon.addColorStop(1,   'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.arc(cx, cy, sz*0.62, 0, Math.PI*2);
    ctx.fillStyle = neon; ctx.fill();
  }

  ctx.restore();
}

resize();
window.addEventListener('resize',resize);
restartCaptureTimer();
// Fire one immediately after a short delay
setTimeout(captureRandomStar, 20000);
setTimeout(spawnAndCapture, 40000);
requestAnimationFrame(loop);
</script>
""")

_INVENTORY = _page("""
<h1>Inventory</h1>
{% if role in ('admin', 'vendor') %}
<div class="card">
  <h2>Add / Update Item</h2>
  <form method="post" action="{{ url_for('inventory_add') }}">
{{ csrf_field }}
    <div class="form-row">
      {% if role == 'admin' %}
      <div class="field"><label>Vendors</label>
        {% for v in vendors %}
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem;color:#ccc;margin-bottom:2px">
          <input type="checkbox" name="vendor_ids" value="{{ v.id }}" checked> {{ v.name }}
        </label>
        {% endfor %}
      </div>
      {% endif %}
      <div class="field"><label>Category</label><input name="category" type="text" required></div>
      <div class="field"><label>Item</label><input name="item" type="text" required></div>
      <div class="field"><label>Qty</label><input name="qty" type="number" min="0" required style="width:80px"></div>
      <button class="btn btn-green" type="submit" style="align-self:flex-end">Save</button>
    </div>
  </form>
</div>
{% endif %}
<div class="card">
  <h2>Inventory ({{ items|length }} items)</h2>
  <div style="margin-bottom:1rem">
    <input id="inv-search" type="text" placeholder="Search items, category, ID..." oninput="filterInventory()"
      style="width:100%;max-width:420px;padding:.5rem .75rem;border-radius:6px;border:1px solid #2d6a4f;background:#1a2e1a;color:#e0e0e0;font-size:.95rem;outline:none">
  </div>
  {% if items %}
  <table id="inv-table">
    <tr>
      <th>ID</th>
      {% if role == 'admin' %}<th>Vendor</th>{% endif %}
      <th>Description</th><th>PLU</th><th>UPC</th><th>Unit Size</th><th>Cost/Unit</th>
      {% if role in ('admin', 'vendor') %}<th>QB Item Name</th><th>Visibility</th><th></th>{% endif %}
    </tr>
    {% for r in items %}
    <tr>
      <td style="color:#888;font-size:.85rem">{{ r.id }}</td>
      {% if role == 'admin' %}<td>{{ r.vendor_name }}</td>{% endif %}
      <td>{{ r.item }}</td>
      <td style="color:#aaa;font-size:.85rem">{{ r.plu or '&mdash;' }}</td>
      <td style="color:#aaa;font-size:.85rem">{{ r.upc or '&mdash;' }}</td>
      <td style="color:#aaa;font-size:.85rem">{{ r.unit_size or r.case_size or '&mdash;' }}</td>
      <td style="color:#6ee7b7;font-size:.85rem">${{ '%.2f'|format(r.price|float) if r.price else '&mdash;' }}</td>
      {% if role in ('admin', 'vendor') %}
      <td style="min-width:160px">
        <input type="text" class="qb-item-name-input"
          data-item-id="{{ r.id }}"
          value="{{ r.qb_item_name or '' }}"
          placeholder="Same as Item"
          style="width:100%;padding:.25rem .5rem;background:#1a2e1a;border:1px solid #2d6a4f;border-radius:4px;color:#e0e0e0;font-size:.85rem">
      </td>
      <td style="white-space:nowrap">
        {% set hidden_from = r._hidden_from %}
        {% if r._has_hann %}
          {% set hann_hidden = 'hannaford' in hidden_from %}
          <button type="button"
            data-item-id="{{ r.id }}" data-group="hannaford"
            onclick="ajaxToggleInv(this)"
            style="font-size:.75rem;padding:.2rem .55rem;border-radius:4px;border:none;cursor:pointer;background:{{ '#3a1a1a' if hann_hidden else '#1a3a2a' }};color:{{ '#f87171' if hann_hidden else '#52c97a' }}">{{ 'Show HH' if hann_hidden else 'Hide HH' }}</button>
        {% endif %}
        {% if r._has_mb %}
          {% set mb_hidden = 'marketbasket' in hidden_from %}
          <button type="button"
            data-item-id="{{ r.id }}" data-group="marketbasket"
            onclick="ajaxToggleInv(this)"
            style="font-size:.75rem;padding:.2rem .55rem;border-radius:4px;border:none;cursor:pointer;background:{{ '#3a1a1a' if mb_hidden else '#1a3a2a' }};color:{{ '#f87171' if mb_hidden else '#52c97a' }}">{{ 'Show MB' if mb_hidden else 'Hide MB' }}</button>
        {% endif %}
        {% if not r._has_hann and not r._has_mb %}
          {% set reg_hidden = 'regular' in hidden_from %}
          <button type="button"
            data-item-id="{{ r.id }}" data-group="regular"
            onclick="ajaxToggleInv(this)"
            style="font-size:.75rem;padding:.2rem .55rem;border-radius:4px;border:none;cursor:pointer;background:{{ '#3a1a1a' if reg_hidden else '#1a3a2a' }};color:{{ '#f87171' if reg_hidden else '#52c97a' }}">{{ 'Show' if reg_hidden else 'Hide' }}</button>
        {% endif %}
      </td>
      <td>
        <form method="post" action="{{ url_for('inventory_remove') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="category" value="{{ r.category }}">
          <input type="hidden" name="item" value="{{ r.item }}">
          <button class="btn btn-red" onclick="return confirm('Remove?')" style="font-size:.8rem;padding:.25rem .6rem">Remove</button>
        </form>
      </td>
      {% endif %}
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No inventory items.</p>{% endif %}
</div>
<script>
function filterInventory() {
  var q = document.getElementById('inv-search').value.toLowerCase();
  var rows = document.querySelectorAll('#inv-table tbody tr');
  rows.forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function saveQbItemName(input) {
  var itemId = input.getAttribute('data-item-id');
  var val = input.value.trim();
  var fd = new FormData();
  fd.append('item_id', itemId);
  fd.append('qb_item_name', val);
  fetch('/inventory/set_qb_item_name', {method:'POST', body:fd})
    .then(function(r){ return r.json(); })
    .then(function(d){
      _invToast(d.ok ? '\u2713 QB name saved' : (d.error || 'Error'), !d.ok);
      if(d.ok) { input.style.borderColor='#52c97a'; setTimeout(function(){ input.style.borderColor='#2d6a4f'; },1500); }
    })
    .catch(function(){ _invToast('Save failed', true); });
}

document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('.qb-item-name-input').forEach(function(inp){
    inp.addEventListener('blur', function(){ saveQbItemName(inp); });
    inp.addEventListener('keydown', function(e){ if(e.key==='Enter'){ e.preventDefault(); inp.blur(); } });
  });
});

function _invToast(msg, err) {
  var t = document.getElementById('inv-toast');
  if (!t) {
    t = document.createElement('div'); t.id = 'inv-toast';
    t.style.cssText = 'position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);'
      +'padding:.6rem 1.4rem;border-radius:8px;font-size:.9rem;font-weight:600;'
      +'z-index:9999;transition:opacity .4s;pointer-events:none;max-width:90vw;text-align:center';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.background = err ? '#7f1d1d' : '#14532d';
  t.style.color = err ? '#fca5a5' : '#86efac';
  t.style.opacity = '1';
  clearTimeout(t._h);
  t._h = setTimeout(function(){ t.style.opacity = '0'; }, 3000);
}

function ajaxToggleInv(btn) {
  var itemId = btn.getAttribute('data-item-id');
  var group  = btn.getAttribute('data-group');
  var fd = new FormData();
  fd.append('item_id', itemId);
  fd.append('group', group);
  btn.disabled = true;
  fetch('/inventory/toggle_visibility', {
    method: 'POST',
    headers: {'X-Requested-With': 'XMLHttpRequest'},
    body: fd
  }).then(function(r){ return r.json(); }).then(function(r) {
    btn.disabled = false;
    _invToast(r.msg, !r.ok);
    if (!r.ok) return;
    var hidden = r.hidden;
    var labelMap = {hannaford:'HH', marketbasket:'MB', regular:''};
    var lbl = labelMap[group] || '';
    btn.textContent = hidden ? ('Show' + (lbl ? ' '+lbl : '')) : ('Hide' + (lbl ? ' '+lbl : ''));
    btn.style.background = hidden ? '#3a1a1a' : '#1a3a2a';
    btn.style.color      = hidden ? '#f87171' : '#52c97a';
    btn.style.outline = '2px solid ' + (hidden ? '#f87171' : '#52c97a');
    setTimeout(function(){ btn.style.outline = ''; }, 600);
  }).catch(function(e) { btn.disabled = false; _invToast('Error: ' + e, true); });
}
</script>
""")

_CATALOG = _page("""
{% if request.args.get('submitted') %}
<div id="order-modal" style="position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:flex;align-items:center;justify-content:center">
  <div style="background:#1a2e1a;border:1px solid #2d6a4f;border-radius:12px;padding:2rem 2.5rem;max-width:420px;width:90%;text-align:center">
    <div style="font-size:3rem;margin-bottom:.5rem">&#10003;</div>
    <h2 style="color:#52c97a;margin:0 0 .5rem">Order Submitted!</h2>
    <p style="color:#aaa;margin-bottom:1.5rem">{{ request.args.get('submitted') }} item(s) ordered for {{ request.args.get('date') }}.</p>
    <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap">
      <button onclick="dismissModal()" class="btn btn-green">Place Another Order</button>
      <a href="{{ url_for('orders') }}" class="btn btn-blue">View Orders</a>
    </div>
  </div>
</div>
{% endif %}
<h1>Place an Order</h1>
{% if available_vendors|length > 1 %}
<div style="display:flex;gap:.5rem;margin-bottom:1.25rem;flex-wrap:wrap">
  {% for v in available_vendors %}
  <a href="{{ url_for('catalog', vendor=v.id) }}"
     class="btn {% if v.id == selected_vendor.id %}btn-green{% else %}btn-blue{% endif %}"
     style="font-size:.9rem">{{ v.name }}</a>
  {% endfor %}
</div>
{% endif %}
{% if selected_vendor %}
<p style="color:#a0aec0;font-size:.9rem;margin-bottom:1rem">Ordering from: <strong style="color:#52c97a">{{ selected_vendor.name }}</strong></p>
{% endif %}
<div style="margin-bottom:1rem">
  <input type="text" id="catalog-search" placeholder="Search items..." oninput="filterCatalog(this.value)"
    style="width:100%;box-sizing:border-box;padding:.55rem .85rem;background:#1e1e1e;border:1px solid rgba(255,255,255,0.15);border-radius:8px;color:#e0e0e0;font-size:.95rem;outline:none">
</div>
<script>
function filterCatalog(q){
  q = q.trim().toLowerCase();
  document.querySelectorAll('.accordion-item').forEach(function(section){
    var rows = section.querySelectorAll('tr[data-item]');
    var visible = 0;
    rows.forEach(function(row){
      var match = !q || row.dataset.item.indexOf(q) !== -1;
      row.style.display = match ? '' : 'none';
      if(match) visible++;
    });
    section.style.display = visible === 0 && q ? 'none' : '';
    if(q && visible > 0){
      var body = section.querySelector('.accordion-body');
      if(body) body.style.display = '';
    }
  });
}
</script>
<form method="post" action="{{ url_for('catalog_submit') }}" id="catalog-form">
{{ csrf_field }}
<input type="hidden" name="vendor_id" value="{{ selected_vendor.id if selected_vendor else 'gmf' }}">
{% for category, items in catalog.items() %}
<div class="accordion-item" style="margin-bottom:.75rem">
  <button type="button" class="cat-header accordion-btn" onclick="toggleAccordion(this)"
    style="width:100%;text-align:left;cursor:pointer;display:flex;justify-content:space-between;align-items:center;border:none">
    <span>{{ category }}</span>
    <span class="acc-arrow" style="font-size:1.1rem;transition:transform .2s">&#x25BC;</span>
  </button>
  <div class="accordion-body" style="display:none">
    <table style="width:100%;border-collapse:collapse;margin-bottom:.5rem">
    {% for item in items %}
    <tr style="border-bottom:1px solid #2a2a2a" data-item="{{ item.item | lower }}">
      <td style="padding:.5rem .75rem;color:#ccc">
        {{ item.item }}
        {% if item.case_size %}<span style="font-size:.75rem;color:#52c97a;margin-left:.4rem">({{ item.case_size }} / case)</span>{% endif %}
      </td>
      <td style="padding:.5rem .75rem;width:120px">
        <div style="display:flex;align-items:center;gap:.4rem">
          <input type="number" class="qty-input" name="qty_{{ item.id }}" min="0"
            onchange="updateCart()" oninput="updateCart()" placeholder=""
            style="width:70px;text-align:center">
          <span style="font-size:.8rem;color:#888">qty</span>
        </div>
      </td>
    </tr>
    {% endfor %}
    </table>
  </div>
</div>
{% endfor %}
<!-- Desktop submit bar (hidden on mobile) -->
<div id="submit-bar-desktop" class="card" style="position:sticky;bottom:1rem;z-index:10;margin-top:1rem">
  <div style="display:flex;flex-wrap:wrap;gap:.75rem;align-items:flex-end">
    <div class="field"><label>Delivery Date</label>
      <div style="display:flex;align-items:center;gap:.4rem">
        <button type="button" id="date-prev" onclick="stepDate(-1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.3rem .6rem;cursor:pointer;font-size:1rem">&#9664;</button>
        <span id="date-display" style="min-width:110px;text-align:center;color:#e0e0e0;font-size:.95rem"></span>
        <button type="button" id="date-next" onclick="stepDate(1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.3rem .6rem;cursor:pointer;font-size:1rem">&#9654;</button>
      </div>
      <input type="hidden" name="date" id="delivery-date" required>
      <script>
      (function(){
        var allowed = {{ allowed_dates | tojson }};
        var today = new Date();
        today.setHours(0,0,0,0);
        var future = allowed.filter(function(d){ return new Date(d+'T00:00:00') > today; }).sort();
        if(!future.length){
          var d=new Date(); d.setDate(d.getDate()+1);
          future=[d.toISOString().split('T')[0]];
        }
        window._dateOptions = future;
        window._dateIdx = 0;
        function renderDate(){
          var d = window._dateOptions[window._dateIdx];
          document.getElementById('delivery-date').value = d;
          document.getElementById('date-display').textContent = d;
          if(document.getElementById('sheet-date-display')) document.getElementById('sheet-date-display').textContent = d;
          document.getElementById('date-prev').disabled = window._dateIdx === 0;
          document.getElementById('date-prev').style.opacity = window._dateIdx === 0 ? '0.35' : '1';
          document.getElementById('date-next').disabled = window._dateIdx === window._dateOptions.length - 1;
          document.getElementById('date-next').style.opacity = window._dateIdx === window._dateOptions.length - 1 ? '0.35' : '1';
          if(document.getElementById('sheet-date-prev')) document.getElementById('sheet-date-prev').style.opacity = window._dateIdx === 0 ? '0.35' : '1';
          if(document.getElementById('sheet-date-next')) document.getElementById('sheet-date-next').style.opacity = window._dateIdx === window._dateOptions.length - 1 ? '0.35' : '1';
        }
        window.stepDate = function(dir){
          var next = window._dateIdx + dir;
          if(next >= 0 && next < window._dateOptions.length){ window._dateIdx = next; renderDate(); }
        };
        renderDate();
      })();
      </script>
    </div>
    <div class="field"><label>Placed By</label><input type="text" name="ordered_by" id="ordered-by-desktop" value="{{ session.username }}" required></div>
    <div class="field"><label>Confirmation Email</label><input type="email" name="confirm_email" id="confirm-email-desktop" placeholder="your@email.com"></div>
    <button class="btn btn-steel" type="submit" style="align-self:flex-end">
      Submit Order <span id="cart-count" class="cart-badge" style="display:none"></span>
    </button>
  </div>
</div>
</form>

<!-- Mobile FAB + bottom sheet (hidden on desktop) -->
<div id="mobile-fab" onclick="openOrderSheet()" style="display:none;position:fixed;bottom:1.5rem;right:1.25rem;z-index:200;
  background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff;border-radius:999px;
  padding:.75rem 1.25rem;font-size:1rem;font-weight:700;box-shadow:0 4px 20px rgba(124,58,237,0.6);
  cursor:pointer;align-items:center;gap:.5rem;user-select:none">
  🛒 Order <span id="fab-count" style="background:rgba(255,255,255,0.25);border-radius:999px;padding:.1rem .45rem;font-size:.82rem;margin-left:.2rem;display:none"></span>
</div>

<!-- Bottom sheet overlay -->
<div id="order-sheet-overlay" onclick="closeOrderSheet()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:300"></div>
<div id="order-sheet" style="display:none;position:fixed;bottom:0;left:0;right:0;z-index:400;
  background:#0e0e1a;border-top:1px solid rgba(139,92,246,0.4);border-radius:18px 18px 0 0;
  padding:1.25rem 1.25rem 2rem;box-shadow:0 -8px 40px rgba(0,0,0,0.7);
  transition:transform .28s cubic-bezier(.4,0,.2,1)">
  <div style="width:40px;height:4px;background:rgba(255,255,255,0.2);border-radius:999px;margin:0 auto .75rem"></div>
  <h2 style="margin-bottom:1rem;font-size:1rem">Submit Order</h2>
  <!-- Date picker -->
  <div style="margin-bottom:.85rem">
    <label style="display:block;font-size:.72rem;font-weight:600;color:#a0aec0;margin-bottom:.3rem;letter-spacing:.8px;text-transform:uppercase">Delivery Date</label>
    <div style="display:flex;align-items:center;gap:.5rem">
      <button type="button" id="sheet-date-prev" onclick="stepDate(-1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.45rem .75rem;cursor:pointer;font-size:1rem;min-height:44px">&#9664;</button>
      <span id="sheet-date-display" style="flex:1;text-align:center;color:#e0e0e0;font-size:1rem;font-weight:600"></span>
      <button type="button" id="sheet-date-next" onclick="stepDate(1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.45rem .75rem;cursor:pointer;font-size:1rem;min-height:44px">&#9654;</button>
    </div>
  </div>
  <!-- Placed by -->
  <div style="margin-bottom:.85rem">
    <label style="display:block;font-size:.72rem;font-weight:600;color:#a0aec0;margin-bottom:.3rem;letter-spacing:.8px;text-transform:uppercase">Placed By</label>
    <input type="text" id="sheet-ordered-by" value="{{ session.username }}" style="width:100%;padding:.55rem .75rem;background:rgba(255,255,255,0.06);border:1px solid rgba(139,92,246,0.25);border-radius:7px;color:#e2e8f0;font-size:.95rem">
  </div>
  <!-- Email -->
  <div style="margin-bottom:1.1rem">
    <label style="display:block;font-size:.72rem;font-weight:600;color:#a0aec0;margin-bottom:.3rem;letter-spacing:.8px;text-transform:uppercase">Confirmation Email <span style="font-weight:400;text-transform:none;color:#666">(optional)</span></label>
    <input type="email" id="sheet-confirm-email" placeholder="your@email.com" style="width:100%;padding:.55rem .75rem;background:rgba(255,255,255,0.06);border:1px solid rgba(139,92,246,0.25);border-radius:7px;color:#e2e8f0;font-size:.95rem">
  </div>
  <!-- Submit -->
  <button type="button" onclick="submitFromSheet()" style="width:100%;padding:.85rem;background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:700;cursor:pointer;box-shadow:0 4px 16px rgba(124,58,237,0.45);min-height:52px">
    Confirm &amp; Submit <span id="sheet-cart-count" style="opacity:.8;font-size:.88rem"></span>
  </button>
  <button type="button" onclick="closeOrderSheet()" style="width:100%;margin-top:.65rem;padding:.65rem;background:none;border:1px solid rgba(255,255,255,0.12);border-radius:10px;color:#aaa;font-size:.9rem;cursor:pointer">Cancel</button>
</div>
<script>
(function(){
  var isMobile = window.matchMedia('(max-width:640px)').matches;
  if(isMobile){
    document.getElementById('submit-bar-desktop').style.display = 'none';
    document.getElementById('mobile-fab').style.display = 'flex';
    // Sync sheet date display on load
    var dd = document.getElementById('delivery-date');
    if(dd && document.getElementById('sheet-date-display'))
      document.getElementById('sheet-date-display').textContent = dd.value;
  }
  // Keep cart badge in sync on both FAB and desktop bar
  var _origUpdateCart = window.updateCart;
  window.updateCart = function(){
    if(_origUpdateCart) _origUpdateCart();
    var inputs = document.querySelectorAll('.qty-input');
    var count = 0;
    inputs.forEach(function(i){ if(parseInt(i.value) > 0) count++; });
    var fab = document.getElementById('fab-count');
    var sheetCount = document.getElementById('sheet-cart-count');
    if(fab){ fab.style.display = count > 0 ? 'inline' : 'none'; fab.textContent = count; }
    if(sheetCount) sheetCount.textContent = count > 0 ? '(' + count + ' item' + (count > 1 ? 's' : '') + ')' : '';
  };
})();
function openOrderSheet(){
  var overlay = document.getElementById('order-sheet-overlay');
  var sheet = document.getElementById('order-sheet');
  overlay.style.display = 'block';
  sheet.style.display = 'block';
  // Sync current date
  var dd = document.getElementById('delivery-date');
  if(dd && document.getElementById('sheet-date-display'))
    document.getElementById('sheet-date-display').textContent = dd.value;
  document.body.style.overflow = 'hidden';
}
function closeOrderSheet(){
  document.getElementById('order-sheet-overlay').style.display = 'none';
  document.getElementById('order-sheet').style.display = 'none';
  document.body.style.overflow = '';
}
function submitFromSheet(){
  // Copy sheet values into hidden desktop form fields before submit
  var ob = document.getElementById('sheet-ordered-by');
  var ce = document.getElementById('sheet-confirm-email');
  var obD = document.getElementById('ordered-by-desktop');
  var ceD = document.getElementById('confirm-email-desktop');
  if(ob && obD) obD.value = ob.value;
  if(ce && ceD) ceD.value = ce.value;
  closeOrderSheet();
  document.getElementById('catalog-form').submit();
}
</script>
<script>
function toggleAccordion(btn){
  var body = btn.nextElementSibling;
  var arrow = btn.querySelector('.acc-arrow');
  var isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  arrow.style.transform = isOpen ? '' : 'rotate(180deg)';
}
function updateCart(){
  var inputs=document.querySelectorAll('.qty-input');
  var count=0;
  inputs.forEach(function(i){if(parseInt(i.value)>0)count++;});
  var badge=document.getElementById('cart-count');
  if(count>0){badge.style.display='inline';badge.textContent=count+' item'+(count>1?'s':'');}
  else{badge.style.display='none';}
}
function dismissModal(){
  document.getElementById('order-modal').style.display='none';
  document.querySelectorAll('.qty-input').forEach(function(i){i.value='';});
  updateCart();
  // Strip submitted params from URL without reload
  var url=new URL(window.location); url.searchParams.delete('submitted'); url.searchParams.delete('date');
  window.history.replaceState({},document.title,url.toString());
}
</script>
""")


_ORDER_SUCCESS = _page("""
<div style="max-width:480px;margin:6rem auto;text-align:center">
  <div style="font-size:5rem;margin-bottom:1rem">&#10003;</div>
  <h1 style="color:#52c97a;margin:0 0 .5rem">Order Submitted!</h1>
  <p style="color:#aaa;font-size:1.1rem;margin-bottom:.5rem">{{ count }} item(s) ordered for <strong style="color:#fff">{{ date }}</strong>.</p>
  <p style="color:#888;font-size:.9rem;margin-bottom:2rem">Your order has been received.</p>
  <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap">
    <a href="{{ url_for('catalog') }}" class="btn btn-green" style="font-size:1rem;padding:.6rem 1.4rem">Place Another Order</a>
    <a href="{{ url_for('orders') }}" class="btn btn-blue" style="font-size:1rem;padding:.6rem 1.4rem">View Orders</a>
  </div>
</div>
""")

_ORDERS = _page("""
<h1>Orders</h1>
{% if session.role == 'store' %}
<div style="margin-bottom:1rem;display:flex;gap:.75rem;flex-wrap:wrap;align-items:center">
  <a href="{{ url_for('catalog') }}" class="btn btn-green">Place New Order</a>
</div>
{% endif %}
{% if session.role == 'vendor' and vendor_stores %}
<div class="card">
  <h2>Create Order</h2>
  <form method="post" action="{{ url_for('orders_add') }}" id="vendor-order-form">
{{ csrf_field }}
    <div class="form-row">
      <div class="field">
        <label>Store</label>
        <select name="store" required id="vendor-store-select" onchange="vendorStoreChanged(this)">
          <option value="">— select store —</option>
          {% for s in vendor_stores %}
          <option value="{{ s.store_name }}" data-storenum="{{ s.store_number }}">{{ s.store_name }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="field">
        <label>Item</label>
        <select name="item" required id="vendor-item-select" onchange="vendorItemChanged(this)">
          <option value="">— select store first —</option>
          {% for i in vendor_inv_items %}
          <option value="{{ i.item }}" data-category="{{ i.category }}" data-case="{{ i.case_size or '' }}" data-stores="{{ i.stores_flat }}">{{ i.category }} — {{ i.item }}{% if i.case_size %} ({{ i.case_size }}){% endif %}</option>
          {% endfor %}
        </select>
      </div>
      <input type="hidden" name="category" id="vendor-category-hidden">
      <div class="field">
        <label>Qty</label>
        <input name="qty" type="number" min="1" required style="width:80px" value="1">
      </div>
      <div class="field">
        <label>Delivery Date</label>
        <input type="date" name="date" id="vendor-order-date" required>
        <script>
        (function(){
          var today = new Date();
          var tyyyy = today.getFullYear();
          var tmm = String(today.getMonth()+1).padStart(2,'0');
          var tdd = String(today.getDate()).padStart(2,'0');
          var todayStr = tyyyy+'-'+tmm+'-'+tdd;
          var d = new Date(); d.setDate(d.getDate() + 1);
          var yyyy = d.getFullYear();
          var mm = String(d.getMonth()+1).padStart(2,'0');
          var dd = String(d.getDate()).padStart(2,'0');
          document.getElementById('vendor-order-date').value = yyyy+'-'+mm+'-'+dd;
          document.getElementById('vendor-order-date').min = todayStr;
        })();
        </script>
      </div>
      <div class="field"><label>Placed By</label><input name="ordered_by" type="text" value="{{ session.username }}" required></div>
    </div>
    <button class="btn btn-green" type="submit">Submit Order</button>
  </form>
  <script>
  var VENDOR_ITEMS = [{% for i in vendor_inv_items %}{"v":{{ i.item|tojson }},"c":{{ i.category|tojson }},"s":{{ i.stores_flat|tojson }},"cs":{{ (i.case_size or "")|tojson }}}{% if not loop.last %},{% endif %}{% endfor %}];

  function buildItemSelect(sel, storeNum) {
    var prev = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    VENDOR_ITEMS.forEach(function(it) {
      var ok = !storeNum ? !it.s : it.s.split(",").indexOf(storeNum) !== -1;
      if (!ok) return;
      var o = document.createElement("option");
      o.value = it.v;
      o.dataset.category = it.c;
      o.dataset.stores = it.s;
      o.textContent = it.c + " — " + it.v + (it.cs ? " (" + it.cs + ")" : "");
      sel.appendChild(o);
    });
    sel.value = prev;
  }

  function setCatField(form, sel) {
    var f = form.querySelector(".add-cat-field, #vendor-category-hidden");
    var o = sel.options[sel.selectedIndex];
    if (f) f.value = o ? (o.dataset.category || "") : "";
  }

  function vendorStoreChanged(storeSel) {
    var opt = storeSel.options[storeSel.selectedIndex];
    var sn = opt ? (opt.getAttribute("data-storenum") || "") : "";
    var itemSel = document.getElementById("vendor-item-select");
    if (itemSel) { buildItemSelect(itemSel, sn); setCatField(itemSel.closest("form"), itemSel); }
  }

  function vendorItemChanged(sel) { setCatField(sel.closest("form"), sel); }

  document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll(".add-item-select").forEach(function(sel) {
      buildItemSelect(sel, sel.getAttribute("data-storenum") || "");
      sel.addEventListener("change", function() { setCatField(sel.closest("form"), sel); });
    });
  });
  </script>
</div>
{% endif %}
{% if session.role == 'admin' %}
<div class="card">
  <h2>Submit Order</h2>
  <form method="post" action="{{ url_for('orders_add') }}">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Store</label><input name="store" type="text" required></div>
      <div class="field"><label>Category</label><input name="category" type="text" required></div>
      <div class="field"><label>Item</label><input name="item" type="text" required></div>
      <div class="field"><label>Qty</label><input name="qty" type="number" min="1" required style="width:80px"></div>
      <div class="field">
        <label>Delivery Date</label>
        <input type="date" name="date" id="delivery-date" required>
        <script>
        (function(){
          var today = new Date();
          var tyyyy = today.getFullYear();
          var tmm = String(today.getMonth()+1).padStart(2,'0');
          var tdd = String(today.getDate()).padStart(2,'0');
          var todayStr = tyyyy+'-'+tmm+'-'+tdd;
          var d = new Date(); d.setDate(d.getDate() + 1);
          var yyyy = d.getFullYear();
          var mm = String(d.getMonth()+1).padStart(2,'0');
          var dd = String(d.getDate()).padStart(2,'0');
          document.getElementById('delivery-date').value = yyyy+'-'+mm+'-'+dd;
          document.getElementById('delivery-date').min = todayStr;
        })();
        </script>
      </div>
      <div class="field"><label>Placed By</label><input name="ordered_by" type="text" value="{{ session.username }}" required></div>
    </div>
    <button class="btn btn-steel" type="submit">Submit Order</button>
  </form>
</div>
{% endif %}
{% if session.role == 'admin' %}
<div class="card">
  <h2>Filter Orders</h2>
  <form method="get" action="{{ url_for('orders') }}">
    <div class="form-row">
      <div class="field"><label>Store</label><input name="store" type="text" value="{{ filter_store }}"></div>
      <div class="field"><label>Date</label><input name="date" type="date" value="{{ filter_date }}"></div>
      <div class="field"><label>Item</label><input name="item" type="text" value="{{ filter_item }}"></div>
      <button class="btn btn-blue" type="submit" style="align-self:flex-end">Filter</button>
      <a href="{{ url_for('orders') }}" class="btn btn-blue" style="text-decoration:none;align-self:flex-end">Clear</a>
    </div>
  </form>
</div>
{% endif %}
{% if True %}
<div class="card">
  <h2>Browse by Date</h2>
  <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.25rem">
    <button type="button" id="orders-date-prev" onclick="ordersStepDate(-1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:1rem">&#9664;</button>
    <span id="orders-date-display" style="min-width:120px;text-align:center;color:#e0e0e0;font-size:1rem;font-weight:600"></span>
    <button type="button" id="orders-date-next" onclick="ordersStepDate(1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:1rem">&#9654;</button>
  </div>
  <script>
  (function(){
    var current = {{ filter_date | tojson }};
    document.getElementById('orders-date-display').textContent = current;
    function stepDay(dateStr, dir){
      var d = new Date(dateStr + 'T00:00:00');
      d.setDate(d.getDate() + dir);
      return d.toISOString().slice(0,10);
    }
    window.ordersStepDate = function(dir){
      window.location.href = '{{ url_for("orders") }}?date=' + stepDay(current, dir);
    };
  })();
  </script>
</div>
{% endif %}
<div class="card">
  <h2 style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem">{% if session.role == 'store' %}Your Orders{% if request.args.get('date') %} — {{ filter_date }}{% endif %} ({{ order_group_count }} order{{ 's' if order_group_count != 1 else '' }}){% elif session.role == 'driver' %}{{ session.driver_area|capitalize }} Area Orders{% else %}All Orders{% endif %}{% if session.role != 'store' %} — {{ filter_date }} ({% if session.role == 'vendor' %}{{ order_group_count }} order group{{ 's' if order_group_count != 1 else '' }}, {{ order_list|length }} item{{ 's' if order_list|length != 1 else '' }}{% else %}{{ order_list|length }}{% endif %}){% endif %}
  {% if session.role in ('vendor', 'admin') and order_list %}<a href="{{ url_for('orders_export_csv', date=filter_date, store=filter_store, item=filter_item) }}" class="btn btn-blue no-print" style="font-size:.8rem;padding:.3rem .75rem;text-decoration:none;font-weight:600">&#8595; Export CSV</a>{% endif %}</h2>
  {% if order_list %}

  {# ── Vendor grouped view ── #}
  {% if session.role == 'vendor' %}
    {% set ns = namespace(last_key='', last_store='', last_date='', last_by='') %}
    {% for o in order_list|sort(attribute='store_name') %}
      {% set group_key = o.store_name ~ '|' ~ o.delivery_date ~ '|' ~ o.ordered_by %}
      {% if group_key != ns.last_key %}
        {% if ns.last_key != '' %}
          {% set _gsnum = (vendor_stores | selectattr('store_name','equalto',ns.last_store) | map(attribute='store_number') | list | first) or '' %}
          </table>
          <div style="padding:.4rem .75rem .6rem;background:rgba(0,0,0,0.15);border-top:1px solid rgba(255,255,255,0.06)">
            <form method="post" action="{{ url_for('orders_add') }}" class="add-item-form" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
{{ csrf_field }}
              <input type="hidden" name="store" value="{{ ns.last_store }}">
              <input type="hidden" name="date" value="{{ ns.last_date }}">
              <input type="hidden" name="ordered_by" value="{{ ns.last_by }}">
              <input type="hidden" name="category" class="add-cat-field" value="">
              <select name="item" required class="add-item-select" data-storenum="{{ _gsnum }}"
                style="padding:.28rem .5rem;background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:5px;color:#e0e0e0;font-size:.8rem;min-width:220px">
                <option value="">— add item —</option>
                {% for i in vendor_inv_items %}<option value="{{ i.item }}" data-category="{{ i.category }}" data-stores="{{ i.stores_flat }}">{{ i.category }} — {{ i.item }}</option>{% endfor %}
              </select>
              <input type="number" name="qty" min="1" value="1" style="width:60px;padding:.28rem .4rem;background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:5px;color:#e0e0e0;font-size:.8rem">
              <button type="submit" class="btn btn-green" style="font-size:.76rem;padding:.28rem .65rem">+ Add</button>
            </form>
          </div>
        </div>
        {% endif %}
        {% set ns.last_key = group_key %}
        {% set ns.last_store = o.store_name %}
        {% set ns.last_date = o.delivery_date %}
        {% set ns.last_by = o.ordered_by %}
        <div data-group-key="{{ group_key }}" style="margin-bottom:1.25rem;border:1px solid rgba(255,255,255,0.08);border-radius:10px;overflow:hidden">
        <div style="background:rgba(255,255,255,0.04);padding:.6rem 1rem;display:flex;gap:2rem;flex-wrap:wrap;align-items:center">
          <span style="font-weight:700;color:#52c97a;font-size:1rem">{{ o.store_name }}</span>
          <span style="color:#aaa;font-size:.85rem">Delivery: <strong style="color:#ddd">{{ o.delivery_date }}</strong></span>
          <span style="color:#aaa;font-size:.85rem">Submitted by: <strong style="color:#ddd">{{ o.ordered_by }}</strong></span>
          <span style="color:#aaa;font-size:.85rem">{{ o.submitted_at }}</span>
          {% set _inv = inv_lookup.get((session.vendor_id or session.vendor_ids[0] if session.vendor_ids else 'gmf', o.store_name, o.delivery_date)) %}
          {% if _inv %}
            <span style="color:#52c97a;font-size:.85rem;font-weight:600">✅ Invoice #{% if _inv.qb_doc_number %}{{ _inv.qb_doc_number }}{% else %}{{ _inv.id }}{% endif %}{% if _inv.total %} — <strong>${{ '%.2f'|format(_inv.total|float) }}</strong>{% endif %}</span>
            <a href="{{ url_for('invoice_view', invoice_id=_inv.id) }}" class="btn" style="font-size:.8rem;padding:.3rem .8rem;margin-left:auto;text-decoration:none">View Invoice</a>
          {% else %}
          <form method="post" action="{{ url_for('invoices_from_orders') }}" style="margin-left:auto">
{{ csrf_field }}
            <input type="hidden" name="store" value="{{ o.store_name }}">
            <input type="hidden" name="date" value="{{ o.delivery_date }}">
            <button type="submit" class="btn btn-green" style="font-size:.8rem;padding:.3rem .8rem">+ Create Invoice</button>
          </form>
          {% endif %}
          {% if vendor_plan in ('standard', 'pro', 'seasonal', 'admin') %}
          <button onclick="window.print()" class="btn" style="font-size:.8rem;padding:.3rem .8rem" id="print-btn-row">🖨 Print / Save PDF</button>
          {% endif %}
          <button type="button" class="btn btn-red" style="font-size:.8rem;padding:.3rem .8rem;margin-left:.5rem" onclick="ajaxRemoveGroup(this,{{ o.store_name|tojson }},{{ o.delivery_date|tojson }},{{ o.ordered_by|tojson }},{{ (o.submitted_at[:16] if o.submitted_at else '')|tojson }})">🗑 Remove Order</button>
        </div>
        <table style="margin:0;border-radius:0">
          <tr><th>Order #</th><th>Item</th><th>Qty</th><th>Barcode</th><th></th></tr>
      {% endif %}
      <tr>
        <td style="color:#888;font-size:.85rem">#{{ o.id }}</td>
        <td>{{ o.item }}{% if o.case_size %} <span style="font-size:.75rem;color:#888">({{ o.case_size }} / case)</span>{% endif %}</td>
        <td id="qty-cell-{{ o.id }}">
          <span id="qty-display-{{ o.id }}">{{ o.disp_qty }}</span>
          <form id="qty-form-{{ o.id }}" method="post" action="{{ url_for('orders_update_qty') }}" style="display:none;margin:0">
            <input type="hidden" name="id" value="{{ o.id }}">
            <input type="number" name="qty" value="{{ o.qty }}" min="1" style="width:60px;padding:.2rem .4rem;font-size:.9rem;background:#1a1a2e;border:1px solid #7c3aed;border-radius:4px;color:#fff">
            <button type="button" onclick="submitQty({{ o.id }})" class="btn btn-green" style="font-size:.75rem;padding:.2rem .5rem;margin-left:.25rem">✓</button>
            <button type="button" onclick="cancelEditQty({{ o.id }})" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#333">✕</button>
          </form>
        </td>
        <td>
          {% if vendor_plan == 'pro' or vendor_plan == 'admin' %}
          {% if o.upc and o.upc != 'None' %}
          <svg class="barcode" data-upc="{{ o.upc }}" style="display:block;min-width:120px"></svg>
          <div style="font-size:.7rem;color:#666;text-align:center;margin-top:2px">{{ o.upc }}</div>
          {% else %}&mdash;{% endif %}
          {% else %}&mdash;{% endif %}
        </td>
        <td>
          <button onclick="editQty({{ o.id }})" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#2d2d4e;margin-bottom:.25rem">✏ Qty</button>
          <button type="button" onclick="ajaxRemoveItem(this,{{ o.id }})" class="btn btn-red" style="font-size:.8rem;padding:.25rem .6rem">✕ Remove</button>
        </td>
      </tr>
    {% endfor %}
    {% if ns.last_key != '' %}
      {% set _gsnum = (vendor_stores | selectattr('store_name','equalto',ns.last_store) | map(attribute='store_number') | list | first) or '' %}
      </table>
      <div style="padding:.4rem .75rem .6rem;background:rgba(0,0,0,0.15);border-top:1px solid rgba(255,255,255,0.06)">
        <form method="post" action="{{ url_for('orders_add') }}" class="add-item-form" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
{{ csrf_field }}
          <input type="hidden" name="store" value="{{ ns.last_store }}">
          <input type="hidden" name="date" value="{{ ns.last_date }}">
          <input type="hidden" name="ordered_by" value="{{ ns.last_by }}">
          <input type="hidden" name="category" class="add-cat-field" value="">
          <select name="item" required class="add-item-select" data-storenum="{{ _gsnum }}"
            style="padding:.28rem .5rem;background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:5px;color:#e0e0e0;font-size:.8rem;min-width:220px">
            <option value="">— add item —</option>
            {% for i in vendor_inv_items %}<option value="{{ i.item }}" data-category="{{ i.category }}" data-stores="{{ i.stores_flat }}">{{ i.category }} — {{ i.item }}</option>{% endfor %}
          </select>
          <input type="number" name="qty" min="1" value="1" style="width:60px;padding:.28rem .4rem;background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:5px;color:#e0e0e0;font-size:.8rem">
          <button type="submit" class="btn btn-green" style="font-size:.76rem;padding:.28rem .65rem">+ Add</button>
        </form>
      </div>
    </div>{% endif %}
  {% else %}
    {% set ns = namespace(last_key='') %}
    {% for o in order_list|sort(attribute='store_name') %}
      {% set group_key = o.store_name ~ '|' ~ o.delivery_date ~ '|' ~ o.ordered_by %}
      {% if group_key != ns.last_key %}
        {% if ns.last_key != '' %}</table></div>{% endif %}
        {% set ns.last_key = group_key %}
        <div style="margin-bottom:1.25rem;border:1px solid rgba(255,255,255,0.08);border-radius:10px;overflow:hidden">
        <div style="background:rgba(255,255,255,0.04);padding:.6rem 1rem;display:flex;gap:2rem;flex-wrap:wrap;align-items:center">
          <span style="font-weight:700;color:#52c97a;font-size:1rem">{{ o.store_name }}</span>
          <span style="color:#aaa;font-size:.85rem">Delivery: <strong style="color:#ddd">{{ o.delivery_date }}</strong></span>
          <span style="color:#aaa;font-size:.85rem">Submitted by: <strong style="color:#ddd">{{ o.ordered_by }}</strong></span>
          <span style="color:#aaa;font-size:.85rem">{{ o.submitted_at }}</span>
          {% if vendor_plan in ('standard', 'pro', 'seasonal', 'admin') %}
          <button onclick="window.print()" class="btn" style="font-size:.8rem;padding:.3rem .8rem;margin-left:auto" id="print-btn-row">🖨 Print / Save PDF</button>
          {% endif %}
        </div>
        <table style="margin:0;border-radius:0">
          <tr><th>Order #</th><th>Item</th><th>Qty</th><th>Barcode</th>{% if session.role in ('admin','vendor') %}<th></th>{% endif %}</tr>
      {% endif %}
      <tr>
        <td style="color:#888;font-size:.85rem">#{{ o.id }}</td>
        <td>{{ o.item }}{% if o.case_size %} <span style="font-size:.75rem;color:#888">({{ o.case_size }} / case)</span>{% endif %}</td>
        <td id="qty-cell-{{ o.id }}">
          <span id="qty-display-{{ o.id }}">{{ o.disp_qty }}</span>
          <form id="qty-form-{{ o.id }}" method="post" action="{{ url_for('orders_update_qty') }}" style="display:none;margin:0">
            <input type="hidden" name="id" value="{{ o.id }}">
            <input type="number" name="qty" value="{{ o.qty }}" min="1" style="width:60px;padding:.2rem .4rem;font-size:.9rem;background:#1a1a2e;border:1px solid #7c3aed;border-radius:4px;color:#fff">
            <button type="button" onclick="submitQty({{ o.id }})" class="btn btn-green" style="font-size:.75rem;padding:.2rem .5rem;margin-left:.25rem">✓</button>
            <button type="button" onclick="cancelEditQty({{ o.id }})" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#333">✕</button>
          </form>
        </td>
        <td>
          {% if vendor_plan == 'pro' or vendor_plan == 'admin' %}
          {% if o.upc and o.upc != 'None' %}
          <svg class="barcode" data-upc="{{ o.upc }}" style="display:block;min-width:120px"></svg>
          <div style="font-size:.7rem;color:#666;text-align:center;margin-top:2px">{{ o.upc }}</div>
          {% else %}&mdash;{% endif %}
          {% else %}&mdash;{% endif %}
        </td>
        <td>
          <button onclick="editQty({{ o.id }})" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#2d2d4e;margin-bottom:.25rem">✏ Qty</button>
          {% if session.role in ('admin','vendor') %}
          <button type="button" onclick="ajaxRemoveItem(this,{{ o.id }})" class="btn btn-red" onclick="return confirm('Remove order #{{ o.id }}?')">Remove</button>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    {% if ns.last_key != '' %}</table></div>{% endif %}
  {% endif %}
  {% else %}<p class="empty">No orders found.</p>{% endif %}
</div>
<script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.6/dist/JsBarcode.all.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
  renderBarcodes();
  initAjaxForms();
});

function renderBarcodes(root) {
  (root || document).querySelectorAll('svg.barcode:not([data-rendered])').forEach(function(el) {
    var upc = el.getAttribute('data-upc');
    if (!upc || upc === 'None') return;
    try {
      JsBarcode(el, upc, {
        format: 'CODE128', width: 1.4, height: 40,
        displayValue: false, margin: 2,
        lineColor: '#ccc', background: 'transparent'
      });
      el.setAttribute('data-rendered', '1');
    } catch(e) { console.warn('Barcode render failed for', upc, e); }
  });
}

// ── Toast notification ──────────────────────────────────────────────────────
function showToast(msg, isErr) {
  var t = document.getElementById('ajax-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'ajax-toast';
    t.style.cssText = 'position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);'
      +'padding:.6rem 1.4rem;border-radius:8px;font-size:.9rem;font-weight:600;'
      +'z-index:9999;transition:opacity .4s;pointer-events:none;max-width:90vw;text-align:center';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.background = isErr ? '#7f1d1d' : '#14532d';
  t.style.color = isErr ? '#fca5a5' : '#86efac';
  t.style.opacity = '1';
  clearTimeout(t._hide);
  t._hide = setTimeout(function(){ t.style.opacity = '0'; }, 3000);
}

// ── AJAX helpers ─────────────────────────────────────────────────────────────
function ajaxPost(url, formData, cb) {
  fetch(url, {
    method: 'POST',
    headers: {'X-Requested-With': 'XMLHttpRequest'},
    body: formData
  }).then(function(r){ return r.json(); }).then(cb).catch(function(e){ cb({ok:false,msg:String(e)}); });
}

// ── Qty edit ─────────────────────────────────────────────────────────────────
function editQty(id) {
  document.getElementById('qty-display-' + id).style.display = 'none';
  document.getElementById('qty-form-' + id).style.display = 'inline-flex';
  document.querySelector('#qty-form-' + id + ' input[type=number]').focus();
}
function cancelEditQty(id) {
  document.getElementById('qty-display-' + id).style.display = '';
  document.getElementById('qty-form-' + id).style.display = 'none';
}
function submitQty(id) {
  var form = document.getElementById('qty-form-' + id);
  var fd = new FormData(form);
  ajaxPost(form.action, fd, function(r) {
    showToast(r.msg, !r.ok);
    if (r.ok) {
      var disp = document.getElementById('qty-display-' + id);
      if (disp) disp.textContent = r.disp_qty !== undefined ? r.disp_qty : fd.get('qty');
      cancelEditQty(id);
    }
  });
}

// ── Remove single item ───────────────────────────────────────────────────────
function ajaxRemoveItem(btn, orderId) {
  if (!confirm('Remove order #' + orderId + '?')) return;
  var fd = new FormData();
  fd.append('id', orderId);
  ajaxPost('/orders/remove', fd, function(r) {
    showToast(r.msg, !r.ok);
    if (r.ok) {
      var row = btn.closest('tr');
      if (row) row.remove();
    }
  });
}

// ── Remove whole group ───────────────────────────────────────────────────────
function ajaxRemoveGroup(btn, store, date, orderedBy, submittedAt) {
  if (!confirm('Remove entire order for ' + store + ' on ' + date + '?')) return;
  var fd = new FormData();
  fd.append('store', store); fd.append('date', date);
  fd.append('ordered_by', orderedBy); fd.append('submitted_at', submittedAt);
  ajaxPost('/orders/remove_group', fd, function(r) {
    showToast(r.msg, !r.ok);
    if (r.ok) {
      var card = btn.closest('[data-group-key]');
      if (card) card.remove();
    }
  });
}

// ── Add item to existing group ───────────────────────────────────────────────
function initAjaxForms() {
  document.querySelectorAll('.add-item-form').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var fd = new FormData(form);
      if (!fd.get('item')) { showToast('Please select an item.', true); return; }
      var btn = form.querySelector('button[type=submit]');
      if (btn) btn.disabled = true;
      ajaxPost(form.action, fd, function(r) {
        if (btn) btn.disabled = false;
        showToast(r.msg, !r.ok);
        if (!r.ok) return;
        if (r.merged) {
          // Update existing qty display
          var disp = document.getElementById('qty-display-' + r.order_id);
          if (disp) disp.textContent = r.disp_qty !== undefined ? r.disp_qty : r.new_qty;
        } else {
          // Insert new row into the group table
          var groupCard = form.closest('[data-group-key]');
          if (groupCard) {
            var tbody = groupCard.querySelector('table');
            if (tbody) {
              var tr = document.createElement('tr');
              tr.setAttribute('data-order-id', r.order_id);
              tr.innerHTML =
                '<td style="color:#888;font-size:.85rem">#' + r.order_id + '</td>'
                + '<td>' + r.item + (r.case_size ? ' <span style="font-size:.75rem;color:#888">('+r.case_size+' / case)</span>' : '') + '</td>'
                + '<td id="qty-cell-'+r.order_id+'" style="min-width:60px">'
                +   '<span id="qty-display-'+r.order_id+'">'+r.disp_qty+'</span>'
                +   '<form id="qty-form-'+r.order_id+'" method="post" action="/orders/update_qty" style="display:none;margin:0">'
                +     '<input type="hidden" name="id" value="'+r.order_id+'">'
                +     '<input type="number" name="qty" value="'+r.qty+'" min="1" style="width:60px;padding:.2rem .4rem;font-size:.9rem;background:#1a1a2e;border:1px solid #7c3aed;border-radius:4px;color:#fff">'
                +     '<button type="button" onclick="submitQty('+r.order_id+')" class="btn btn-green" style="font-size:.75rem;padding:.2rem .5rem;margin-left:.25rem">✓</button>'
                +     '<button type="button" onclick="cancelEditQty('+r.order_id+')" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#333">✕</button>'
                +   '</form>'
                + '</td>'
                + '<td>&mdash;</td>'
                + '<td>'
                +   '<button onclick="editQty('+r.order_id+')" class="btn" style="font-size:.75rem;padding:.2rem .5rem;background:#2d2d4e;margin-bottom:.25rem">✏ Qty</button> '
                +   '<button type="button" onclick="ajaxRemoveItem(this,'+r.order_id+')" class="btn btn-red" style="font-size:.8rem;padding:.25rem .6rem">✕ Remove</button>'
                + '</td>';
              tbody.appendChild(tr);
              renderBarcodes(tr);
            }
          }
        }
        // Reset the add-item select
        var sel = form.querySelector('select[name=item]');
        if (sel) sel.value = '';
        var qty = form.querySelector('input[name=qty]');
        if (qty) qty.value = '1';
      });
    });
  });
}

// ── Vendor "Create Order" form (top of page) — redirect with date preserved ──
var _vendorOrderForm = document.getElementById('vendor-order-form');
if (_vendorOrderForm) {
  _vendorOrderForm.addEventListener('submit', function(e) {
    e.preventDefault();
    var fd = new FormData(_vendorOrderForm);
    var date = fd.get('date') || '';
    var btn = _vendorOrderForm.querySelector('button[type=submit]');
    if (btn) btn.disabled = true;
    ajaxPost(_vendorOrderForm.action, fd, function(r) {
      if (btn) btn.disabled = false;
      showToast(r.msg, !r.ok);
      if (r.ok) {
        // Navigate to the orders page on that date so the new order is visible
        window.location.href = '/orders?date=' + encodeURIComponent(date);
      }
    });
  });
}
</script>
""")

_DATES = _page("""
<h1>Delivery Dates</h1>
<div class="card">
  <h2>Auto-generate (tomorrow + 7 days)</h2>
  <form method="post" action="{{ url_for('dates_generate') }}">
{{ csrf_field }}
    <button class="btn btn-blue">Generate</button>
  </form>
</div>
<div class="card">
  <h2>Set Custom Dates</h2>
  <form method="post" action="{{ url_for('dates_set') }}">
{{ csrf_field }}
    <div class="field" style="margin-bottom:.75rem">
      <label>Dates (one per line, e.g. "April 15, 2025")</label>
      <textarea name="dates" rows="5" style="width:100%;padding:.4rem;border:1px solid #ccc;border-radius:4px;font-size:.9rem">{{ current_dates|join('\n') }}</textarea>
    </div>
    <button class="btn btn-green" type="submit">Save</button>
  </form>
</div>
<div class="card">
  <h2>Current Allowed Dates</h2>
  {% if current_dates %}{% for d in current_dates %}<span class="pill">{{ d }}</span>{% endfor %}
  {% else %}<p class="empty">None configured yet.</p>{% endif %}
</div>
""")

_CALENDAR = _page("""
<h1>Delivery Calendar</h1>
<style>
.cal-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin-top:.75rem}
.cal-header{text-align:center;font-size:.75rem;color:#a855f7;font-weight:600;padding:.25rem 0}
.cal-day{min-height:80px;background:#1e1e2e;border:1px solid #333;border-radius:6px;padding:.4rem;font-size:.8rem;cursor:pointer;transition:border-color .2s}
.cal-day:hover{border-color:#a855f7}
.cal-day.today{border-color:#52c97a}
.cal-day.has-orders{background:#1a1a2e}
.cal-day.empty{background:#111;border-color:#222;cursor:default}
.cal-day-num{font-weight:600;color:#ccc;font-size:.85rem}
.cal-day.today .cal-day-num{color:#52c97a}
.cal-pill{display:inline-block;margin-top:.25rem;padding:.1rem .35rem;border-radius:4px;font-size:.7rem;font-weight:600;background:#7c3aed;color:#fff;line-height:1.3}
.cal-pill.invoiced{background:#15803d}
.cal-pill.pending{background:#b45309}
.cal-nav{display:flex;align-items:center;gap:1rem;margin-bottom:.5rem}
.cal-nav form{margin:0}
.cal-summary{margin-top:1.5rem}
</style>
<div class="card">
  <div class="cal-nav">
    <form method="get" action="{{ url_for('calendar_view') }}"><input type="hidden" name="y" value="{{ prev_y }}"><input type="hidden" name="m" value="{{ prev_m }}"><button class="btn">← Prev</button></form>
    <strong style="font-size:1.1rem;color:#e0e0e0">{{ month_label }}</strong>
    <form method="get" action="{{ url_for('calendar_view') }}"><input type="hidden" name="y" value="{{ next_y }}"><input type="hidden" name="m" value="{{ next_m }}"><button class="btn">Next →</button></form>
  </div>
  <div class="cal-grid">
    {% for h in ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'] %}<div class="cal-header">{{ h }}</div>{% endfor %}
    {% for cell in cells %}
      {% if cell is none %}
        <div class="cal-day empty"></div>
      {% else %}
        {% set day_str = cell.date %}
        {% set day_orders = order_map.get(day_str, []) %}
        {% set store_set = day_orders|map(attribute='store_name')|list|unique|list %}
        {% set inv_dates = invoiced_dates %}
        <div class="cal-day {% if day_orders %}has-orders{% endif %} {% if cell.today %}today{% endif %}" onclick="{% if day_orders %}window.location='{{ url_for('orders') }}?date={{ day_str }}'{% endif %}">
          <div class="cal-day-num">{{ cell.day }}</div>
          {% if day_orders %}
            <div class="cal-pill {% if day_str in inv_dates %}invoiced{% else %}pending{% endif %}">{{ store_set|length }} store{{ 's' if store_set|length != 1 else '' }}</div>
            <div style="font-size:.68rem;color:#aaa;margin-top:.15rem">{{ day_orders|length }} item{{ 's' if day_orders|length != 1 else '' }}</div>
          {% endif %}
        </div>
      {% endif %}
    {% endfor %}
  </div>
</div>
<div class="cal-summary card">
  <h2>This Month — Orders by Date</h2>
  {% if month_summary %}
    {% for entry in month_summary %}
      <div style="display:flex;align-items:center;gap:.75rem;padding:.4rem 0;border-bottom:1px solid #2a2a3a">
        <a href="{{ url_for('orders') }}?date={{ entry.date }}" style="color:#a855f7;font-weight:600;min-width:110px">{{ entry.date }}</a>
        <span style="color:#ccc">{{ entry.stores }} store{{ 's' if entry.stores != 1 else '' }}</span>
        <span style="color:#aaa;font-size:.85rem">{{ entry.item_count }} item{{ 's' if entry.item_count != 1 else '' }}</span>
        {% if entry.invoiced %}<span style="color:#52c97a;font-size:.8rem">✓ invoiced</span>{% else %}<span style="color:#f59e0b;font-size:.8rem">pending</span>{% endif %}
      </div>
    {% endfor %}
  {% else %}
    <p class="empty">No orders this month.</p>
  {% endif %}
</div>
""")

_USERS = _page("""
<h1>Users</h1>
{% if request.args.get('edit_user') %}
<div class="card" style="border-color:#a855f7">
  <h2 style="color:#a855f7">Edit Store: {{ request.args.get('edit_user') }}</h2>
  <form method="post" action="{{ url_for('users_edit') }}">
{{ csrf_field }}
    <input type="hidden" name="username" value="{{ request.args.get('edit_user') }}">
    <div class="form-row">
      <div class="field"><label>Allowed Vendors</label>
        {% for v in vendors %}
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem;color:#ccc;margin-bottom:4px">
          <input type="checkbox" name="vendor_ids" value="{{ v.id }}"
            {% if v.id in (edit_user_vendors or []) %}checked{% endif %}> {{ v.name }}
        </label>
        {% endfor %}
      </div>
      <div class="field"><label>Store Name</label><input name="store" type="text" value="{{ edit_user_store or '' }}" required></div>
      <div class="field"><label>Store Number</label><input name="store_number" type="text" value="{{ edit_user_store_number or '' }}" placeholder="optional"></div>
      <div class="field" style="display:flex;gap:.5rem;align-self:flex-end">
        <button class="btn btn-green" type="submit">Save Changes</button>
        <a href="{{ url_for('users') }}" class="btn btn-blue">Cancel</a>
      </div>
    </div>
  </form>
</div>
{% endif %}
<div class="card">
  <h2>Add Store Account</h2>
  <form method="post" action="{{ url_for('users_add') }}">
{{ csrf_field }}
    <input type="hidden" name="role" value="store">
    <div class="form-row">
      <div class="field"><label>Allowed Vendors</label>
        {% for v in vendors %}
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem;color:#ccc;margin-bottom:4px">
          <input type="checkbox" name="vendor_ids" value="{{ v.id }}" checked> {{ v.name }}
        </label>
        {% endfor %}
      </div>
      <div class="field"><label>Store Name</label><input name="store" type="text" required></div>
      <div class="field"><label>Username</label><input name="username" type="text" required></div>
      <div class="field"><label>Password</label><input name="password" type="password" required></div>
      <button class="btn btn-green" type="submit" style="align-self:flex-end">Add Store</button>
    </div>
  </form>
</div>
<div class="card">
  <h2>Add Vendor Account</h2>
  <form method="post" action="{{ url_for('users_add') }}">
{{ csrf_field }}
    <input type="hidden" name="role" value="vendor">
    <div class="form-row">
      <div class="field"><label>Vendor</label>
        <select name="vendor_id">
          {% for v in vendors %}<option value="{{ v.id }}">{{ v.name }}</option>{% endfor %}
        </select>
      </div>
      <div class="field"><label>Username</label><input name="username" type="text" required></div>
      <div class="field"><label>Password</label><input name="password" type="password" required></div>
      <button class="btn btn-blue" type="submit" style="align-self:flex-end">Add Vendor Login</button>
    </div>
  </form>
</div>
<div class="card">
  <h2>Change Password</h2>
  <form method="post" action="{{ url_for('users_password') }}">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Username</label><input name="username" type="text" required></div>
      <div class="field"><label>New Password</label><input name="password" type="password" required></div>
      <button class="btn btn-blue" type="submit" style="align-self:flex-end">Update</button>
    </div>
  </form>
</div>
<div class="card">
  <h2>All Users ({{ user_list|length }})</h2>
  <div style="margin-bottom:1rem">
    <input id="user-search" type="text" placeholder="Search username, store, role, vendor..." oninput="filterUsers()"
      style="width:100%;max-width:420px;padding:.5rem .75rem;border-radius:6px;border:1px solid #2d6a4f;background:#1a2e1a;color:#e0e0e0;font-size:.95rem;outline:none">
  </div>
  {% if user_list %}
  <table id="user-table">
    <tr><th>ID</th><th>Vendor</th><th>Store</th><th>Username</th><th>Role</th><th>QR Code</th><th></th></tr>
    {% for u in user_list %}
    <tr>
      <td>{{ u.id }}</td><td>{{ u.vendor_name }}</td><td>{{ u.store_name }}</td><td>{{ u.username }}</td><td>{{ u.role }}</td>
      <td>
        {% if u.role in ('store', 'driver') %}
          {% if u.has_qr %}
            <span style="color:#52c97a;font-size:.8rem">✓ Active</span>
          {% else %}
            <span style="color:#888;font-size:.8rem">None</span>
          {% endif %}
        {% else %}—{% endif %}
      </td>
      <td style="display:flex;gap:.4rem;flex-wrap:wrap">{% if u.username != 'admin' %}
        {% if u.role in ('store', 'driver') %}
        <a href="{{ url_for('users', edit_user=u.username) }}" class="btn btn-blue" style="font-size:.8rem;padding:.3rem .7rem">Edit</a>
        <form method="post" action="{{ url_for('qr_generate') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="username" value="{{ u.username }}">
          <button class="btn" style="background:#7c3aed;font-size:.8rem;padding:.3rem .7rem" title="{{ 'Regenerate' if u.has_qr else 'Generate' }} QR code">{{ '↺ QR' if u.has_qr else '+ QR' }}</button>
        </form>
        {% if u.has_qr %}
        <a href="{{ url_for('qr_download', username=u.username) }}" class="btn btn-green" style="font-size:.8rem;padding:.3rem .7rem" title="Download QR PNG">⬇ QR</a>
        <form method="post" action="{{ url_for('qr_revoke') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="username" value="{{ u.username }}">
          <button class="btn btn-red" style="font-size:.8rem;padding:.3rem .7rem" onclick="return confirm('Revoke QR code for {{ u.username }}? They will need a new code to scan.')">✕ QR</button>
        </form>
        {% endif %}
        {% endif %}
        <form method="post" action="{{ url_for('users_remove') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="username" value="{{ u.username }}">
          <button class="btn btn-red" style="font-size:.8rem;padding:.3rem .7rem" onclick="return confirm('Remove {{ u.username }}?')">Remove</button>
        </form>
      {% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No users yet.</p>{% endif %}
</div>
<script>
function filterUsers() {
  var q = document.getElementById('user-search').value.toLowerCase();
  var rows = document.querySelectorAll('#user-table tbody tr');
  rows.forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
""")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render(template, **kwargs):
    kwargs.setdefault("flash_msg", request.args.get("msg", ""))
    kwargs.setdefault("flash_cls", request.args.get("cls", "ok"))
    # Role-based inactivity timeout: admin + vendor = 15 min, store/driver = 10 min
    role = session.get("role", "store")
    kwargs.setdefault("_inactivity_timeout", 900 if role in ("admin", "vendor") else 600)
    # CSRF token + convenience field for templates
    _tok = _get_csrf_token()
    kwargs.setdefault("csrf_token", _tok)
    kwargs.setdefault("csrf_field", Markup(f'<input type="hidden" name="csrf_token" value="{_tok}">'))
    return render_template_string(template, **kwargs)

def _redirect(endpoint, msg, cls="ok", **kw):
    return redirect(url_for(endpoint, msg=msg, cls=cls, **kw))

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    if request.method == "GET":
        session.clear()  # Always clear on login page load — no ghost sessions
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if not _check_login_rate(ip):
            return _render(_LOGIN, flash_msg="Too many login attempts. Please wait 10 minutes.", flash_cls="err")
        username = request.form["username"]
        password = request.form["password"]
        user = _get_user(username)
        if user and user.get("password") and check_password_hash(user["password"], password):
            session.permanent = False  # session dies when browser closes
            session["username"] = user["username"]
            session["role"] = user.get("role", "store")
            session["store_name"] = user.get("store_name", "")
            session["store_number"] = user.get("store_number", "")
            session["session_version"] = user.get("session_version", 0)
            vendor_ids = user.get("vendor_ids", ["gmf"])
            session["vendor_ids"] = vendor_ids
            # Pre-load first vendor name for nav display
            all_vendors = _load_vendors()
            vmap = {v["id"]: v.get("name", v.get("id", "")) for v in all_vendors}
            session["vendor_name"] = vmap.get(vendor_ids[0], vendor_ids[0]) if vendor_ids else ""
            role = user.get("role", "store")
            # Validate ?next= to prevent open redirect — only allow same-origin relative paths
            raw_next = request.args.get("next", "")
            from urllib.parse import urlparse
            parsed = urlparse(raw_next)
            safe_next = raw_next if (raw_next and not parsed.scheme and not parsed.netloc and raw_next.startswith("/")) else None
            if role == "vendor":
                session["vendor_id"] = user.get("vendor_id") or (user.get("vendor_ids", ["gmf"])[0] if user.get("vendor_ids") else "gmf")
                next_url = safe_next or url_for("invoices")
            elif role == "admin":
                next_url = safe_next or url_for("orders")
            elif role == "driver":
                session["vendor_id"] = user.get("vendor_id", "gmf")
                session["driver_area"] = user.get("driver_area", "")
                next_url = safe_next or url_for("orders")
            else:
                next_url = safe_next or url_for("catalog")
            return redirect(next_url)
        return _render(_LOGIN, flash_msg="Invalid username or password.", flash_cls="err")
    return _render(_LOGIN)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# QR Code auto-login
# ---------------------------------------------------------------------------

@app.route("/qr/<token>")
def qr_login(token):
    """Auto-login via QR code token. No password needed."""
    session.clear()
    tokens = _load_qr_tokens()
    rec = next((t for t in tokens if t['token'] == token), None)
    if not rec:
        return _render(_LOGIN, flash_msg="QR code is invalid or has been revoked.", flash_cls="err")
    # Check expiry
    expires_at_str = rec.get('expires_at')
    if expires_at_str:
        from datetime import datetime, timezone
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now(timezone.utc) > expires_at:
                _revoke_qr_token(rec['username'])
                return _render(_LOGIN, flash_msg="QR code has expired. Please request a new one.", flash_cls="err")
        except Exception:
            pass  # malformed date — allow through, will be fixed on next regeneration
    user = _get_user(rec['username'])
    if not user:
        return _render(_LOGIN, flash_msg="Store account not found.", flash_cls="err")
    session.permanent = False
    session["username"] = user["username"]
    session["role"] = user.get("role", "store")
    session["store_name"] = user.get("store_name", "")
    session["store_number"] = user.get("store_number", "")
    vendor_ids = user.get("vendor_ids", ["gmf"])
    session["vendor_ids"] = vendor_ids
    all_vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in all_vendors}
    session["vendor_name"] = vmap.get(vendor_ids[0], vendor_ids[0]) if vendor_ids else ""
    session["qr_login"] = True  # flag so we know this was a QR session
    role = user.get("role", "store")
    if role == "driver":
        session["vendor_id"] = user.get("vendor_id", "gmf")
        session["driver_area"] = user.get("driver_area", "")
        return redirect(url_for("orders"))
    elif role == "vendor":
        session["vendor_id"] = user.get("vendor_id") or (vendor_ids[0] if vendor_ids else "gmf")
        return redirect(url_for("invoices"))
    elif role == "admin":
        return redirect(url_for("orders"))
    return redirect(url_for("catalog"))

@app.route("/users/qr/generate", methods=["POST"])
@csrf_protect
@admin_required
def qr_generate():
    """Generate (or regenerate) a QR token for a store user."""
    username = request.form["username"]
    user = _get_user(username)
    if not user or user.get("role") not in ("store", "driver"):
        return _redirect("users", "QR codes can only be generated for store or driver accounts.", cls="err")
    _generate_qr_token(username)
    return _redirect("users", f"QR code generated for {username}.")

@app.route("/users/qr/revoke", methods=["POST"])
@csrf_protect
@admin_required
def qr_revoke():
    """Revoke (delete) the QR token for a store user."""
    username = request.form["username"]
    _revoke_qr_token(username)
    return _redirect("users", f"QR code revoked for {username}.")

@app.route("/users/qr/download/<username>")
@admin_required
def qr_download(username):
    """Download QR code PNG for a store user."""
    from flask import send_file, Response
    rec = _get_qr_token_for_user(username)
    if not rec:
        return _redirect("users", "No QR code found for that user. Generate one first.", cls="err")
    base_url = request.host_url.rstrip('/')
    qr_url = f"{base_url}/qr/{rec['token']}"
    # Get vendor name and store name for the card header
    user = _get_user(username)
    vendor_name = ""
    store_name = ""
    if user:
        vendor_ids = user.get("vendor_ids", [user.get("vendor_id", "gmf")])
        all_vendors = _load_vendors()
        vmap = {v["id"]: v.get("name", v.get("id", "")) for v in all_vendors}
        vendor_name = vmap.get(vendor_ids[0], "") if vendor_ids else ""
        store_name = user.get("store_name", "")
    png_bytes = _make_qr_png_bytes(qr_url, vendor_name=vendor_name, store_name=store_name)
    return Response(
        png_bytes,
        mimetype='image/png',
        headers={"Content-Disposition": f'attachment; filename="qr_{username}.png"'}
    )

# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("orders"))
    elif role == "vendor":
        return redirect(url_for("invoices"))
    return redirect(url_for("catalog"))

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

@app.route("/inventory")
@login_required
def inventory():
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    items = cli.inventory_list()
    for item in items:
        item["vendor_name"] = vmap.get(item.get("vendor_id","gmf"), item.get("vendor_id","gmf"))
    role = session.get("role", "store")
    # Filter by vendor for non-admin roles
    if role == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
        items = [i for i in items if i.get("vendor_id","gmf") in vendor_ids]
    elif role == "store":
        # Store sees only their vendor's inventory
        vid = session.get("vendor_id", "gmf")
        items = [i for i in items if i.get("vendor_id","gmf") == vid]
    elif role == "driver":
        items = [i for i in items]  # drivers see all
    filter_vendor = request.args.get("vendor", "")
    if role == "admin" and filter_vendor:
        items = [i for i in items if i.get("vendor_id","gmf") == filter_vendor]
    # Sort by category then item
    items = sorted(items, key=lambda x: (x.get("category",""), x.get("item","")))
    # Pre-compute group flags for template (avoid complex Jinja2 filter chains)
    for item in items:
        sgs = item.get("store_groups") or []
        all_stores = [str(s) for sg in sgs for s in sg.get("stores", [])]
        item["_has_hann"] = any(s.strip().isdigit() for s in all_stores)
        item["_has_mb"] = any(s.strip().startswith("mb_") for s in all_stores)
        # Normalize hidden_from — migrate legacy visible=False
        hf = item.get("hidden_from", [])
        if item.get("visible") is False and not hf:
            hf = ["hannaford", "marketbasket", "regular"]
        item["_hidden_from"] = hf
    return _render(_INVENTORY, items=items, vendors=vendors, filter_vendor=filter_vendor, role=role)

@app.route("/inventory/set_qb_item_name", methods=["POST"])
@csrf_protect
@vendor_required
def inventory_set_qb_item_name():
    from flask import jsonify
    import json as _json
    item_id = request.form.get("item_id", "").strip()
    qb_name = request.form.get("qb_item_name", "").strip()
    if not item_id:
        return jsonify({"ok": False, "error": "Missing item_id"})
    inv_path = os.path.join(DATA_DIR, "inventory.json")
    with open(inv_path) as _f:
        inv = _json.load(_f)
    found = False
    for item in inv:
        if str(item.get("id")) == str(item_id):
            item["qb_item_name"] = qb_name
            found = True
            break
    if not found:
        return jsonify({"ok": False, "error": "Item not found"})
    with _get_file_lock(inv_path):
        _atomic_write(inv_path, inv)
    return jsonify({"ok": True})


@app.route("/inventory/toggle_visibility", methods=["POST"])
@csrf_protect
@vendor_required
def inventory_toggle_visibility():
    import json as _json
    item_id = request.form.get("item_id", "")
    group = request.form.get("group", "regular")  # hannaford | marketbasket | regular
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if not item_id:
        return (jsonify({"ok": False, "msg": "Missing item."}), 400) if is_ajax else _redirect("inventory", "Missing item.", cls="err")
    if group not in ("hannaford", "marketbasket", "regular"):
        return (jsonify({"ok": False, "msg": "Invalid group."}), 400) if is_ajax else _redirect("inventory", "Invalid group.", cls="err")
    inv_file = os.path.join(DATA_DIR, "inventory.json")
    inv = cli.inventory_list()
    found = False
    now_hidden = False
    for item in inv:
        if str(item["id"]) == str(item_id):
            hidden_from = item.get("hidden_from", [])
            if item.get("visible") is False and not hidden_from:
                hidden_from = ["hannaford", "marketbasket", "regular"]
            item.pop("visible", None)
            if group in hidden_from:
                hidden_from.remove(group)
                msg = f"Item now visible to {group} stores."
                now_hidden = False
            else:
                hidden_from.append(group)
                msg = f"Item hidden from {group} stores."
                now_hidden = True
            item["hidden_from"] = hidden_from
            found = True
            break
    if not found:
        return (jsonify({"ok": False, "msg": "Item not found."}), 404) if is_ajax else _redirect("inventory", "Item not found.", cls="err")
    with open(inv_file, "w") as _f:
        _json.dump(inv, _f)
    return jsonify({"ok": True, "msg": msg, "hidden": now_hidden, "group": group}) if is_ajax else _redirect("inventory", msg)

@app.route("/inventory/add", methods=["POST"])
@csrf_protect
@vendor_required
def inventory_add():
    try:
        vendor_id = request.form.get("vendor_id", "gmf")
        result = cli.inventory_add(request.form["category"], request.form["item"], int(request.form["qty"]))
        # tag with vendor_id
        inv = cli.inventory_list()
        for item in inv:
            if item["id"] == result["id"]:
                item["vendor_id"] = vendor_id
        import json as _json
        with open(os.path.join(DATA_DIR, "inventory.json"), "w") as _f:
            _json.dump(inv, _f, indent=2)
        return _redirect("inventory", f"Saved {request.form['item']}.")
    except Exception as exc:
        return _redirect("inventory", str(exc), cls="err")

@app.route("/inventory/remove", methods=["POST"])
@csrf_protect
@vendor_required
def inventory_remove():
    result = cli.inventory_remove(request.form["category"], request.form["item"])
    if result:
        return _redirect("inventory", f"Removed {result['item']}.")
    return _redirect("inventory", "Item not found.", cls="err")

# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------
# Routes - Catalog (store users)
# ---------------------------------------------------------------------------

@app.route("/catalog")
@login_required
def catalog():
    all_items = cli.inventory_list()
    all_vendors = _load_vendors()
    role = session.get("role")
    vendor_ids = session.get("vendor_ids", ["gmf"])

    # Determine which vendors this user can see
    if role == "admin":
        available_vendors = all_vendors
    else:
        available_vendors = [v for v in all_vendors if v["id"] in vendor_ids]

    # Selected vendor (from query param or first available)
    selected_vendor_id = request.args.get("vendor") or (available_vendors[0]["id"] if available_vendors else "gmf")
    selected_vendor = next((v for v in available_vendors if v["id"] == selected_vendor_id), available_vendors[0] if available_vendors else None)

    # Filter items to selected vendor
    items = [i for i in all_items if i.get("vendor_id", "gmf") == selected_vendor_id]

    # Hannaford stores see only items whose store_group includes their store number
    # Market Basket stores see only MB items (store_groups with mb_ prefixed ids)
    # All other stores see only regular items (no store_groups)
    if role == "store":
        username = session.get("username", "").lower()
        store_number = str(session.get("store_number", "")).strip()
        if "hannaford" in username:
            if store_number:
                items = [i for i in items if store_number in [
                    s.strip() for s in str(i.get("store_group", "")).split(",")
                ] or store_number in [
                    str(s).strip()
                    for sg in i.get("store_groups", [])
                    for s in sg.get("stores", [])
                ]]
            else:
                # No store number set — show all Hannaford items
                items = [i for i in items if i.get("store_group") or i.get("store_groups")]
        elif "marketbasket" in username:
            items = [i for i in items if i.get("store_groups") and any(
                str(s).strip().startswith("mb_")
                for sg in i.get("store_groups", [])
                for s in sg.get("stores", [])
            )]
        else:
            items = [i for i in items if not i.get("store_groups") and not i.get("store_group")]

    # Filter items hidden from this store's group
    if role == "store":
        username = session.get("username", "").lower()
        if "hannaford" in username:
            store_group = "hannaford"
        elif "marketbasket" in username:
            store_group = "marketbasket"
        else:
            store_group = "regular"
        def _item_visible(i):
            hidden_from = i.get("hidden_from", [])
            # Legacy support: visible=False with no hidden_from means hidden from all
            if i.get("visible") is False and not hidden_from:
                return False
            return store_group not in hidden_from
        items = [i for i in items if _item_visible(i)]

    for item in items:
        if item.get('case_qty'):
            item['case_size'] = item['case_qty']

    from collections import OrderedDict
    cat_dict = OrderedDict()
    for item in sorted(items, key=lambda x: (x.get('category', 'Other'), x.get('item', ''))):
        cat = item.get("category", "Other")
        cat_dict.setdefault(cat, []).append(item)
    cat_dict = OrderedDict(sorted(cat_dict.items()))
    # Keep nav vendor name in sync with selected vendor
    if selected_vendor:
        session["vendor_name"] = selected_vendor["name"]
    return _render(_CATALOG, catalog=cat_dict, available_vendors=available_vendors, selected_vendor=selected_vendor, allowed_dates=sorted(cli.dates_list()))

@app.route("/catalog/submit", methods=["POST"])
@csrf_protect
@login_required
def catalog_submit():
    items = cli.inventory_list()
    store = session.get("store_name") if session.get("role") == "store" else request.form.get("store", "")
    date = request.form.get("date", "")
    ordered_by = request.form.get("ordered_by", session.get("username", ""))
    confirm_email = request.form.get("confirm_email", "").strip()
    # Lock vendor_id to session for store-role users — prevents cross-vendor order injection
    if session.get("role") == "store":
        selected_vendor_id = (session.get("vendor_ids") or ["gmf"])[0]
    else:
        selected_vendor_id = request.form.get("vendor_id", "gmf")
    submitted = []
    errors = []
    store_number = session.get("store_number", "")
    for item in items:
        qty_val = request.form.get(f"qty_{item['id']}", "0")
        try:
            qty = int(qty_val)
        except ValueError:
            qty = 0
        if qty > 0:
            case_qty = item.get('case_qty') or 1
            qty = qty * case_qty
            try:
                resolved_upc = _resolve_upc(item, store_number)
                result = cli.orders_add(
                    store=store,
                    category=item["category"],
                    item=item["item"],
                    qty=qty,
                    date=date,
                    ordered_by=ordered_by,
                )
                _stamp_eastern(result)
                # Patch UPC, vendor_id, and case_size onto saved order
                result['upc'] = resolved_upc
                result['case_size'] = item.get('case_size', '')
                result['qb_item_name'] = item.get('qb_item_name', '')
                _patch_order_upc(result['id'], resolved_upc, vendor_id=selected_vendor_id, case_size=item.get('case_size', ''), submitted_at=result['submitted_at'])
                submitted.append(result)
            except Exception as e:
                errors.append(str(e))
    if not submitted:
        return _redirect("catalog", "No items selected — please enter quantities.", cls="err")
    if confirm_email and submitted:
        _vend = _get_vendor(selected_vendor_id)
        _vend_name = _vend.get("name", "") if _vend else ""
        _send_order_confirmation_summary(confirm_email, submitted, store, date, session.get("store_number", ""), vendor_name=_vend_name)
    # Real-time order alert to vendor office
    _send_new_order_alert(selected_vendor_id, store, store_number, date, ordered_by, submitted)
    # Auto-invoice: if vendor has auto_invoice enabled, create invoice automatically
    vendor = _get_vendor(selected_vendor_id)
    if vendor and vendor.get("auto_invoice") and vendor.get("plan", "starter") in ("standard", "pro", "seasonal"):
        inv = _auto_create_invoice(selected_vendor_id, store, date, submitted)
        # Auto QB sync: if enabled and vendor user is QB-connected
        if inv and vendor.get("auto_qb_sync"):
            users = _load_users()
            vendor_user = next((u for u in users if u.get("role") == "vendor"
                                and selected_vendor_id in u.get("vendor_ids", [u.get("vendor_id", "")])
                                and u.get("qb_token")), None)
            if vendor_user:
                ok, qb_result = _qb_push_invoice(inv, vendor_user)
                if ok:
                    qb_id, qb_doc, qb_total, qb_lines = qb_result
                    all_inv = _load_invoices()
                    for i in all_inv:
                        if i["id"] == inv["id"]:
                            i["qb_invoice_id"] = qb_id
                            i["qb_doc_number"] = qb_doc
                            if qb_total:
                                i["total"] = qb_total
                            # Render barcode PNGs
                            for li in i.get("line_items", []):
                                if li.get("upc") and li["upc"] != "None" and not li.get("barcode_b64"):
                                    b64 = _upc_to_barcode_b64(li["upc"])
                                    if b64:
                                        li["barcode_b64"] = b64
                    _save_invoices(all_inv)
    return _render(_ORDER_SUCCESS, count=len(submitted), date=date)

# ---------------------------------------------------------------------------

@app.route("/orders")
@login_required
def orders():
    from datetime import date as _date
    store_filter = None
    if session.get("role") == "store":
        store_filter = session.get("store_name")
    elif request.args.get("store"):
        store_filter = request.args.get("store")

    # Default to today
    _today_iso = _date.today().isoformat()
    date_filter = request.args.get("date") or _today_iso
    item_filter = request.args.get("item") or None

    # Load all orders first, then apply Python-level filters
    # (cli.orders_list date param does prefix matching on allowed dates,
    #  not on delivery_date — so we filter delivery_date ourselves)
    all_orders = cli.orders_list(
        store=store_filter,
        item=item_filter,
    )

    # Filter by exact delivery_date — store users see all their orders (no date gate)
    if session.get("role") != "store":
        all_orders = [o for o in all_orders if o.get("delivery_date", "").strip() == date_filter.strip()]
    elif request.args.get("date"):
        # Store user can optionally filter by date if they choose
        all_orders = [o for o in all_orders if o.get("delivery_date", "").strip() == date_filter.strip()]

    # Vendors only see orders for their vendor_id(s)
    if session.get("role") == "vendor":
        vendor_id = session.get("vendor_id", "")
        # vendor_ids covers multi-vendor accounts; vendor_id is the login's primary
        vendor_ids = session.get("vendor_ids", [vendor_id])
        all_orders = [o for o in all_orders if o.get("vendor_id") in vendor_ids]

    # Drivers only see orders for their area stores
    if session.get("role") == "driver":
        area = session.get("driver_area", "")
        area_set = AREA_STORES.get(area, set())
        all_orders = [o for o in all_orders if o.get("store_name") in area_set]

    # Sort store orders by delivery_date ascending (upcoming first)
    if session.get("role") == "store":
        all_orders.sort(key=lambda o: o.get("delivery_date", ""))

    order_group_count = len(set(
        (o.get("store_name"), o.get("delivery_date"), o.get("ordered_by"), (o.get("submitted_at") or "")[:16])
        for o in all_orders
    ))
    # Pre-compute display qty (qty × case_size) for each order
    for o in all_orders:
        o["disp_qty"] = _disp_qty(o.get("qty", 1), o.get("case_size", ""))
    # Build invoice lookup by (vendor_id, store_name, delivery_date) for order group headers
    _inv_lookup = {}
    if session.get("role") in ("vendor", "admin"):
        _vid = session.get("vendor_id") or (session.get("vendor_ids") or ["gmf"])[0]
        for _inv in _load_invoices():
            if session.get("role") == "admin" or _inv.get("vendor_id") == _vid:
                _key = (_inv.get("vendor_id",""), _inv.get("store_name",""), _inv.get("delivery_date",""))
                _inv_lookup[_key] = _inv
    # Resolve vendor plan for barcode gating (gmf always gets pro access)
    _role = session.get("role", "store")
    if _role == "admin":
        _vendor_plan = "admin"  # admin sees everything
    else:
        _vid = session.get("vendor_id") or (session.get("vendor_ids") or ["gmf"])[0]
        if _vid == "gmf":
            _vendor_plan = "pro"
        else:
            _vobj = _get_vendor(_vid)
            _vendor_plan = (_vobj or {}).get("plan", "starter")
    # Build vendor store list + inventory for vendor create-order form
    _vendor_stores = []
    _vendor_inv_items = []
    if session.get("role") == "vendor":
        _vids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
        import re as _re
        # Build city→store_num lookup from hannaford store list
        _hann_store_list_path = "/data/.openclaw/workspace/memory/hannaford_store_list.json"
        _city_to_num = {}
        try:
            import json as _json2
            _hsl = _json2.load(open(_hann_store_list_path))
            for _hs in _hsl:
                _c = (_hs.get("city") or "").upper().strip()
                if _c:
                    _city_to_num[_c] = _hs["store_num"]
        except Exception:
            pass
        def _extract_store_num(u):
            # 1. Try store_number field
            sn = u.get("store_number")
            if sn:
                return str(int(sn)) if str(sn).isdigit() else str(sn).lstrip("0")
            name = u.get("store_name") or ""
            # 2. Try (08109) pattern in store_name
            m = _re.search(r'\((0*(\d+))\)', name)
            if m:
                return str(int(m.group(2)))
            # 3. City name match against hannaford store list
            name_upper = name.upper()
            for city, num in _city_to_num.items():
                if city in name_upper:
                    return str(num)
            return ""
        _vendor_stores = sorted(
            [{"store_name": u.get("store_name",""), "store_number": _extract_store_num(u)} 
             for u in _load_users() 
             if u.get("role") == "store" and u.get("vendor_id") in _vids and u.get("store_name")],
            key=lambda s: s["store_name"]
        )
        # Read inventory directly from JSON to guarantee plain dicts with all fields
        import json as _inv_json
        _inv_file = os.path.join(DATA_DIR, "inventory.json")
        try:
            with open(_inv_file) as _f:
                _all_inv = _inv_json.load(_f)
        except Exception:
            _all_inv = cli.inventory_list()
        _vendor_inv_items = sorted(
            [i for i in _all_inv if (i.get("vendor_id") or "gmf") in _vids],
            key=lambda i: (i.get("category",""), i.get("item",""))
        )
        # Pre-compute flat store number list for JS filtering
        for _i in _vendor_inv_items:
            _sgs = _i.get("store_groups") or []
            _flat = []
            for _sg in _sgs:
                for _sn in _sg.get("stores", []):
                    try:
                        _flat.append(str(int(_sn)))
                    except (ValueError, TypeError):
                        _flat.append(str(_sn).lstrip("0") or str(_sn))
            _i["stores_flat"] = ",".join(_flat)
    return _render(
        _ORDERS,
        order_list=all_orders,
        order_group_count=order_group_count,
        inv_lookup=_inv_lookup if session.get("role") in ("vendor", "admin") else {},
        allowed_dates=sorted(cli.dates_list()),
        filter_store=request.args.get("store", ""),
        filter_date=date_filter,
        filter_item=request.args.get("item", ""),
        vendor_plan=_vendor_plan,
        vendor_stores=_vendor_stores,
        vendor_inv_items=_vendor_inv_items,
    )

@app.route("/orders/export.csv")
@vendor_required
def orders_export_csv():
    """Export filtered orders as CSV. Vendor and admin only. Respects same date/store filters as orders page."""
    import csv, io
    from datetime import date as _date

    date_filter = request.args.get("date") or _date.today().isoformat()
    store_filter = request.args.get("store") or None
    item_filter  = request.args.get("item")  or None

    all_orders = cli.orders_list(store=store_filter, item=item_filter)
    all_orders = [o for o in all_orders if o.get("delivery_date", "").strip() == date_filter.strip()]

    # Vendors only see their own orders
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
        all_orders = [o for o in all_orders if o.get("vendor_id") in vendor_ids]

    all_orders.sort(key=lambda o: (o.get("store_name", ""), o.get("item", "")))

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Order ID", "Store", "Store #", "Category", "Item", "Qty",
                     "Case Size", "UPC", "Delivery Date", "Ordered By", "Submitted At"])
    for o in all_orders:
        writer.writerow([
            o.get("id", ""),
            o.get("store_name", ""),
            o.get("store_number", ""),
            o.get("category", ""),
            o.get("item", ""),
            _disp_qty(o.get("qty", 0), o.get("case_size", "")),
            o.get("case_size", ""),
            o.get("upc", ""),
            o.get("delivery_date", ""),
            o.get("ordered_by", ""),
            o.get("submitted_at", ""),
        ])

    from flask import Response
    filename = f"orders_{date_filter}.csv"
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.route("/orders/add", methods=["POST"])
@csrf_protect
@login_required
def orders_add():
    try:
        # Lock store to session for store-role users — prevents IDOR order injection
        if session.get("role") == "store":
            store = session.get("store_name", "")
        else:
            store = request.form.get("store") or session.get("store_name")
        item_name = request.form["item"]
        try:
            add_qty = int(request.form["qty"])
        except (ValueError, TypeError):
            add_qty = 0
        if add_qty < 1:
            is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
            return (jsonify({"ok": False, "msg": "Quantity must be at least 1."}), 400) if is_ajax else _redirect("orders", "Quantity must be at least 1.", cls="err")
        if add_qty > 10000:
            is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
            return (jsonify({"ok": False, "msg": "Quantity exceeds maximum allowed (10,000)."}), 400) if is_ajax else _redirect("orders", "Quantity exceeds maximum allowed.", cls="err")
        date = request.form["date"]
        ordered_by = request.form.get("ordered_by", session.get("username", ""))
        _vid = session.get("vendor_id") if session.get("role") == "vendor" else None
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

        # Merge into existing line if same store+item+date+ordered_by already exists
        orders_file = os.path.join(DATA_DIR, "orders.json")
        if os.path.exists(orders_file):
            with open(orders_file) as _f:
                _all = json.load(_f)
            for _o in _all:
                if (
                    _o.get("store_name") == store
                    and _o.get("item") == item_name
                    and _o.get("delivery_date") == date
                    and _o.get("ordered_by") == ordered_by
                    and (_vid is None or _o.get("vendor_id") == _vid)
                ):
                    _o["qty"] = int(_o.get("qty", 1)) + add_qty
                    orders_file_w = os.path.join(DATA_DIR, "orders.json")
                    with _get_file_lock(orders_file_w):
                        _atomic_write(orders_file_w, _all)
                    msg = f"Qty updated — {item_name} is now {_o['qty']} for {store} on {date}."
                    return jsonify({"ok": True, "msg": msg, "merged": True, "order_id": _o["id"], "new_qty": _o["qty"], "disp_qty": _disp_qty(_o["qty"], _o.get("case_size", ""))}) if is_ajax else _redirect("orders", msg)

        result = cli.orders_add(
            store=store,
            category=request.form["category"],
            item=item_name,
            qty=add_qty,
            date=date,
            ordered_by=ordered_by,
        )
        _stamp_eastern(result)
        # Pass vendor_id so orders created by vendors are visible in the filtered view
        _patch_order_upc(result['id'], result.get('upc', ''), vendor_id=_vid, submitted_at=result['submitted_at'])
        confirm_email = request.form.get("confirm_email", "").strip()
        if confirm_email:
            _send_order_confirmation(confirm_email, result, store, session.get("store_number", ""))
        msg = f"Order #{result['id']} submitted successfully."
        return jsonify({"ok": True, "msg": msg, "merged": False, "order_id": result["id"], "item": item_name, "qty": add_qty, "disp_qty": _disp_qty(add_qty, result.get("case_size", "")), "store": store, "date": date, "ordered_by": ordered_by, "case_size": result.get("case_size", ""), "upc": result.get("upc", "")}) if is_ajax else _redirect("orders", msg)
    except Exception as exc:
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
        return (jsonify({"ok": False, "msg": str(exc)}), 500) if is_ajax else _redirect("orders", str(exc), cls="err")

@app.route("/orders/remove", methods=["POST"])
@csrf_protect
@vendor_required
def orders_remove():
    order_id = int(request.form["id"])
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if session.get("role") == "vendor":
        all_orders = cli.orders_list()
        order = next((o for o in all_orders if o["id"] == order_id), None)
        if not order:
            return (jsonify({"ok": False, "msg": "Order not found."}), 404) if is_ajax else _redirect("orders", "Order not found.", cls="err")
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        if order.get("vendor_id") not in vendor_ids:
            return (jsonify({"ok": False, "msg": "Access denied."}), 403) if is_ajax else _redirect("orders", "Access denied.", cls="err")
    result = cli.orders_remove(order_id)
    if result:
        return jsonify({"ok": True, "msg": f"Item #{result['id']} removed."}) if is_ajax else _redirect("orders", f"Item #{result['id']} removed.")
    return (jsonify({"ok": False, "msg": "Item not found."}), 404) if is_ajax else _redirect("orders", "Item not found.", cls="err")

@app.route("/orders/remove_group", methods=["POST"])
@csrf_protect
@vendor_required
def orders_remove_group():
    """Remove all line items belonging to the same order group (store + date + ordered_by + submitted_at prefix)."""
    store = request.form.get("store", "").strip()
    date = request.form.get("date", "").strip()
    ordered_by = request.form.get("ordered_by", "").strip()
    submitted_at_prefix = request.form.get("submitted_at", "").strip()  # first 16 chars
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    all_orders = cli.orders_list()
    vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
    is_admin = session.get("role") == "admin"
    to_remove = []
    for o in all_orders:
        if (o.get("store_name") == store
                and o.get("delivery_date") == date
                and o.get("ordered_by") == ordered_by
                and (o.get("submitted_at", "")[:16] == submitted_at_prefix or not submitted_at_prefix)):
            if not is_admin and session.get("role") == "vendor" and o.get("vendor_id") not in vendor_ids:
                continue
            to_remove.append(o["id"])
    if not to_remove:
        return (jsonify({"ok": False, "msg": "No matching orders found."}), 404) if is_ajax else _redirect("orders", "No matching orders found.", cls="err")
    for oid in to_remove:
        cli.orders_remove(oid)
    msg = f"Removed order group ({len(to_remove)} items) for {store} on {date}."
    return jsonify({"ok": True, "msg": msg, "date": date}) if is_ajax else _redirect("orders", msg, date=date)

@app.route("/orders/update_qty", methods=["POST"])
@csrf_protect
@login_required
def orders_update_qty():
    order_id = int(request.form["id"])
    new_qty  = int(request.form["qty"])
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if new_qty < 1:
        return (jsonify({"ok": False, "msg": "Quantity must be at least 1."}), 400) if is_ajax else _redirect("orders", "Quantity must be at least 1.", cls="err")
    orders_file = os.path.join(DATA_DIR, "orders.json")
    if not os.path.exists(orders_file):
        return (jsonify({"ok": False, "msg": "Orders file not found."}), 500) if is_ajax else _redirect("orders", "Orders file not found.", cls="err")
    with open(orders_file) as f:
        orders = json.load(f)
    updated = False
    disp_qty = new_qty
    for o in orders:
        if o.get("id") == order_id:
            # Access check — store users can only edit their own orders
            if session.get("role") == "store" and o.get("store_name") != session.get("store_name"):
                return (jsonify({"ok": False, "msg": "Access denied."}), 403) if is_ajax else _redirect("orders", "Access denied.", cls="err")
            # Vendor check
            if session.get("role") == "vendor":
                vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
                if o.get("vendor_id") not in vendor_ids:
                    return (jsonify({"ok": False, "msg": "Access denied."}), 403) if is_ajax else _redirect("orders", "Access denied.", cls="err")
            o["qty"] = new_qty
            disp_qty = _disp_qty(new_qty, o.get("case_size", ""))
            updated = True
            break
    if not updated:
        return (jsonify({"ok": False, "msg": "Order not found."}), 404) if is_ajax else _redirect("orders", "Order not found.", cls="err")
    orders_file = os.path.join(DATA_DIR, "orders.json")
    with _get_file_lock(orders_file):
        _atomic_write(orders_file, orders)
    return jsonify({"ok": True, "msg": f"Order #{order_id} quantity updated to {new_qty}.", "disp_qty": disp_qty}) if is_ajax else _redirect("orders", f"Order #{order_id} quantity updated to {new_qty}.")


# ---------------------------------------------------------------------------
# Dates (admin only)
# ---------------------------------------------------------------------------

@app.route("/dates")
@admin_required
def dates():
    return _render(_DATES, current_dates=cli.dates_list())

@app.route("/dates/generate", methods=["POST"])
@csrf_protect
@admin_required
def dates_generate():
    result = cli.dates_generate()
    return _redirect("dates", f"Generated {len(result)} dates.")

@app.route("/dates/set", methods=["POST"])
@csrf_protect
@admin_required
def dates_set():
    raw = request.form.get("dates", "")
    new_dates = [d.strip() for d in raw.splitlines() if d.strip()]
    cli.dates_set(new_dates)
    return _redirect("dates", f"Saved {len(new_dates)} dates.")

# ---------------------------------------------------------------------------
# Calendar (admin + vendor)
# ---------------------------------------------------------------------------

@app.route("/calendar")
@login_required
def calendar_view():
    from datetime import date as _date
    import calendar
    role = session.get("role")
    if role not in ("admin", "vendor", "driver"):
        return _redirect("index", "Access denied.", cls="err")
    _vid = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    _vobj = _get_vendor(_vid)
    _vendor_plan = "admin" if role == "admin" else ("pro" if _is_internal_vendor(_vid) else (_vobj or {}).get("plan", "starter"))
    today = _date.today()
    try:
        y = int(request.args.get("y", today.year))
        m = int(request.args.get("m", today.month))
    except (ValueError, TypeError):
        y, m = today.year, today.month
    # Clamp
    if m < 1: m = 12; y -= 1
    if m > 12: m = 1; y += 1
    prev_m, prev_y = (m - 1, y) if m > 1 else (12, y - 1)
    next_m, next_y = (m + 1, y) if m < 12 else (1, y + 1)
    month_label = _date(y, m, 1).strftime("%B %Y")
    # Build calendar grid cells
    cal = calendar.Calendar(firstweekday=6).monthdayscalendar(y, m)  # weeks, Sun=0, 0 means empty
    cells = []
    for week in cal:
        for day_num in week:
            if day_num == 0:
                cells.append(None)
            else:
                d = _date(y, m, day_num)
                cells.append({"day": day_num, "date": d.isoformat(), "today": d == today})
    # Load orders
    all_orders = cli.orders_list()
    if role == "vendor":
        vendor_id = session.get("vendor_id", "")
        vendor_ids = session.get("vendor_ids", [vendor_id])
        all_orders = [o for o in all_orders if o.get("vendor_id") in vendor_ids]
    if role == "driver":
        area = session.get("driver_area", "")
        area_set = AREA_STORES.get(area, set())
        all_orders = [o for o in all_orders if o.get("store_name") in area_set]
    # Filter to this month
    prefix = f"{y:04d}-{m:02d}"
    month_orders = [o for o in all_orders if (o.get("delivery_date") or "").startswith(prefix)]
    # Build order_map: date -> list of orders
    order_map = {}
    for o in month_orders:
        d = o.get("delivery_date", "")
        order_map.setdefault(d, []).append(o)
    # Invoiced dates (dates that have at least one invoice)
    invoices_raw = []
    try:
        inv_path = os.path.join(DATA_DIR, "invoices.json")
        if os.path.exists(inv_path):
            with open(inv_path) as f:
                invoices_raw = json.load(f)
    except Exception:
        pass
    invoiced_dates = set(inv.get("delivery_date", "") for inv in invoices_raw if not inv.get("voided"))
    # Build summary list
    month_summary = []
    for day_str, orders in sorted(order_map.items()):
        stores = len(set(o.get("store_name") for o in orders))
        month_summary.append({
            "date": day_str,
            "stores": stores,
            "item_count": len(orders),
            "invoiced": day_str in invoiced_dates,
        })
    return _render(
        _CALENDAR,
        y=y, m=m,
        month_label=month_label,
        prev_y=prev_y, prev_m=prev_m,
        next_y=next_y, next_m=next_m,
        cells=cells,
        order_map=order_map,
        invoiced_dates=invoiced_dates,
        month_summary=month_summary,
        vendor_plan=_vendor_plan,
    )

# ---------------------------------------------------------------------------
# Users (admin only)
# ---------------------------------------------------------------------------

@app.route("/users")
@admin_required
def users():
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    qr_tokens = _load_qr_tokens()
    qr_usernames = {t['username'] for t in qr_tokens}
    user_list = [
        {"id": i+1, "store_name": u.get("store_name", ""), "username": u["username"],
         "role": u.get("role", "store"),
         "vendor_name": ", ".join([vmap.get(v, v) for v in u.get("vendor_ids", [u.get("vendor_id","gmf")])]),
         "has_qr": u["username"] in qr_usernames}
        for i, u in enumerate(_load_users())
    ]
    # Edit context — populate form if ?edit_user= is set
    edit_username = request.args.get("edit_user")
    edit_user_vendors = []
    edit_user_store = ""
    edit_user_store_number = ""
    if edit_username:
        eu = _get_user(edit_username)
        if eu:
            edit_user_vendors = eu.get("vendor_ids", [eu.get("vendor_id", "gmf")])
            edit_user_store = eu.get("store_name", "")
            edit_user_store_number = eu.get("store_number", "")
    return _render(_USERS, user_list=user_list, vendors=vendors,
                   edit_user_vendors=edit_user_vendors,
                   edit_user_store=edit_user_store,
                   edit_user_store_number=edit_user_store_number)

@app.route("/users/edit", methods=["POST"])
@csrf_protect
@admin_required
def users_edit():
    username = request.form["username"]
    users = _load_users()
    for u in users:
        if u["username"] == username:
            u["store_name"] = request.form.get("store", u.get("store_name", ""))
            u["store_number"] = request.form.get("store_number", u.get("store_number", ""))
            vendor_ids = request.form.getlist("vendor_ids")
            if vendor_ids:
                u["vendor_ids"] = vendor_ids
                u["vendor_id"] = vendor_ids[0]
                u["session_version"] = u.get("session_version", 0) + 1  # invalidate active sessions
            break
    _save_users(users)
    return _redirect("users", f"Store '{username}' updated.")

@app.route("/users/add", methods=["POST"])
@csrf_protect
@admin_required
def users_add():
    username = request.form["username"]
    if _get_user(username):
        return _redirect("users", f"Username '{username}' already exists.", cls="err")
    users = _load_users()
    role = request.form.get("role", "store")
    new_user = {
        "id": len(users) + 1,
        "username": username,
        "password": generate_password_hash(request.form["password"]),
        "role": role,
    }
    if role == "vendor":
        new_user["vendor_id"] = request.form.get("vendor_id", "gmf")
        new_user["store_name"] = ""
        new_user["vendor_ids"] = [request.form.get("vendor_id", "gmf")]
    else:
        new_user["store_name"] = request.form.get("store", "")
        vendor_ids = request.form.getlist("vendor_ids") or ["gmf"]
        new_user["vendor_ids"] = vendor_ids
        # Enforce store limit based on vendor plan (gmf is exempt)
        primary_vid = vendor_ids[0]
        if primary_vid != "gmf":
            vendor_obj = _get_vendor(primary_vid)
            vendor_plan = (vendor_obj or {}).get("plan", "starter")
            store_limit = 30 if vendor_plan == "pro" else 10
            existing_stores = [u for u in users if u.get("role") == "store" and primary_vid in u.get("vendor_ids", [])]
            if len(existing_stores) >= store_limit:
                return _redirect("users", f"Store limit reached ({store_limit} stores on {vendor_plan} plan). Upgrade to add more.", cls="err")
    users.append(new_user)
    _save_users(users)
    return _redirect("users", f"User '{username}' added.")

@app.route("/users/remove", methods=["POST"])
@csrf_protect
@admin_required
def users_remove():
    username = request.form["username"]
    if username == "admin":
        return _redirect("users", "Cannot remove admin.", cls="err")
    _save_users([u for u in _load_users() if u["username"] != username])
    return _redirect("users", f"User '{username}' removed.")

@app.route("/users/password", methods=["POST"])
@csrf_protect
@admin_required
def users_password():
    username = request.form["username"]
    users = _load_users()
    for u in users:
        if u["username"] == username:
            u["password"] = generate_password_hash(request.form["password"])
            u["session_version"] = u.get("session_version", 0) + 1
            _save_users(users)
            return _redirect("users", f"Password updated for '{username}'.")
    return _redirect("users", f"User '{username}' not found.", cls="err")

# ---------------------------------------------------------------------------
# API (X-API-Key access for backend automation)
# ---------------------------------------------------------------------------

def _api_auth():
    return request.headers.get("X-API-Key") == API_KEY

@app.route("/api/inventory")
@api_rate_limit
def api_inventory():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    return jsonify(cli.inventory_list())

@app.route("/api/inventory/add", methods=["POST"])
@api_rate_limit
def api_inventory_add():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.json
    return jsonify(cli.inventory_add(d["category"], d["item"], int(d["qty"])))

@app.route("/api/inventory/bulk_replace", methods=["POST"])
@api_rate_limit
def api_inventory_bulk_replace():
    """Replace all items for a given vendor_id with the provided list."""
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    import json as _json
    d = request.json
    vendor_id = d.get("vendor_id")
    new_items = d.get("items", [])
    if not vendor_id:
        return jsonify({"error": "vendor_id required"}), 400
    inv_path = os.path.join(DATA_DIR, "inventory.json")
    with open(inv_path) as _f:
        existing = _json.load(_f)
    # Keep non-vendor items
    kept = [i for i in existing if i.get("vendor_id") != vendor_id]
    # Assign new IDs
    all_ids = [i.get("id", 0) for i in existing if isinstance(i.get("id"), int)]
    next_id = max(all_ids) + 1 if all_ids else 1
    for item in new_items:
        item["id"] = next_id
        next_id += 1
    combined = kept + new_items
    with _get_file_lock(inv_path):
        _atomic_write(inv_path, combined)
    return jsonify({"replaced": len(new_items), "total": len(combined)})

@app.route("/api/orders")
@api_rate_limit
def api_orders():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    all_orders = cli.orders_list(
        store=request.args.get("store"),
        date=request.args.get("date"),
        item=request.args.get("item")
    )
    vendor_id = request.args.get("vendor_id")
    if vendor_id:
        all_orders = [o for o in all_orders if o.get("vendor_id","gmf") == vendor_id]
    return jsonify(all_orders)

@app.route("/api/orders/add", methods=["POST"])
@api_rate_limit
def api_orders_add():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.json
    return jsonify(cli.orders_add(
        store=d["store"], category=d["category"], item=d["item"],
        qty=int(d["qty"]), date=d["date"], ordered_by=d.get("ordered_by", "openclaw")
    ))

@app.route("/api/orders/remove", methods=["POST"])
@api_rate_limit
def api_orders_remove():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    result = cli.orders_remove(int(request.json["id"]))
    return jsonify(result or {"error": "not found"})

@app.route("/api/dates")
@api_rate_limit
def api_dates():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    return jsonify(cli.dates_list())

@app.route("/api/users/bulk_replace", methods=["POST"])
@api_rate_limit
def api_users_bulk_replace():
    """Replace all store users for a vendor_id with the provided list. Keeps non-store and non-vendor accounts."""
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    from werkzeug.security import generate_password_hash as _gph
    d = request.json
    vendor_id = d.get("vendor_id")
    new_stores = d.get("users", [])
    if not vendor_id:
        return jsonify({"error": "vendor_id required"}), 400
    existing = _load_users()
    # Keep non-store accounts and store accounts for OTHER vendors
    kept = [u for u in existing if u.get("role") != "store" or u.get("vendor_id") != vendor_id]
    # Assign IDs
    all_ids = [u.get("id", 0) for u in existing if isinstance(u.get("id"), int)]
    next_id = max(all_ids) + 1 if all_ids else 10
    # Preserve existing IDs where username matches
    existing_id_map = {u["username"]: u["id"] for u in existing}
    for u in new_stores:
        if u["username"] in existing_id_map:
            u["id"] = existing_id_map[u["username"]]
        else:
            u["id"] = next_id
            next_id += 1
        # Re-hash plain passwords with werkzeug if they look like raw SHA256
        pw = u.get("password", "")
        if pw and not pw.startswith("pbkdf2:") and not pw.startswith("scrypt:"):
            u["password"] = _gph(u["_plain_password"]) if u.get("_plain_password") else _gph(pw)
        if "_plain_password" in u:
            del u["_plain_password"]
    combined = kept + new_stores
    # Safety check: never save if admin/vendor accounts lost their password
    for _u in combined:
        if _u.get("role") in ("admin", "vendor") and not _u.get("password"):
            return jsonify({"error": f"Safety abort: {_u['username']} would lose password hash"}), 500
    _save_users(combined)
    # Clear all QR tokens for store users of this vendor
    tokens = _load_qr_tokens()
    store_usernames = {u["username"] for u in new_stores}
    tokens = [t for t in tokens if t.get("username") not in store_usernames]
    _save_qr_tokens(tokens)
    return jsonify({"replaced": len(new_stores), "total": len(combined), "qr_tokens_cleared": True})

@app.route("/api/users/bulk_qr", methods=["POST"])
@api_rate_limit
def api_users_bulk_qr():
    """Generate QR tokens for all store users of a vendor. Returns list of {username, token, url}."""
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    d = request.json or {}
    vendor_id = d.get("vendor_id")
    all_users = _load_users()
    targets = [
        u["username"] for u in all_users
        if u.get("role") == "store" and (
            not vendor_id or u.get("vendor_id") == vendor_id or vendor_id in u.get("vendor_ids", [])
        )
    ]
    results = []
    base_url = request.host_url.rstrip("/")
    for username in targets:
        token = _generate_qr_token(username)
        results.append({"username": username, "token": token, "url": f"{base_url}/qr/{token}"})
    return jsonify({"generated": len(results), "tokens": results})

@app.route("/api/users")
@api_rate_limit
def api_users():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    vendor_filter = request.args.get("vendor_id")
    users = _load_users()
    result = []
    for u in users:
        uid = u.get("vendor_id") or (u.get("vendor_ids") or ["gmf"])[0]
        if vendor_filter and uid != vendor_filter:
            continue
        result.append({"id": u.get("id"), "store_name": u.get("store_name"), "username": u["username"], "role": u.get("role"), "vendor_id": uid})
    return jsonify(result)

@app.route("/api/daily-summary", methods=["POST"])
@api_rate_limit
def api_daily_summary():
    if not _api_auth(): return jsonify({"error": "unauthorized"}), 401
    import datetime
    delivery_date = request.json.get("date") if request.json else None
    if not delivery_date:
        tomorrow = datetime.date.today() + datetime.timedelta(days=1)
        delivery_date = tomorrow.isoformat()
    _send_office_daily_summary(delivery_date)
    return jsonify({"ok": True, "date": delivery_date})


_VENDORS = _page("""
<h1>Vendors</h1>
<div class="card">
  <h2>Add Vendor</h2>
  <form method="post" action="{{ url_for('vendors_add') }}">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Vendor Name</label><input name="name" type="text" required></div>
      <div class="field"><label>Slug (short ID, no spaces)</label><input name="slug" type="text" required></div>
      <div class="field"><label>Office Email</label><input name="office_email" type="email"></div>
      <div class="field"><label>Plan</label><select name="plan" style="padding:.4rem .6rem;background:#1a1a1a;color:#eee;border:1px solid #444;border-radius:6px"><option value="starter">Starter</option><option value="standard">Standard</option><option value="pro">Pro</option><option value="seasonal">Seasonal</option></select></div>
      <button class="btn btn-green" type="submit" style="align-self:flex-end">Add Vendor</button>
    </div>
  </form>
</div>
<div class="card">
  <h2>All Vendors ({{ vendor_list|length }})</h2>
  {% if vendor_list %}
  <table>
    <tr><th>ID</th><th>Name</th><th>Office Email</th><th>Plan</th><th>Auto Invoice</th><th>Auto QB Sync</th><th></th></tr>
    {% for v in vendor_list %}
    <tr>
      <td>{{ v.id }}</td><td>{{ v.name }}</td><td>{{ v.office_email or '—' }}</td>
      <td>{{ v.plan or 'starter' }}</td>
      <td>
        {% if v.plan in ('standard','pro','seasonal') %}
        <form method="post" action="{{ url_for('vendors_toggle') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="vendor_id" value="{{ v.id }}">
          <input type="hidden" name="field" value="auto_invoice">
          <button class="btn {{ 'btn-green' if v.auto_invoice else '' }}" style="font-size:.8rem;padding:.25rem .6rem">{{ 'ON' if v.auto_invoice else 'OFF' }}</button>
        </form>
        {% else %}<span style="color:#555;font-size:.8rem">Standard+</span>{% endif %}
      </td>
      <td>
        {% if v.plan in ('standard','pro','seasonal') %}
        <form method="post" action="{{ url_for('vendors_toggle') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="vendor_id" value="{{ v.id }}">
          <input type="hidden" name="field" value="auto_qb_sync">
          <button class="btn {{ 'btn-green' if v.auto_qb_sync else '' }}" style="font-size:.8rem;padding:.25rem .6rem">{{ 'ON' if v.auto_qb_sync else 'OFF' }}</button>
        </form>
        {% else %}<span style="color:#555;font-size:.8rem">Standard+</span>{% endif %}
      </td>
      <td>{% if v.id != 'gmf' %}
        <form method="post" action="{{ url_for('vendors_remove') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="vendor_id" value="{{ v.id }}">
          <button class="btn btn-red" onclick="return confirm('Remove {{ v.name }}?')">Remove</button>
        </form>
      {% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No vendors yet.</p>{% endif %}
</div>
""")

# ---------------------------------------------------------------------------
# Pick List
# ---------------------------------------------------------------------------

_PICKLIST = _page("""
<style>
@page { size: landscape; margin: 8mm; }
@media print {
  nav, .timeout-bar, .flash, .no-print { display: none !important; }
  body { background: #fff !important; color: #000 !important; }
  .picklist-sheet { page-break-after: always; }
  .picklist-sheet:last-child { page-break-after: avoid; }
  .print-header { display: block !important; }
  h2 { font-size: 1rem !important; margin: .3rem 0 .2rem !important; color: #000 !important; }
  /* Force table to fill page width without overflowing */
  table.picklist-table {
    border-collapse: collapse;
    width: 100% !important;
    table-layout: fixed !important;
  }
  table.picklist-table th,
  table.picklist-table td,
  table.picklist-table tr:nth-child(even) td,
  table.picklist-table tr:hover td,
  table.picklist-table .total-row td {
    border: 1px solid #999 !important;
    padding: 1px 2px !important;
    font-size: .62rem !important;
    color: #000 !important;
    background: #fff !important;
  }
  table.picklist-table .total-row td {
    font-weight: 700 !important;
    border-top: 2px solid #333 !important;
    background: #eee !important;
  }
  table.picklist-table th {
    background: #e0e0e0 !important;
    font-weight: 700 !important;
  }
  /* Item column: fixed width so store columns share the rest */
  table.picklist-table td.item-col,
  table.picklist-table th:first-child {
    width: 130px !important;
    min-width: 0 !important;
    font-size: .62rem !important;
  }
  /* Store + total columns: no min-width, let table-layout compress them */
  table.picklist-table td.qty-col,
  table.picklist-table th:not(:first-child) {
    min-width: 0 !important;
    max-width: none !important;
    text-align: center;
    white-space: normal;
    word-break: break-word;
    font-size: .62rem !important;
  }
}
.print-header { display: none; }
.picklist-controls { display:flex; gap:1rem; flex-wrap:wrap; align-items:flex-end; margin-bottom:1.2rem; }
.picklist-controls label { font-weight:600; font-size:.9rem; }
.picklist-controls select, .picklist-controls input { padding:.4rem .7rem; border-radius:6px; border:1px solid #555; background:#1e1e1e; color:#eee; font-size:.9rem; }
.picklist-controls .btn { align-self:flex-end; }
.picklist-sheet { margin-bottom: 2.5rem; }
.picklist-sheet h2 { font-size:1.2rem; font-weight:700; margin-bottom:.6rem; }
table.picklist-table { border-collapse: collapse; width:100%; table-layout:fixed; margin-bottom:.5rem; }
table.picklist-table th { background:#2a2a2a; color:#eee; padding:.3rem .2rem; border:1px solid #444; font-size:.72rem; text-align:center; white-space:normal; word-break:break-word; vertical-align:bottom; overflow:hidden; }
table.picklist-table td { padding:.3rem .2rem; border:1px solid #444; font-size:.72rem; overflow:hidden; text-overflow:ellipsis; }
table.picklist-table td.item-col { font-weight:500; width:160px; text-align:left; white-space:nowrap; }
table.picklist-table td.qty-col { text-align:center; }
table.picklist-table th:first-child { width:160px; text-align:left; }
table.picklist-table tr:nth-child(even) td { background:#1a1a1a; }
table.picklist-table tr:hover td { background:#222; }
.total-row td { font-weight:700; background:#222 !important; border-top:2px solid #666; }
</style>

<div class="picklist-controls no-print">
  <div>
    <label style="font-weight:600;font-size:.9rem;display:block;margin-bottom:.35rem">Delivery Date</label>
    <div style="display:flex;align-items:center;gap:.6rem">
      <button type="button" id="pl-date-prev" onclick="plStepDate(-1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:1rem">&#9664;</button>
      <span id="pl-date-display" style="min-width:120px;text-align:center;color:#e0e0e0;font-size:1rem;font-weight:600"></span>
      <button type="button" id="pl-date-next" onclick="plStepDate(1)" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:1rem">&#9654;</button>
    </div>
    <script>
    (function(){
      var current = {{ filter_date | tojson }};
      document.getElementById('pl-date-display').textContent = current;
      function stepDay(dateStr, dir){
        var d = new Date(dateStr + 'T00:00:00');
        d.setDate(d.getDate() + dir);
        return d.toISOString().slice(0,10);
      }
      window.plStepDate = function(dir){
        window.location.href = '{{ url_for("picklist") }}?date=' + stepDay(current, dir);
      };
    })();
    </script>
  </div>
  <button class="btn btn-blue no-print" onclick="window.print()">🖨️ Print All</button>
</div>
<script>
function printSheet(sheetId) {
  var sheets = document.querySelectorAll('.picklist-sheet');
  sheets.forEach(function(s) {
    if (s.id !== sheetId) s.style.display = 'none';
  });
  window.print();
  sheets.forEach(function(s) { s.style.display = ''; });
}
</script>

{% if not brewer_sheet and not biddeford_sheet %}
  <p class="empty">No orders found for {{ filter_date }}.</p>
{% endif %}

{% for sheet in [brewer_sheet, biddeford_sheet] %}
{% if sheet %}
<div class="picklist-sheet" id="sheet-{{ sheet.area | lower | replace(' ', '-') }}">
  <div class="no-print" style="display:flex;justify-content:flex-end;margin-bottom:.5rem">
    <button class="btn" style="font-size:.78rem;padding:.25rem .7rem" onclick="printSheet('sheet-{{ sheet.area | lower | replace(\" \", \"-\") }}')">🖨️ Print {{ sheet.area }} Only</button>
  </div>
  <h2>{{ sheet.area }} — {{ filter_date }}</h2>
  <p class="print-header" style="font-size:.8rem;color:#555;margin-bottom:.4rem">Green Meadow Farms | orders.everblack.cloud</p>
  <table class="picklist-table">
    <thead>
      <tr>
        <th style="text-align:left">Item</th>
        {% for store in sheet.stores %}<th>{{ store }}</th>{% endfor %}
        <th>CASES</th>
      </tr>
    </thead>
    <tbody>
      {% for row in sheet.rows %}
      <tr>
        <td class="item-col">{{ row.item }}</td>
        {% for store in sheet.stores %}
        <td class="qty-col">{{ row.qtys.get(store, '') }}</td>
        {% endfor %}
        <td class="qty-col">{{ row.total }}</td>
      </tr>
      {% endfor %}
      <tr class="total-row">
        <td>TOTAL CASES</td>
        {% for store in sheet.stores %}
        <td class="qty-col">{{ sheet.store_totals.get(store, 0) }}</td>
        {% endfor %}
        <td class="qty-col">{{ sheet.grand_total }}</td>
      </tr>
    </tbody>
  </table>
</div>
{% endif %}
{% endfor %}
""")

@app.route("/picklist")
@vendor_required
def picklist():
    from datetime import date as _date
    _today_iso2 = _date.today().isoformat()
    allowed_dates = sorted(cli.dates_list())
    filter_date = request.args.get("date") or _today_iso2

    # Load all orders for this vendor on this date
    vendor_id = session.get("vendor_id") or (session.get("vendor_ids") or ["gmf"])[0]
    vendor_ids = session.get("vendor_ids") or [vendor_id]
    if session.get("role") == "admin":
        all_orders = cli.orders_list()
    else:
        all_orders = [o for o in cli.orders_list() if o.get("vendor_id", "gmf") in vendor_ids]
    all_orders = [o for o in all_orders if o.get("delivery_date", "").strip() == filter_date.strip()]

    def build_sheet(area_name, store_set):
        orders = [o for o in all_orders if o.get("store_name") in store_set]
        if not orders:
            return None
        # Collect stores that actually ordered
        stores = sorted(set(o.get("store_name", "") for o in orders))
        # Aggregate: item -> store -> case count
        item_store_qty = {}
        for o in orders:
            item = o.get("item", "")
            store = o.get("store_name", "")
            cases = o.get("cases") or 1
            try:
                cases = int(cases)
            except (ValueError, TypeError):
                cases = 1
            if item not in item_store_qty:
                item_store_qty[item] = {}
            item_store_qty[item][store] = item_store_qty[item].get(store, 0) + cases
        # Build rows sorted by item name
        rows = []
        for item in sorted(item_store_qty.keys()):
            qtys = item_store_qty[item]
            total = sum(qtys.values())
            rows.append({"item": item, "qtys": qtys, "total": total})
        # Per-store totals
        store_totals = {s: sum(item_store_qty[it].get(s, 0) for it in item_store_qty) for s in stores}
        grand_total = sum(store_totals.values())
        return {
            "area": area_name,
            "stores": stores,
            "rows": rows,
            "store_totals": store_totals,
            "grand_total": grand_total,
        }

    # Build display-name sets for each area by mapping usernames → store_name via users
    _all_users = _load_users()
    def _area_display_names(username_set):
        names = set()
        for u in _all_users:
            if u.get('username') in username_set and u.get('store_name'):
                names.add(u['store_name'])
        return names
    brewer_display = _area_display_names(BREWER_STORES)
    biddeford_display = _area_display_names(BIDDEFORD_STORES)

    brewer_sheet = build_sheet("Brewer Route", brewer_display)
    biddeford_sheet = build_sheet("Biddeford Route", biddeford_display)

    return _render(_PICKLIST,
        filter_date=filter_date,
        allowed_dates=allowed_dates,
        brewer_sheet=brewer_sheet,
        biddeford_sheet=biddeford_sheet,
    )

# ---------------------------------------------------------------------------
# Vendors (admin only)
# ---------------------------------------------------------------------------

@app.route("/vendors")
@admin_required
def vendors():
    return _render(_VENDORS, vendor_list=_load_vendors())

@app.route("/vendors/add", methods=["POST"])
@csrf_protect
@admin_required
def vendors_add():
    slug = request.form["slug"].strip().lower().replace(" ", "_")
    vendors = _load_vendors()
    if any(v["id"] == slug for v in vendors):
        return _redirect("vendors", f"Vendor '{slug}' already exists.", cls="err")
    vendors.append({
        "id": slug,
        "name": request.form["name"],
        "slug": slug,
        "office_email": request.form.get("office_email", ""),
        "plan": request.form.get("plan", "starter")
    })
    _save_vendors(vendors)
    return _redirect("vendors", f"Vendor '{request.form['name']}' added.")

@app.route("/vendors/remove", methods=["POST"])
@csrf_protect
@admin_required
def vendors_remove():
    vid = request.form["vendor_id"]
    if vid == "gmf":
        return _redirect("vendors", "Cannot remove default vendor.", cls="err")
    _save_vendors([v for v in _load_vendors() if v["id"] != vid])
    return _redirect("vendors", "Vendor removed.")

@app.route("/vendors/toggle", methods=["POST"])
@csrf_protect
@admin_required
def vendors_toggle():
    vid = request.form["vendor_id"]
    field = request.form["field"]
    if field not in ("auto_invoice", "auto_qb_sync"):
        return _redirect("vendors", "Invalid field.", cls="err")
    vendors = _load_vendors()
    for v in vendors:
        if v["id"] == vid:
            if v.get("plan", "starter") not in ("standard", "pro", "seasonal"):
                return _redirect("vendors", "Standard, Pro or Seasonal plan required.", cls="err")
            v[field] = not v.get(field, False)
            label = "Auto Invoice" if field == "auto_invoice" else "Auto QB Sync"
            state = "enabled" if v[field] else "disabled"
            _save_vendors(vendors)
            return _redirect("vendors", f"{label} {state} for {v['name']}.")
    return _redirect("vendors", "Vendor not found.", cls="err")


# ---------------------------------------------------------------------------
# Invoice Templates
# ---------------------------------------------------------------------------

_QB_MATCH = _page("""
<h1>QB Customer Matching</h1>
<p style="color:#aaa;margin-bottom:1.5rem">Match each store to their QuickBooks customer name. Use the search box to filter QB customers. Leave blank to skip a store.</p>
<form method="post" action="{{ url_for('qb_match_customers_save') }}">
{{ csrf_field }}
<div class="card" style="overflow-x:auto">
  <div style="margin-bottom:1rem;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap">
    <input type="text" id="store-search" placeholder="Filter stores..." oninput="filterStores()" style="padding:.4rem .75rem;border-radius:6px;border:1px solid rgba(139,92,246,0.6);background:rgba(88,28,135,0.15);color:#e2e8f0;min-width:220px;box-shadow:0 0 0 2px rgba(124,58,237,0.2),0 0 12px rgba(139,92,246,0.25)">
    <span id="store-count" style="color:#aaa;font-size:.85rem"></span>
  </div>
  <table>
    <tr><th style="min-width:220px">Store</th><th style="min-width:280px">QB Customer</th><th>Current Mapping</th></tr>
    {% for u in store_users %}
    <tr class="store-row" data-name="{{ u.store_name | lower }}">
      <td style="font-weight:600">{{ u.store_name }}</td>
      <td>
        <select name="qb_{{ u.username }}" style="width:100%;padding:.35rem .5rem;background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:5px;color:#e0e0e0;font-size:.85rem">
          <option value="">— not matched —</option>
          <option value="__clear__">&#x274c; Clear mapping</option>
          {% for c in qb_customers %}
          <option value="{{ c.DisplayName }}" {% if u.qb_customer_name == c.DisplayName %}selected{% endif %}>{{ c.DisplayName }}</option>
          {% endfor %}
        </select>
      </td>
      <td style="color:{% if u.qb_customer_name %}#52c97a{% else %}#666{% endif %};font-size:.85rem">
        {{ u.qb_customer_name or '—' }}
      </td>
    </tr>
    {% endfor %}
  </table>
</div>
<div style="margin-top:1.25rem;display:flex;gap:.75rem">
  <button class="btn btn-green" type="submit">Save All Mappings</button>
  <a href="{{ url_for('invoices') }}" class="btn" style="text-decoration:none">Cancel</a>
</div>
</form>
<script>
function filterStores() {
  var q = document.getElementById('store-search').value.toLowerCase();
  var rows = document.querySelectorAll('.store-row');
  var shown = 0;
  rows.forEach(function(r) {
    var match = !q || r.getAttribute('data-name').indexOf(q) !== -1;
    r.style.display = match ? '' : 'none';
    if (match) shown++;
  });
  document.getElementById('store-count').textContent = shown + ' stores shown';
}
filterStores();
</script>
""")

_INVOICES = _page("""
<h1>Invoices</h1>
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem;margin-bottom:1rem">
  {% if session.role == 'admin' %}
  <a href="{{ url_for('invoices_create') }}" class="btn btn-green">+ New Invoice</a>
  {% else %}<div></div>{% endif %}
  {% if session.role == 'vendor' %}
  <div>
    {% if qb_connected %}
    <span style="color:#52c97a;font-size:.9rem">&#10003; QuickBooks Connected</span>
    <form method="post" action="{{ url_for('qb_disconnect') }}" style="display:inline;margin-left:.75rem">
{{ csrf_field }}
      <button class="btn btn-red" style="font-size:.8rem" onclick="return confirm('Disconnect QuickBooks?')">Disconnect</button>
    </form>
    {% else %}
    <a href="{{ url_for('qb_connect') }}" class="btn" style="background:#2CA01C;color:#fff;display:inline-flex;align-items:center;gap:.5rem;font-size:.9rem">
      <svg width="18" height="18" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="#2CA01C"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-size="14" font-weight="bold" fill="white">QB</text></svg>
      Connect QuickBooks
    </a>
    {% endif %}
  </div>
  {% endif %}
  {% if qb_connected and (session.role == 'admin' or vendor_plan in ('standard','pro','seasonal')) %}
  {% if session.role == 'admin' %}
  <form method="post" action="{{ url_for('qb_sync_customers') }}" style="display:inline">
{{ csrf_field }}
    <button class="btn btn-blue" style="font-size:.85rem" onclick="return confirm('Fetch all QB customers and auto-map store users?')">🔄 Auto-Sync QB Customer Names</button>
  </form>
  {% endif %}
  <a href="{{ url_for('qb_match_customers') }}" class="btn btn-green" style="font-size:.85rem;text-decoration:none">🎯 Manual QB Match</a>
  <a href="{{ url_for('qb_map_items') }}" class="btn btn-blue" style="font-size:.85rem;text-decoration:none">📦 QB Item Mapping</a>
  {% endif %}
</div>
<div style="margin-bottom:.75rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap">
  <button onclick="selectAllInvoices(true)" class="btn" style="font-size:.8rem;padding:.3rem .7rem">Select All</button>
  <button onclick="selectAllInvoices(false)" class="btn" style="font-size:.8rem;padding:.3rem .7rem">Clear</button>
  <button onclick="printSelectedInvoices()" class="btn btn-green" style="font-size:.8rem;padding:.3rem .7rem">🖨 Print Selected</button>
  <span id="sel-count" style="color:#aaa;font-size:.82rem"></span>
</div>
<div class="card" id="invoice-table-card">
  <table>
    <tr><th style="width:32px"></th><th>Invoice #</th><th>Vendor</th><th>Store</th><th>Delivery Date</th><th>Due Date</th><th>Total</th><th>Status</th><th></th></tr>
    {% for inv in invoices %}
    <tr>
      <td><input type="checkbox" class="inv-check" data-id="{{ inv.id }}" onchange="updateSelCount()"></td>
      <td style="font-family:monospace;font-size:.9rem">#{{ inv.id }}</td>
      <td>{{ inv.vendor_name }}</td>
      <td>{{ inv.store_name }}{% if inv.store_number %} #{{ inv.store_number }}{% endif %}</td>
      <td>{{ inv.delivery_date }}</td>
      <td>{{ inv.due_date }}</td>
      <td>${{ '%.2f'|format(inv.total|float) }}</td>
      <td><span class="pill" style="background:{% if inv.status=='paid' %}#2d6a4f{% elif inv.status=='void' %}#555{% else %}#8b1a1a{% endif %};color:#fff">{{ inv.status }}</span></td>
      <td><a href="{{ url_for('invoice_view', invoice_id=inv.id) }}" class="btn btn-blue" style="font-size:.8rem">View</a></td>
    </tr>
    {% else %}
    <tr><td colspan="9"><p class="empty">No invoices yet.</p></td></tr>
    {% endfor %}
  </table>
</div>
<script>
function updateSelCount(){
  var n = document.querySelectorAll('.inv-check:checked').length;
  document.getElementById('sel-count').textContent = n ? n+' selected' : '';
}
function selectAllInvoices(checked){
  document.querySelectorAll('.inv-check').forEach(function(c){c.checked=checked;});
  updateSelCount();
}
function printSelectedInvoices(){
  var ids = Array.from(document.querySelectorAll('.inv-check:checked')).map(function(c){return c.getAttribute('data-id');});
  if(!ids.length){alert('Select at least one invoice.');return;}
  var w = window.open('','_blank','width=900,height=700');
  w.document.write('<html><head><title>Invoices</title><style>body{font-family:sans-serif;padding:1rem} @media print{.no-print{display:none}} table{width:100%;border-collapse:collapse;margin-bottom:2rem} td,th{border:1px solid #ccc;padding:6px 10px;font-size:12px} h2{margin:.5rem 0} .page-break{page-break-after:always}</style></head><body>');
  w.document.write('<div class="no-print" style="margin-bottom:1rem"><button onclick="window.print()">Print</button> <button onclick="window.close()">Close</button></div>');
  var done = 0;
  ids.forEach(function(id){
    fetch('/invoices/'+id+'/print_fragment')
      .then(function(r){return r.text();})
      .then(function(html){
        w.document.write('<div class="page-break">'+html+'</div>');
        done++;
        if(done===ids.length){w.document.write('</body></html>');w.document.close();}
      });
  });
}
</script>
""")

_INVOICE_CREATE = _page("""
<h1>Create Invoice</h1>
<div class="card">
  <form method="post" action="{{ url_for('invoices_create') }}" id="inv-form">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Vendor</label>
        <select name="vendor_id" id="vendor-select" onchange="this.form.submit()">
          {% for v in vendors %}<option value="{{ v.id }}" {% if v.id == selected_vendor_id %}selected{% endif %}>{{ v.name }}</option>{% endfor %}
        </select>
      </div>
      <div class="field"><label>Store</label>
        <select name="store_username">
          {% for s in stores %}<option value="{{ s.username }}" {% if s.store_name == prefill_store %}selected{% endif %}>{{ s.store_name }}{% if s.store_number %} #{{ s.store_number }}{% endif %}</option>{% endfor %}
        </select>
      </div>
      <div class="field"><label>Delivery Date</label><input type="date" name="delivery_date" value="{{ prefill_date }}" required></div>
      <div class="field"><label>Due Date</label><input type="date" name="due_date" required></div>
    </div>
    <h3 style="margin-top:1.5rem">Line Items</h3>
    <div id="line-items">
      <div class="form-row line-item" style="margin-bottom:.5rem">
        <div class="field"><label>Item</label><input name="item[]" type="text" required placeholder="e.g. Apples 40#"></div>
        <div class="field" style="width:80px"><label>Qty</label><input name="qty[]" type="number" min="1" required></div>
        <div class="field" style="width:120px"><label>Unit Price ($)</label><input name="price[]" type="number" step="0.01" min="0" required></div>
        <div class="field" style="align-self:flex-end"><button type="button" class="btn btn-red" onclick="removeLine(this)">✕</button></div>
      </div>
    </div>
    <button type="button" class="btn btn-blue" onclick="addLine()" style="margin:.5rem 0 1rem">+ Add Item</button>
    <div class="form-row">
      <div class="field"><label>Notes</label><input name="notes" type="text" placeholder="Optional"></div>
      <div class="field"><label>Send to Email</label><input name="send_email" type="email" placeholder="Optional"></div>
    </div>
    <input type="hidden" name="_action" value="save">
    <div style="margin-top:1rem;display:flex;gap:.75rem">
      <button class="btn btn-green" type="submit">Save Invoice</button>
      <a href="{{ url_for('invoices') }}" class="btn">Cancel</a>
    </div>
  </form>
</div>
<script>
function addLine(){
  var t=document.querySelector('.line-item').cloneNode(true);
  t.querySelectorAll('input').forEach(function(i){i.value='';});
  document.getElementById('line-items').appendChild(t);
}
function removeLine(btn){
  var lines=document.querySelectorAll('.line-item');
  if(lines.length>1) btn.closest('.line-item').remove();
}
</script>
""")

_INVOICE_VIEW = _page("""
<style>
@media print {
  nav, .timeout-bar, .flash, #print-btn-row, a.btn, button.btn, form { display: none !important; }
  body { background: #fff !important; color: #000 !important; }
  .card { background: #fff !important; color: #000 !important; border: 1px solid #ccc !important; box-shadow: none !important; }
  .container { max-width: 100% !important; padding: 0 !important; }
  table { border-collapse: collapse !important; }
  th, td { color: #000 !important; background: #fff !important; border: 1px solid #ccc !important; }
  tr:nth-child(even) td { background: #f5f5f5 !important; }
  tr:hover td { background: #f5f5f5 !important; }
  .total-row td { background: #e8e8e8 !important; font-weight: 700 !important; border-top: 2px solid #333 !important; }
  table th { background: #e0e0e0 !important; font-weight: 700 !important; }
  tr[style] { background: #f5f5f5 !important; }
  h1, h2 { color: #000 !important; }
  strong { color: #000 !important; }
  .pill { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .print-logo { display: block !important; }
}
.print-logo { display: none; }
</style>
<div class="print-logo" style="margin-bottom:1.5rem;border-bottom:2px solid #2d6a4f;padding-bottom:1rem">
  {% if inv.vendor_id == 'gmf' %}
  <img src="data:image/jpeg;base64,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" alt="Green Meadow Farms" style="height:70px;display:block;margin-bottom:.4rem">
  {% else %}
  <strong style="font-size:1.4rem;letter-spacing:.05em">Everblack™</strong>
  <span style="display:block;font-size:.85rem;color:#555">orders.everblack.cloud</span>
  {% endif %}
</div>
<div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem">
  <h1 style="margin:0">Invoice #{{ inv.id }}</h1>
  <span class="pill" style="background:{% if inv.status=='paid' %}#2d6a4f{% elif inv.status=='void' %}#555{% else %}#8b1a1a{% endif %};color:#fff;font-size:.9rem">{{ inv.status }}</span>
</div>
<div class="card">
  <div style="display:flex;flex-wrap:wrap;gap:1.5rem;margin-bottom:1rem">
    <div><strong>Vendor:</strong> {{ inv.vendor_name }}</div>
    <div><strong>Store:</strong> {{ inv.store_name }}{% if inv.store_number %} #{{ inv.store_number }}{% endif %}</div>
    <div><strong>Delivery:</strong> {{ inv.delivery_date }}</div>
    <div><strong>Due:</strong> {{ inv.due_date }}</div>
    <div><strong>Created:</strong> {{ inv.created_date }}</div>
    {% if inv.paid_date %}<div><strong>Paid:</strong> {{ inv.paid_date }}</div>{% endif %}
    {% if inv.qb_doc_number %}<div><strong>Invoice #:</strong> {{ inv.qb_doc_number }}</div>{% endif %}
  </div>
  <table style="width:100%;border-collapse:collapse">
    <tr style="background:#e9f5ee">
      <th style="padding:.5rem .75rem;text-align:left">Item</th>
      {% if inv.line_items and inv.line_items|selectattr('upc')|list %}
      <th style="padding:.5rem .75rem;text-align:left">{% if show_barcodes %}Barcode{% else %}Item # / SKU{% endif %}</th>
      {% endif %}
      <th style="padding:.5rem .75rem;text-align:right">Qty</th>
      <th style="padding:.5rem .75rem;text-align:right">Unit Price</th>
      <th style="padding:.5rem .75rem;text-align:right">Total</th>
    </tr>
    {% for li in inv.line_items %}
    <tr style="border-bottom:1px solid #2a2a2a{% if li.unit_price == 0 or li.unit_price == 0.0 %};background:rgba(252,129,74,0.08){% endif %}">
      <td style="padding:.45rem .75rem">{{ li.item }}{% if li.unit_price == 0 or li.unit_price == 0.0 %} <span style="font-size:.75rem;color:#fc8181" title="No price matched in QuickBooks">⚠ no QB price</span>{% endif %}</td>
      {% if inv.line_items and inv.line_items|selectattr('upc')|list %}
      <td style="padding:.45rem .75rem">
        {% if li.upc and li.upc != 'None' %}
          {% if show_barcodes %}
          {% if li.barcode_b64 %}
          <img src="data:image/png;base64,{{ li.barcode_b64 }}" style="display:block;height:40px;max-width:160px" alt="{{ li.upc }}">
          {% else %}
          <svg class="inv-barcode" data-upc="{{ li.upc }}" style="display:block;min-width:120px"></svg>
          {% endif %}
          <div style="font-size:.7rem;color:#666;text-align:center;margin-top:2px">{{ li.upc }}</div>
          {% else %}
          <span style="font-family:monospace;font-size:.85rem">{{ li.upc }}</span>
          {% endif %}
        {% else %}&mdash;{% endif %}
      </td>
      {% endif %}
      <td style="padding:.45rem .75rem;text-align:right">{{ li.qty }}</td>
      <td style="padding:.45rem .75rem;text-align:right">${{ '%.2f'|format(li.unit_price|float) }}</td>
      <td style="padding:.45rem .75rem;text-align:right">${{ '%.2f'|format(li.total|float) }}</td>
    </tr>
    {% endfor %}
    <tr style="font-weight:bold">
      <td colspan="{% if inv.line_items and inv.line_items|selectattr('upc')|list %}4{% else %}3{% endif %}" style="padding:.5rem .75rem;text-align:right">Total Due</td>
      <td style="padding:.5rem .75rem;text-align:right">${{ '%.2f'|format(inv.total|float) }}</td>
    </tr>
  </table>
  {% if inv.notes %}<p style="margin-top:1rem">Notes: {{ inv.notes }}</p>{% endif %}
</div>
{% if session.role == 'admin' %}
<div id="print-btn-row" style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap">
  {% if can_print %}<button class="btn" onclick="if(typeof renderInvBarcodes==='function'){renderInvBarcodes();} setTimeout(function(){window.print();},150)">🖨 Print / Save PDF</button>{% endif %}
  {% if inv.status == 'unpaid' %}
  <form method="post" action="{{ url_for('invoice_action', invoice_id=inv.id) }}">
{{ csrf_field }}
    <input type="hidden" name="action" value="paid">
    <button class="btn btn-green">Mark Paid</button>
  </form>
  <form method="post" action="{{ url_for('invoice_email', invoice_id=inv.id) }}">
{{ csrf_field }}
    <div style="display:flex;gap:.5rem;align-items:center">
      <input type="email" name="to_email" placeholder="Send to email" style="padding:.4rem .75rem;border-radius:6px;border:1px solid #444;background:#111;color:#eee" required>
      <button class="btn btn-blue">Email Invoice</button>
    </div>
  </form>
  <form method="post" action="{{ url_for('invoice_action', invoice_id=inv.id) }}">
{{ csrf_field }}
    <input type="hidden" name="action" value="void">
    <button class="btn btn-red" onclick="return confirm('Void this invoice?')">Void</button>
  </form>
  {% elif inv.status == 'paid' %}
  <form method="post" action="{{ url_for('invoice_action', invoice_id=inv.id) }}">
{{ csrf_field }}
    <input type="hidden" name="action" value="unpaid">
    <button class="btn">Mark Unpaid</button>
  </form>
  {% endif %}
  {% if qb_connected %}
    {% if inv.qb_invoice_id %}
    <span style="color:#52c97a;font-size:.85rem;align-self:center">✅ Synced to QB{% if inv.qb_doc_number %} — Invoice #{{ inv.qb_doc_number }}{% else %} #{{ inv.qb_invoice_id }}{% endif %}</span>
    {% else %}
    <form method="post" action="{{ url_for('invoice_qb_sync', invoice_id=inv.id) }}">
{{ csrf_field }}
      <button class="btn btn-blue">Sync to QuickBooks</button>
    </form>
    {% endif %}
  {% endif %}
  {% if inv.status == 'void' %}
  <form method="post" action="{{ url_for('invoice_action', invoice_id=inv.id) }}" style="display:inline">
{{ csrf_field }}
    <input type="hidden" name="action" value="delete">
    <button class="btn btn-red" onclick="return confirm('Delete this invoice permanently?')">Delete</button>
  </form>
  {% endif %}
  <a href="{{ url_for('invoices') }}" class="btn">Back</a>
</div>
{% elif session.role == 'vendor' %}
<div id="print-btn-row" style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap">
  {% if can_print %}<button class="btn" onclick="if(typeof renderInvBarcodes==='function'){renderInvBarcodes();} setTimeout(function(){window.print();},150)">🖨 Print / Save PDF</button>{% endif %}
  {% if inv.status == 'unpaid' %}
  <form method="post" action="{{ url_for('invoice_email', invoice_id=inv.id) }}">
{{ csrf_field }}
    <div style="display:flex;gap:.5rem;align-items:center">
      <input type="email" name="to_email" placeholder="Send to email" style="padding:.4rem .75rem;border-radius:6px;border:1px solid #444;background:#111;color:#eee" required>
      <button class="btn btn-blue">Email Invoice</button>
    </div>
  </form>
  {% endif %}
  {% if qb_connected %}
    {% if inv.qb_invoice_id %}
    <span style="color:#52c97a;font-size:.85rem;align-self:center">✅ Synced to QB{% if inv.qb_doc_number %} — Invoice #{{ inv.qb_doc_number }}{% else %} #{{ inv.qb_invoice_id }}{% endif %}</span>
    {% else %}
    <form method="post" action="{{ url_for('invoice_qb_sync', invoice_id=inv.id) }}">
{{ csrf_field }}
      <button class="btn btn-blue">Sync to QuickBooks</button>
    </form>
    {% endif %}
  {% endif %}
  <form method="post" action="{{ url_for('invoice_action', invoice_id=inv.id) }}" style="display:inline">
{{ csrf_field }}
    <input type="hidden" name="action" value="delete">
    <button class="btn btn-red" onclick="return confirm('Delete this invoice permanently?')">Delete</button>
  </form>
  <a href="{{ url_for('invoices') }}" class="btn">Back</a>
</div>
{% else %}
<div id="print-btn-row" style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap">
  {% if can_print %}<button class="btn" onclick="if(typeof renderInvBarcodes==='function'){renderInvBarcodes();} setTimeout(function(){window.print();},150)">🖨 Print / Save PDF</button>{% endif %}
  <a href="{{ url_for('invoices') }}" class="btn" style="margin-top:0">Back</a>
</div>
{% endif %}
{% if show_barcodes %}
<script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.6/dist/JsBarcode.all.min.js"></script>
<script>
  function renderInvBarcodes() {
    document.querySelectorAll('svg.inv-barcode').forEach(function(el) {
      var upc = (el.getAttribute('data-upc') || '').replace(/-/g,'').replace(/[ \t]/g,'');
      if (!upc || upc === 'None') return;
      try {
        JsBarcode(el, upc, {format: 'CODE128', lineColor:'#000', width:1.5, height:40, displayValue:false, margin:2});
        el.setAttribute('data-rendered','1');
      } catch(e) { console.warn('Barcode render failed for', upc, e); }
    });
  }
  renderInvBarcodes();
  window.addEventListener('beforeprint', renderInvBarcodes);
</script>
{% endif %}
""")

# ---------------------------------------------------------------------------
# Invoice Routes
# ---------------------------------------------------------------------------

@app.route("/invoices")
@vendor_required
def invoices():
    gate = _check_invoice_plan()
    if gate: return gate
    all_inv = _load_invoices()
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    for inv in all_inv:
        inv["vendor_name"] = vmap.get(inv.get("vendor_id", ""), inv.get("vendor_id", ""))
    all_inv.sort(key=lambda x: x.get("id", 0), reverse=True)
    # Check QB connection status
    qb_connected = False
    if session.get("role") == "vendor":
        user = _get_user(session["username"])
        qb_connected = bool(user and user.get("qb_token"))
    elif session.get("role") == "admin":
        users = _load_users()
        qb_connected = any(u.get("role") == "vendor" and u.get("qb_token") for u in users)
    # Resolve vendor plan
    _role = session.get("role", "store")
    if _role == "admin":
        _vendor_plan = "admin"
    else:
        _vid = session.get("vendor_id") or (session.get("vendor_ids") or ["gmf"])[0]
        _vendor_plan = "pro" if _is_internal_vendor(_vid) else ((_get_vendor(_vid) or {}).get("plan", "starter"))
    return _render(_INVOICES, invoices=all_inv, qb_connected=qb_connected, vendor_plan=_vendor_plan)

@app.route("/qb/connect")
@login_required
def qb_connect():
    gate = _check_invoice_plan()
    if gate: return gate
    # Placeholder — will redirect to Intuit OAuth once credentials are configured
    QB_CLIENT_ID = os.environ.get("QB_CLIENT_ID", "")
    QB_REDIRECT_URI = os.environ.get("QB_REDIRECT_URI", "")
    if not QB_CLIENT_ID:
        return _redirect("invoices", "QuickBooks integration not yet configured. Contact your administrator.", cls="err")
    import urllib.parse, secrets
    state = secrets.token_urlsafe(16)
    session["qb_state"] = state
    params = urllib.parse.urlencode({
        "client_id": QB_CLIENT_ID,
        "response_type": "code",
        "scope": "com.intuit.quickbooks.accounting",
        "redirect_uri": QB_REDIRECT_URI,
        "state": state,
    })
    return redirect(f"https://appcenter.intuit.com/connect/oauth2?{params}")

@app.route("/qb/callback")
@login_required
def qb_callback():
    import urllib.parse, base64, urllib.request, json as _json
    error = request.args.get("error")
    if error:
        return _redirect("invoices", f"QuickBooks error: {error}", cls="err")
    state = request.args.get("state", "")
    if state != session.get("qb_state", ""):
        return _redirect("invoices", "QuickBooks state mismatch. Please try again.", cls="err")
    code = request.args.get("code", "")
    realm_id = request.args.get("realmId", "")
    QB_CLIENT_ID = os.environ.get("QB_CLIENT_ID", "")
    QB_CLIENT_SECRET = os.environ.get("QB_CLIENT_SECRET", "")
    QB_REDIRECT_URI = os.environ.get("QB_REDIRECT_URI", "")
    # Exchange code for tokens
    credentials = base64.b64encode(f"{QB_CLIENT_ID}:{QB_CLIENT_SECRET}".encode()).decode()
    token_data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": QB_REDIRECT_URI,
    }).encode()
    req = urllib.request.Request(
        "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        data=token_data,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            token_resp = _json.loads(resp.read())
    except Exception as e:
        return _redirect("invoices", f"QuickBooks token exchange failed: {e}", cls="err")
    # Save tokens to user record
    users = _load_users()
    for u in users:
        if u["username"] == session["username"]:
            u["qb_token"] = token_resp.get("access_token", "")
            u["qb_refresh_token"] = token_resp.get("refresh_token", "")
            u["qb_realm_id"] = realm_id
            break
    _save_users(users)
    return _redirect("invoices", "QuickBooks connected successfully!")

@app.route("/qb/disconnect", methods=["POST"])
@csrf_protect
@vendor_required
def qb_disconnect():
    users = _load_users()
    for u in users:
        if u["username"] == session["username"]:
            u.pop("qb_token", None)
            u.pop("qb_realm_id", None)
            break
    _save_users(users)
    return _redirect("invoices", "QuickBooks disconnected.")

@app.route("/qb/sync_customers", methods=["POST"])
@csrf_protect
@admin_required
def qb_sync_customers():
    """Fetch all QB customers and auto-populate qb_customer_name on store users."""
    import urllib.request as _urlreq, urllib.parse as _urlparse, json as _json, base64 as _b64
    users = _load_users()
    vendor_user = next((u for u in users if u.get("role") == "vendor" and u.get("qb_token")), None)
    if not vendor_user:
        return _redirect("invoices", "No QB-connected vendor found.", cls="err")
    QB_CLIENT_ID = os.environ.get("QB_CLIENT_ID", "")
    QB_CLIENT_SECRET = os.environ.get("QB_CLIENT_SECRET", "")
    base_url = "https://sandbox-quickbooks.api.intuit.com" if os.environ.get("QB_SANDBOX", "0") == "1" else "https://quickbooks.api.intuit.com"
    realm_id = vendor_user.get("qb_realm_id", "")
    token = vendor_user.get("qb_token", "")
    q = _urlparse.urlencode({"query": "SELECT Id, DisplayName FROM Customer MAXRESULTS 1000", "minorversion": "65"})
    req = _urlreq.Request(f"{base_url}/v3/company/{realm_id}/query?{q}",
                          headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with _urlreq.urlopen(req, timeout=15) as resp:
            qb_customers = _json.loads(resp.read().decode()).get("QueryResponse", {}).get("Customer", [])
    except Exception as e:
        return _redirect("invoices", f"QB fetch failed: {e}", cls="err")
    # Build lookup: first word -> list of (DisplayName, Id)
    store_users = [u for u in users if u.get("role") == "store"]
    updated = 0
    for su in store_users:
        store_name = (su.get("store_name") or "").strip()
        if not store_name:
            continue
        name_lower = store_name.lower()
        # Exact match first
        match = next((c for c in qb_customers if c.get("DisplayName", "").lower() == name_lower), None)
        if not match:
            # First-word fallback
            first_word = name_lower.split()[0]
            candidates = [c for c in qb_customers if first_word in c.get("DisplayName", "").lower()]
            match = candidates[0] if candidates else None
        if match:
            su["qb_customer_name"] = match["DisplayName"]
            updated += 1
    _save_users(users)
    return _redirect("invoices", f"QB customer names synced: {updated} store users updated.")

@app.route("/ping")
@login_required
def session_ping():
    """Lightweight session keepalive — resets inactivity timer."""
    from flask import jsonify
    return jsonify({"ok": True})


@app.route("/qb/map_items")
@vendor_required
def qb_map_items():
    """Bulk QB item name mapping — shows Hannaford inventory items with QB item dropdown."""
    gate = _check_invoice_plan()
    if gate: return gate
    import urllib.request as _urlreq, urllib.parse as _urlparse, json as _json, urllib.error as _urlerr
    users = _load_users()
    _role = session.get("role")
    _vids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
    if _role == "admin":
        vendor_user = next((u for u in users if u.get("qb_token")), None)
    else:
        vendor_user = next((u for u in users if u.get("role") == "vendor" and u.get("vendor_id") in _vids and u.get("qb_token")), None)
    if not vendor_user:
        return _redirect("invoices", "QuickBooks is not connected.", cls="err")
    base_url = "https://sandbox-quickbooks.api.intuit.com" if os.environ.get("QB_SANDBOX","0") == "1" else "https://quickbooks.api.intuit.com"
    realm_id = vendor_user.get("qb_realm_id","")

    def _fetch_qb_items():
        q = _urlparse.urlencode({"query": "SELECT Id, Name, UnitPrice FROM Item MAXRESULTS 1000", "minorversion": "65"})
        req = _urlreq.Request(f"{base_url}/v3/company/{realm_id}/query?{q}",
                              headers={"Authorization": f"Bearer {vendor_user['qb_token']}", "Accept": "application/json"})
        try:
            with _urlreq.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
                return sorted(data.get("QueryResponse",{}).get("Item",[]), key=lambda x: x.get("Name","").lower())
        except Exception:
            return []

    qb_items = _fetch_qb_items()
    # Hannaford inventory items = not hidden from hannaford group
    inv_items = sorted(
        [it for it in cli.inventory_list() if "hannaford" not in it.get("hidden_from", [])],
        key=lambda x: (x.get("category","").lower(), x.get("item","").lower())
    )

    _QB_MAP_ITEMS = _page("""
<h1>QB Item Mapping — Hannaford</h1>
<p style="color:#aaa;margin-bottom:1.5rem">Map each Hannaford inventory item to its exact QuickBooks item. This controls which QB item is used when syncing invoices.</p>
<div class="card">
  <div style="margin-bottom:1rem;display:flex;gap:.75rem;flex-wrap:wrap;align-items:center">
    <input id="imap-search" type="text" placeholder="Search inventory items..." oninput="filterRows()"
      style="flex:1;min-width:180px;max-width:360px;padding:.5rem .75rem;border-radius:6px;border:1px solid #2d6a4f;background:#1a2e1a;color:#e0e0e0;font-size:.95rem;outline:none">
    <span style="color:#888;font-size:.85rem">{{ inv_items|length }} items</span>
  </div>
  <form method="post" action="{{ url_for('qb_map_items_save') }}">
  {{ csrf_field }}
  <table id="imap-table" style="width:100%">
    <thead><tr>
      <th style="text-align:left;padding:.5rem .75rem">Inventory Item</th>
      <th style="text-align:left;padding:.5rem .75rem">QB Item</th>
      <th style="text-align:right;padding:.5rem .75rem">QB Price</th>
    </tr></thead>
    <tbody>
    {% for it in inv_items %}
    {% set cur = it.qb_item_name or '' %}
    <tr class="imap-row">
      <td style="padding:.4rem .75rem;font-size:.9rem">{{ it.item }}<br><span style="color:#888;font-size:.75rem">{{ it.category or '' }}</span></td>
      <td style="padding:.4rem .75rem">
        <select name="qb_{{ it.id }}" class="qb-sel" data-cur="{{ it.qb_item_name or '' }}"
          style="width:100%;max-width:320px;padding:.35rem .6rem;border-radius:5px;border:1px solid #2d6a4f;background:#1a2e1a;color:#e0e0e0;font-size:.88rem">
          <option value="">— not mapped —</option>
          {% for qi in qb_items %}
          <option value="{{ qi.Name }}" {% if qi.Name == cur %}selected{% endif %}
            data-price="{{ qi.UnitPrice }}">{{ qi.Name }} (${{ '%.2f'|format(qi.UnitPrice|float) }})</option>
          {% endfor %}
        </select>
      </td>
      <td style="padding:.4rem .75rem;text-align:right;font-size:.88rem;color:#6ee7b7" id="price-{{ it.id }}">
        {% if cur %}
          {% for qi in qb_items %}{% if qi.Name == cur %}${{ '%.2f'|format(qi.UnitPrice|float) }}{% endif %}{% endfor %}
        {% else %}—{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  <div style="margin-top:1.5rem">
    <button class="btn btn-green" type="submit">Save All Mappings</button>
    <a href="{{ url_for('invoices') }}" class="btn btn-blue" style="margin-left:.5rem">Back to Invoices</a>
  </div>
  </form>
</div>
<script>
function filterRows(){
  var q = document.getElementById('imap-search').value.toLowerCase();
  document.querySelectorAll('.imap-row').forEach(function(r){
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

var _imapSaveQueue = {};
function _imapAutoSave(sel, itemId) {
  var val = sel.value;
  var opt = sel.options[sel.selectedIndex];
  // Update price display immediately
  var price = opt.dataset.price ? '$'+parseFloat(opt.dataset.price).toFixed(2) : '—';
  var priceEl = document.getElementById('price-'+itemId);
  if(priceEl) priceEl.textContent = price;
  // Debounce per-item to avoid rapid double-fires
  clearTimeout(_imapSaveQueue[itemId]);
  _imapSaveQueue[itemId] = setTimeout(function(){
    var fd = new FormData();
    fd.append('item_id', itemId);
    fd.append('qb_item_name', val);
    sel.style.borderColor = '#888';
    fetch('/inventory/set_qb_item_name', {method:'POST', body:fd})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d.ok){
          sel.style.borderColor = '#52c97a';
          setTimeout(function(){ sel.style.borderColor = '#2d6a4f'; }, 1500);
        } else {
          sel.style.borderColor = '#e74c3c';
          alert('Auto-save failed for this row: ' + (d.error || 'unknown error'));
        }
      })
      .catch(function(){
        sel.style.borderColor = '#e74c3c';
        alert('Auto-save failed — check your connection.');
      });
  }, 300);
}

document.querySelectorAll('.qb-sel').forEach(function(sel){
  var itemId = sel.name.replace('qb_','');
  sel.setAttribute('data-item-id', itemId);
  sel.addEventListener('change', function(){ _imapAutoSave(this, itemId); });
});

// Session keepalive: ping every 4 min so inactivity timer can't fire mid-mapping
setInterval(function(){
  fetch('/ping').catch(function(){});
}, 240000);
</script>
""")
    return _render(_QB_MAP_ITEMS, inv_items=inv_items, qb_items=qb_items)


@app.route("/qb/map_items/save", methods=["POST"])
@csrf_protect
@vendor_required
def qb_map_items_save():
    """Save bulk QB item name mappings to inventory."""
    gate = _check_invoice_plan()
    if gate: return gate
    import json as _json
    inv_path = os.path.join(DATA_DIR, "inventory.json")
    with open(inv_path) as _f:
        inv = _json.load(_f)
    saved = 0
    for item in inv:
        key = f"qb_{item['id']}"
        val = request.form.get(key)
        if val is not None:
            item["qb_item_name"] = val.strip()
            saved += 1
    with _get_file_lock(inv_path):
        _atomic_write(inv_path, inv)
    return _redirect("qb_map_items", f"Saved QB item mappings for {saved} items.")


@app.route("/qb/match_customers")
@vendor_required
def qb_match_customers():
    """Manual QB customer matching UI."""
    gate = _check_invoice_plan()
    if gate: return gate
    import urllib.request as _urlreq, urllib.parse as _urlparse, json as _json, base64 as _b64, urllib.error as _urlerr
    users = _load_users()
    _role = session.get("role")
    _vids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
    if _role == "admin":
        vendor_user = next((u for u in users if u.get("qb_token")), None)
    else:
        vendor_user = next((u for u in users if u.get("role") == "vendor" and u.get("vendor_id") in _vids and u.get("qb_token")), None)
    if not vendor_user:
        return _redirect("invoices", "QuickBooks is not connected.", cls="err")
    QB_CLIENT_ID = os.environ.get("QB_CLIENT_ID", "")
    QB_CLIENT_SECRET = os.environ.get("QB_CLIENT_SECRET", "")
    base_url = "https://sandbox-quickbooks.api.intuit.com" if os.environ.get("QB_SANDBOX","0") == "1" else "https://quickbooks.api.intuit.com"
    realm_id = vendor_user.get("qb_realm_id","")

    def _refresh_token():
        creds = _b64.b64encode(f"{QB_CLIENT_ID}:{QB_CLIENT_SECRET}".encode()).decode()
        body = _urlparse.urlencode({"grant_type": "refresh_token", "refresh_token": vendor_user.get("qb_refresh_token","")}).encode()
        req = _urlreq.Request("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", data=body,
                              headers={"Authorization": f"Basic {creds}", "Accept": "application/json",
                                       "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        try:
            with _urlreq.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
                new_access = data.get("access_token","")
                new_refresh = data.get("refresh_token", vendor_user.get("qb_refresh_token",""))
                all_users = _load_users()
                for u in all_users:
                    if u.get("username") == vendor_user.get("username"):
                        u["qb_token"] = new_access
                        u["qb_refresh_token"] = new_refresh
                _save_users(all_users)
                vendor_user["qb_token"] = new_access
                vendor_user["qb_refresh_token"] = new_refresh
                return True
        except Exception:
            return False

    def _fetch_customers():
        q = _urlparse.urlencode({"query": "SELECT Id, DisplayName FROM Customer MAXRESULTS 1000", "minorversion": "65"})
        req = _urlreq.Request(f"{base_url}/v3/company/{realm_id}/query?{q}",
                              headers={"Authorization": f"Bearer {vendor_user['qb_token']}", "Accept": "application/json"})
        with _urlreq.urlopen(req, timeout=15) as resp:
            return _json.loads(resp.read().decode()).get("QueryResponse",{}).get("Customer",[])

    try:
        qb_customers = _fetch_customers()
    except _urlerr.HTTPError as e:
        if e.code == 401:
            if not _refresh_token():
                return _redirect("invoices", "QB token expired and refresh failed. Please reconnect QuickBooks.", cls="err")
            try:
                qb_customers = _fetch_customers()
            except Exception as e2:
                return _redirect("invoices", f"QB fetch failed after refresh: {e2}", cls="err")
        else:
            return _redirect("invoices", f"QB fetch failed: {e}", cls="err")
    except Exception as e:
        return _redirect("invoices", f"QB fetch failed: {e}", cls="err")

    qb_customers = sorted(qb_customers, key=lambda c: c.get("DisplayName","").lower())
    if _role == "admin":
        store_users = sorted(
            [u for u in users if u.get("role") == "store" and u.get("store_name")],
            key=lambda u: u.get("store_name","").lower()
        )
    else:
        store_users = sorted(
            [u for u in users if u.get("role") == "store" and u.get("store_name") and u.get("vendor_id") in _vids],
            key=lambda u: u.get("store_name","").lower()
        )
    return _render(_QB_MATCH, store_users=store_users, qb_customers=qb_customers)

@app.route("/qb/match_customers/save", methods=["POST"])
@csrf_protect
@vendor_required
def qb_match_customers_save():
    """Save confirmed QB customer name mappings."""
    gate = _check_invoice_plan()
    if gate: return gate
    users = _load_users()
    _role = session.get("role")
    _vids = session.get("vendor_ids", [session.get("vendor_id", "gmf")])
    saved = 0
    for u in users:
        if u.get("role") != "store": continue
        # Vendors can only update their own stores
        if _role != "admin" and u.get("vendor_id") not in _vids:
            continue
        key = f"qb_{u['username']}"
        val = request.form.get(key, "").strip()
        if val == "__clear__":
            u["qb_customer_name"] = ""
            saved += 1
        elif val:
            u["qb_customer_name"] = val
            saved += 1
    _save_users(users)
    return _redirect("invoices", f"Saved QB mappings for {saved} stores.")

@app.route("/invoices/from_orders", methods=["POST"])
@csrf_protect
@vendor_required
def invoices_from_orders():
    gate = _check_invoice_plan()
    if gate: return gate
    """Create an invoice directly from a vendor's order group (store + delivery date)."""
    from datetime import date, timedelta
    store_name = request.form.get("store", "").strip()
    delivery_date = request.form.get("date", "").strip()
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])

    # Pull all orders for this store + delivery date + vendor
    all_orders = cli.orders_list()
    group = [o for o in all_orders
             if o.get("store_name") == store_name
             and o.get("delivery_date") == delivery_date
             and o.get("vendor_id") == vendor_id]

    if not group:
        return _redirect("orders", f"No orders found for {store_name} on {delivery_date}.", cls="err")

    # Build line items from orders — include UPC for Hannaford stores
    line_items = []
    for o in group:
        upc = str(o.get("upc", "") or "").strip().replace("-", "").replace(" ", "")
        barcode_b64 = None
        if upc and upc != "None":
            barcode_b64 = _upc_to_barcode_b64(upc)
        li = {
            "item": o.get("item", ""),
            "qty": _disp_qty(o.get("qty", 1), o.get("case_size", "")),
            "unit_price": 0.0,
            "total": 0.0,
            "upc": upc,
            "qb_item_name": o.get("qb_item_name", "")
        }
        if barcode_b64:
            li["barcode_b64"] = barcode_b64
        line_items.append(li)

    # Resolve store user for store_number
    users = _load_users()
    store_user = next((u for u in users if u.get("store_name") == store_name), {})

    # Due date: delivery + 30 days
    try:
        due = str(date.fromisoformat(delivery_date) + timedelta(days=30))
    except Exception:
        due = ""

    inv = {
        "id": _next_invoice_id(),
        "vendor_id": vendor_id,
        "store_name": store_name,
        "store_number": store_user.get("store_number", ""),
        "delivery_date": delivery_date,
        "due_date": due,
        "created_date": str(date.today()),
        "line_items": line_items,
        "total": 0.0,
        "status": "unpaid",
        "notes": "",
        "paid_date": ""
    }
    all_inv = _load_invoices()
    all_inv.append(inv)
    _save_invoices(all_inv)
    return redirect(url_for("invoice_view", invoice_id=inv["id"]))


@app.route("/invoices/create", methods=["GET", "POST"])
@csrf_protect
@vendor_required
def invoices_create():
    gate = _check_invoice_plan()
    if gate: return gate
    vendors = _load_vendors()
    users = _load_users()
    selected_vendor_id = request.form.get("vendor_id") or request.args.get("vendor") or (vendors[0]["id"] if vendors else "gmf")
    stores = [u for u in users if u.get("role", "store") == "store" and selected_vendor_id in u.get("vendor_ids", ["gmf"])]

    if request.method == "POST" and request.form.get("_action") == "save":
        items = request.form.getlist("item[]")
        qtys = request.form.getlist("qty[]")
        prices = request.form.getlist("price[]")
        line_items = []
        total = 0.0
        for item, qty, price in zip(items, qtys, prices):
            if item.strip():
                q = int(qty or 0)
                p = float(price or 0)
                t = round(q * p, 2)
                total += t
                line_items.append({"item": item.strip(), "qty": q, "unit_price": p, "total": t})
        store_username = request.form.get("store_username", "")
        store_user = next((u for u in users if u["username"] == store_username), {})
        from datetime import date
        inv = {
            "id": _next_invoice_id(),
            "vendor_id": selected_vendor_id,
            "store_name": store_user.get("store_name", store_username),
            "store_number": store_user.get("store_number", ""),
            "delivery_date": request.form.get("delivery_date", ""),
            "due_date": request.form.get("due_date", ""),
            "created_date": str(date.today()),
            "line_items": line_items,
            "total": round(total, 2),
            "status": "unpaid",
            "notes": request.form.get("notes", ""),
            "paid_date": ""
        }
        all_inv = _load_invoices()
        all_inv.append(inv)
        _save_invoices(all_inv)
        send_to = request.form.get("send_email", "").strip()
        if send_to:
            vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
            _send_invoice_email(send_to, inv, vmap.get(selected_vendor_id, selected_vendor_id))
        return redirect(url_for("invoice_view", invoice_id=inv["id"]))

    return _render(_INVOICE_CREATE, vendors=vendors, stores=stores, selected_vendor_id=selected_vendor_id,
                   prefill_store=request.args.get('store', ''),
                   prefill_date=request.args.get('date', ''))

@app.route("/invoices/<int:invoice_id>/print_fragment")
@vendor_required
def invoice_print_fragment(invoice_id):
    """Return bare invoice HTML fragment for batch printing."""
    gate = _check_invoice_plan()
    if gate: return ("Access denied.", 403)
    all_inv = _load_invoices()
    inv = next((i for i in all_inv if i["id"] == invoice_id), None)
    if not inv: return ("Not found.", 404)
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        if inv.get("vendor_id") not in vendor_ids:
            return ("Access denied.", 403)
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    pmap = {v["id"]: v.get("plan", "starter") for v in vendors}
    inv["vendor_name"] = vmap.get(inv.get("vendor_id", ""), inv.get("vendor_id", ""))
    vendor_plan = pmap.get(inv.get("vendor_id", ""), "starter")
    if inv.get("vendor_id") == "gmf":
        vendor_plan = "pro"
    show_barcodes = (session.get("role") == "admin" or vendor_plan == "pro")
    from flask import render_template_string
    frag = render_template_string("""
<h2>Invoice #{{ inv.id }} &mdash; {{ inv.store_name }}</h2>
<p style="margin:.2rem 0"><strong>Vendor:</strong> {{ inv.vendor_name }} &nbsp;|&nbsp;
<strong>Delivery:</strong> {{ inv.delivery_date }} &nbsp;|&nbsp;
<strong>Due:</strong> {{ inv.due_date }} &nbsp;|&nbsp;
<strong>Status:</strong> {{ inv.status }}</p>
<table>
  <tr><th>#</th><th>Item</th><th>Qty</th><th>Unit Price</th><th>Total</th></tr>
  {% for li in inv.line_items %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ li.item }}</td>
    <td>{{ li.qty }}</td>
    <td>${{ '%.2f'|format(li.unit_price|float) }}</td>
    <td>${{ '%.2f'|format((li.qty|float)*(li.unit_price|float)) }}</td>
  </tr>
  {% endfor %}
  <tr><td colspan="4" style="text-align:right"><strong>Total</strong></td><td><strong>${{ '%.2f'|format(inv.total|float) }}</strong></td></tr>
</table>
{% if inv.notes %}<p><strong>Notes:</strong> {{ inv.notes }}</p>{% endif %}
""", inv=inv, show_barcodes=show_barcodes)
    return frag

@app.route("/invoices/<int:invoice_id>")
@vendor_required
def invoice_view(invoice_id):
    gate = _check_invoice_plan()
    if gate: return gate
    all_inv = _load_invoices()
    inv = next((i for i in all_inv if i["id"] == invoice_id), None)
    if not inv:
        return _redirect("invoices", "Invoice not found.", cls="err")
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        if inv.get("vendor_id") not in vendor_ids:
            return _redirect("invoices", "Access denied.", cls="err")
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    pmap = {v["id"]: v.get("plan", "starter") for v in vendors}
    inv["vendor_name"] = vmap.get(inv.get("vendor_id", ""), inv.get("vendor_id", ""))
    vendor_plan = pmap.get(inv.get("vendor_id", ""), "starter")
    if inv.get("vendor_id") == "gmf":
        vendor_plan = "pro"
    can_print = session.get("role") == "admin" or vendor_plan in ("standard", "pro", "seasonal")
    show_barcodes = (session.get("role") == "admin" or vendor_plan == "pro")
    # QB connection check — admin or vendor sees sync button if vendor is connected
    qb_connected = False
    users = _load_users()
    vendor_user = next((u for u in users if u.get("role") == "vendor"
                        and inv.get("vendor_id") in u.get("vendor_ids", [u.get("vendor_id", "")])
                        and u.get("qb_token")), None)
    if session.get("role") in ("admin", "vendor"):
        qb_connected = bool(vendor_user)
    return _render(_INVOICE_VIEW, inv=inv, can_print=can_print, qb_connected=qb_connected, show_barcodes=show_barcodes)

@app.route("/invoices/<int:invoice_id>/action", methods=["POST"])
@csrf_protect
@vendor_required
def invoice_action(invoice_id):
    gate = _check_invoice_plan()
    if gate: return gate
    from datetime import date
    all_inv = _load_invoices()
    action = request.form.get("action")
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        inv_check = next((i for i in all_inv if i["id"] == invoice_id), None)
        if not inv_check or inv_check.get("vendor_id") not in vendor_ids:
            return _redirect("invoices", "Access denied.", cls="err")
    for inv in all_inv:
        if inv["id"] == invoice_id:
            if action == "paid":
                inv["status"] = "paid"
                inv["paid_date"] = str(date.today())
            elif action == "unpaid":
                inv["status"] = "unpaid"
                inv["paid_date"] = ""
            elif action == "void":
                inv["status"] = "void"
            elif action == "delete":
                all_inv = [i for i in all_inv if i["id"] != invoice_id]
                _save_invoices(all_inv)
                return _redirect("invoices", f"Invoice #{invoice_id} deleted.")
            break
    _save_invoices(all_inv)
    return redirect(url_for("invoice_view", invoice_id=invoice_id))

@app.route("/invoices/<int:invoice_id>/email", methods=["POST"])
@csrf_protect
@vendor_required
def invoice_email(invoice_id):
    gate = _check_invoice_plan()
    if gate: return gate
    all_inv = _load_invoices()
    inv = next((i for i in all_inv if i["id"] == invoice_id), None)
    if not inv:
        return _redirect("invoices", "Invoice not found.", cls="err")
    # Ownership check — vendors may only email their own invoices
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        if inv.get("vendor_id") not in vendor_ids:
            return _redirect("invoices", "Access denied.", cls="err")
    vendors = _load_vendors()
    vmap = {v["id"]: v.get("name", v.get("id", "")) for v in vendors}
    to_email = request.form.get("to_email", "").strip()
    if to_email:
        _send_invoice_email(to_email, inv, vmap.get(inv.get("vendor_id", ""), ""))
    return redirect(url_for("invoice_view", invoice_id=invoice_id))

@app.route("/invoices/<int:invoice_id>/qb_sync", methods=["POST"])
@csrf_protect
@vendor_required
def invoice_qb_sync(invoice_id):
    gate = _check_invoice_plan()
    if gate: return gate
    all_inv = _load_invoices()
    inv = next((i for i in all_inv if i["id"] == invoice_id), None)
    if not inv:
        return _redirect("invoices", "Invoice not found.", cls="err")
    # Ownership check — vendors may only sync their own invoices
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [session.get("vendor_id", "")])
        if inv.get("vendor_id") not in vendor_ids:
            return _redirect("invoices", "Access denied.", cls="err")
    users = _load_users()
    vendor_user = next((u for u in users if u.get("role") == "vendor"
                        and inv.get("vendor_id") in u.get("vendor_ids", [u.get("vendor_id", "")])
                        and u.get("qb_token")), None)
    if not vendor_user:
        return _redirect("invoices", "QuickBooks not connected for this vendor.", cls="err")
    ok, qb_result = _qb_push_invoice(inv, vendor_user)
    if ok:
        qb_id, qb_doc, qb_total, qb_lines = qb_result
        for i in all_inv:
            if i["id"] == invoice_id:
                i["qb_invoice_id"] = qb_id
                i["qb_doc_number"] = qb_doc
                if qb_total:
                    i["total"] = qb_total
                # Render barcode PNGs for any line items that have a UPC
                for li in i.get("line_items", []):
                    if li.get("upc") and li["upc"] != "None" and not li.get("barcode_b64"):
                        b64 = _upc_to_barcode_b64(li["upc"])
                        if b64:
                            li["barcode_b64"] = b64
        _save_invoices(all_inv)
        return _redirect("invoice_view", f"Synced to QuickBooks (Invoice #{qb_doc}).", invoice_id=invoice_id)
    qb_id, err = qb_result
    return _redirect("invoices", f"QB sync failed: {err}", cls="err")


# ---------------------------------------------------------------------------
# Vendor Users
# ---------------------------------------------------------------------------

_VENDOR_USERS = _page("""
<h1>Store Users</h1>

{% if request.args.get('edit_user') %}
<div class="card" style="border-color:#a855f7">
  <h2 style="color:#a855f7">Edit: {{ request.args.get('edit_user') }}</h2>
  <form method="post" action="{{ url_for('vendor_users_edit') }}">
{{ csrf_field }}
    <input type="hidden" name="username" value="{{ request.args.get('edit_user') }}">
    <div class="form-row">
      <div class="field"><label>Store / Customer Name</label><input name="store" type="text" value="{{ edit_store or '' }}" required></div>
      <div class="field"><label>QB Customer Name</label><input name="qb_customer_name" type="text" value="{{ edit_qb_name or '' }}" placeholder="Exact name in QuickBooks"></div>
      <div class="field"><label>Store Number</label><input name="store_number" type="text" value="{{ edit_store_number or '' }}" placeholder="optional"></div>
      <div class="field" style="display:flex;gap:.5rem;align-self:flex-end">
        <button class="btn btn-green" type="submit">Save</button>
        <a href="{{ url_for('vendor_users') }}" class="btn btn-blue">Cancel</a>
      </div>
    </div>
  </form>
</div>
{% endif %}

<div class="card">
  <h2>Change Password</h2>
  <form method="post" action="{{ url_for('vendor_users_password') }}">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Username</label><input name="username" type="text" required></div>
      <div class="field"><label>New Password</label><input name="password" type="password" required></div>
      <button class="btn btn-blue" type="submit" style="align-self:flex-end">Update</button>
    </div>
  </form>
</div>

<div class="card">
  <h2>Add Store Account</h2>
  <form method="post" action="{{ url_for('vendor_users_add') }}">
{{ csrf_field }}
    <div class="form-row">
      <div class="field"><label>Store / Customer Name</label><input name="store" type="text" required></div>
      <div class="field"><label>QB Customer Name</label><input name="qb_customer_name" type="text" placeholder="Exact name in QuickBooks"></div>
      <div class="field"><label>Username</label><input name="username" type="text" required></div>
      <div class="field"><label>Password</label><input name="password" type="password" required></div>
      <button class="btn btn-green" type="submit" style="align-self:flex-end">Add Store</button>
    </div>
  </form>
</div>

<div class="card">
  <h2>Store Accounts ({{ user_list|length }})</h2>
  <div style="margin-bottom:1rem">
    <input id="vuser-search" type="text" placeholder="Search store, username, store #..." oninput="filterVendorUsers()"
      style="width:100%;max-width:420px;padding:.5rem .75rem;border-radius:6px;border:1px solid #2d6a4f;background:#1a2e1a;color:#e0e0e0;font-size:.95rem;outline:none">
  </div>
  {% if user_list %}
  <table id="vuser-table">
    <tr><th>Store / Customer Name</th><th class="hide-mobile">QB Customer Name</th><th>Username</th><th class="hide-mobile">Store #</th><th>Orders</th><th class="hide-mobile">Last Order</th><th></th></tr>
    {% for u in user_list %}
    <tr>
      <td>{{ u.store_name }}</td>
      <td class="hide-mobile" style="color:#a78bfa;font-size:.85rem">{{ u.qb_customer_name or '—' }}</td>
      <td style="font-family:monospace;font-size:.85rem">{{ u.username }}</td>
      <td class="hide-mobile" style="color:#aaa;font-size:.85rem">{{ u.store_number or '—' }}</td>
      <td style="text-align:center;font-size:.85rem">{% if u.order_count %}<span style="background:#1a3a1a;color:#6ee7b7;border-radius:12px;padding:.15rem .55rem;font-weight:600">{{ u.order_count }}</span>{% else %}<span style="color:#555">0</span>{% endif %}</td>
      <td class="hide-mobile" style="font-size:.82rem;color:{% if u.last_order %}#86efac{% else %}#555{% endif %}">{{ u.last_order or 'Never' }}</td>
      <td style="display:flex;gap:.4rem;flex-wrap:wrap">
        <a href="{{ url_for('vendor_users', edit_user=u.username) }}" class="btn btn-blue" style="font-size:.8rem;padding:.3rem .7rem">Edit</a>
        <form method="post" action="{{ url_for('vendor_users_remove') }}" style="display:inline">
{{ csrf_field }}
          <input type="hidden" name="username" value="{{ u.username }}">
          <button class="btn btn-red" style="font-size:.8rem;padding:.3rem .7rem" onclick="return confirm('Remove {{ u.username }}?')">Remove</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No store accounts yet.</p>{% endif %}
</div>
<script>
function filterVendorUsers() {
  var q = document.getElementById('vuser-search').value.toLowerCase();
  var rows = document.querySelectorAll('#vuser-table tbody tr');
  rows.forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
""")


# Vendor Settings
# ---------------------------------------------------------------------------

_VENDOR_MAP = _page("""
<style>
#vendor-map{width:100%;height:520px;border-radius:12px;border:1px solid rgba(139,92,246,0.3)}
.map-date-nav{display:flex;align-items:center;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap}
.map-date-label{font-size:1.1rem;font-weight:600;color:#e2e8f0;min-width:110px;text-align:center}
.map-nav-btn{background:#2a2a2a;border:1px solid rgba(255,255,255,0.15);color:#e0e0e0;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:1rem;line-height:1}
.map-nav-btn:disabled{opacity:.35;cursor:default}
.map-legend{display:flex;gap:1rem;flex-wrap:wrap;margin-top:.75rem;font-size:.85rem;color:#aaa}
.map-legend span{display:flex;align-items:center;gap:.4rem}
.map-legend i{display:inline-block;width:12px;height:12px;border-radius:50%}
.rnum{background:#7c3aed;color:#fff;font-weight:700;font-size:.78rem;border-radius:50%;width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.rnum.bid{background:#0ea5e9}.rnum.go{background:#52c97a}.rstop{display:flex;align-items:flex-start;gap:.75rem;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:.88rem;color:#ccc}.rstop:last-child{border-bottom:none}.rtab{background:#2a2a2a;border:1px solid rgba(255,255,255,0.12);color:#aaa;border-radius:6px;padding:.3rem .8rem;cursor:pointer;font-size:.85rem}.rtab.on{background:#7c3aed;border-color:#7c3aed;color:#fff}.rtab.on.bid{background:#0ea5e9;border-color:#0ea5e9}
</style>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<div class="card">
  <h2 style="margin:0 0 1rem;font-size:1.2rem;color:#e2e8f0">&#128506; Delivery Map</h2>
  <div class="map-date-nav">
    <button class="map-nav-btn" id="map-prev" onclick="mapStepDate(-1)">&#9664;</button>
    <span class="map-date-label" id="map-date-label"></span>
    <button class="map-nav-btn" id="map-next" onclick="mapStepDate(1)">&#9654;</button>
    <span style="color:#888;font-size:.85rem;margin-left:.5rem" id="map-order-count"></span>
  </div>
  <div id="vendor-map"></div>
  <div class="map-legend">
    <span><i style="background:#7c3aed"></i> Brewer area</span>
    <span><i style="background:#0ea5e9"></i> Biddeford area</span>
    <span><i style="background:#52c97a"></i> Other / Warehouse</span>
  </div>
</div>
<div class="card" id="route-card" style="margin-top:1.25rem">
  <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;flex-wrap:wrap">
    <h2 style="margin:0;font-size:1.1rem;color:#e2e8f0">&#128736; Optimized Routes</h2>
    <button id="print-route-btn" style="background:#2a2a2a;border:1px solid rgba(255,255,255,0.12);color:#ccc;border-radius:6px;padding:.35rem .9rem;cursor:pointer;font-size:.85rem;margin-left:auto" onclick="window.print()">&#128438; Print Routes</button>
  </div>
  <div id="route-tabs" style="display:flex;gap:.5rem;margin-bottom:.75rem;flex-wrap:wrap"></div>
  <div id="route-list"></div>
</div>
<script>
var MAP_DATES = {{ allowed_dates | tojson }};
var MAP_ORDERS = {{ map_orders | tojson }};
var MAP_TODAY  = {{ today | tojson }};

var STORE_COORDS = {
  "Ellsworth Hannaford":   [44.5321,-68.4110],
  "Bar Harbor Hannaford":  [44.3884,-68.2107],
  "Blue Hill Hannaford":   [44.4065,-68.5975],
  "Bucksport Hannaford":   [44.5737,-68.7988],
  "Brewer Hannaford":      [44.7832,-68.7542],
  "Hampden Hannaford":     [44.7438,-68.8452],
  "Hogan Road Hannaford":  [44.8346,-68.7478],
  "Airport Mall Hannaford":[44.8189,-68.8123],
  "Broadway Hannaford":    [44.8250,-68.7777],
  "Old Town Hannaford":    [44.9285,-68.6642],
  "Lincoln Hannaford":     [45.3628,-68.5163],
  "Biddeford Hannaford":       [43.4881,-70.4656],
  "Saco Hannaford":            [43.5116,-70.4354],
  "Scarborough Hannaford":     [43.5950,-70.3314],
  "Mill Creek Hannaford":      [43.6335,-70.2864],
  "Maine Mall Hannaford":      [43.6230,-70.3130],
  "Forest Ave Hannaford":      [43.6644,-70.2878],
  "Riverside Hannaford":       [43.7018,-70.3195],
  "Falmouth Hannaford":        [43.7344,-70.2942],
  "Westbrook Hannaford":       [43.6760,-70.3551],
  "Sanford Hannaford":         [43.4578,-70.7731],
  "Danforth's Market":     [44.8049,-68.9028],
  "Paradis":               [44.7994,-68.7539],
  "Edward Brothers":       [44.4583,-68.9262],
  "GM Family Market":      [44.7528,-68.6789],
  "Lincoln Steaks":        [45.3628,-68.5163],
  "Friends & Family":      [44.5597,-68.4371],
  "Hilton Garden Inn":     [44.8351,-68.7373],
  "Chase's Restaurant":    [44.7948,-68.8398],
  "Mason's Brewing":       [44.7921,-68.7693],
  "Marsh Island":          [44.7436,-68.8370],
  "Paddy Murphy's":        [44.8009,-68.7713],
  "Dennis Food Service":   [44.7784,-68.8003],
  "Becky's Diner":         [43.6506,-70.2569],
  "Scratch Bakery":        [43.6395,-70.2307],
  "Two Fat Cats":          [43.6602,-70.2624],
  "Rosemont Bakery":       [43.6870,-70.2940],
  "Valerie's Diner":       [43.4760,-70.4961],
  "Robin's Confections":   [43.4758,-70.5135],
  "Pier Fries":            [43.5160,-70.3743],
  "Joseph's By The Sea":   [43.5117,-70.3770],
  "Ramuno's":              [43.5148,-70.3745],
  "Beach Lobster":         [43.5151,-70.3797],
  "Native Maine":          [43.6626,-70.3675]
};

var BREWER_SET = new Set([
  "Ellsworth Hannaford","Bar Harbor Hannaford","Blue Hill Hannaford",
  "Bucksport Hannaford","Brewer Hannaford","Hampden Hannaford",
  "Hogan Road Hannaford","Airport Mall Hannaford","Broadway Hannaford",
  "Old Town Hannaford","Lincoln Hannaford",
  "Danforth's Market","Paradis","Edward Brothers","GM Family Market",
  "Lincoln Steaks","Friends & Family","Hilton Garden Inn",
  "Chase's Restaurant","Mason's Brewing","Marsh Island",
  "Paddy Murphy's","Dennis Food Service"
]);
var BIDDEFORD_SET = new Set([
  "Biddeford Hannaford","Saco Hannaford","Scarborough Hannaford",
  "Mill Creek Hannaford","Maine Mall Hannaford","Forest Ave Hannaford",
  "Riverside Hannaford","Falmouth Hannaford","Westbrook Hannaford","Sanford Hannaford",
  "Becky's Diner","Scratch Bakery","Two Fat Cats","Rosemont Bakery",
  "Valerie's Diner","Robin's Confections","Pier Fries","Joseph's By The Sea",
  "Ramuno's","Beach Lobster","Native Maine"
]);

var _map = null;
var _markers = [];
var _mapDateIdx = 0;

function _circleIcon(color){
  return L.divIcon({
    className:'',
    html:'<div style="width:18px;height:18px;border-radius:50%;background:'+color+';border:2.5px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,0.55)"></div>',
    iconSize:[18,18],iconAnchor:[9,9],popupAnchor:[0,-12]
  });
}

function _renderDate(d){
  _markers.forEach(function(m){_map.removeLayer(m);}); _markers=[];
  var orders = MAP_ORDERS[d] || {};
  var stores = Object.keys(orders);
  document.getElementById('map-order-count').textContent =
    stores.length ? stores.length+' store'+(stores.length!==1?'s':'')+' ordered' : 'No orders this day';
  var bounds=[];
  stores.forEach(function(sn){
    var snClean = sn.replace(/\s*\(\d+\)\s*$/, '').trim();
    var c=STORE_COORDS[snClean]; if(!c) return;
    var color=BREWER_SET.has(snClean)?'#7c3aed':BIDDEFORD_SET.has(snClean)?'#0ea5e9':'#52c97a';
    var html='<strong>'+sn+'</strong><br><span style="color:#888;font-size:.8rem">'+d+'</span><br><div style="margin-top:.4rem;max-height:150px;overflow-y:auto">';
    (orders[sn]||[]).forEach(function(it){html+='<div style="font-size:.83rem">&bull; '+it.item+' &times; '+it.qty+'</div>';});
    html+='</div>';
    var mk=L.marker(c,{icon:_circleIcon(color)}).bindPopup(html,{maxWidth:230}).addTo(_map);
    _markers.push(mk); bounds.push(c);
  });
  if(bounds.length) _map.fitBounds(bounds,{padding:[50,50],maxZoom:11});
  else _map.setView([44.5,-69.0],7);
}

function mapStepDate(dir){
  var n=_mapDateIdx+dir;
  if(n<0||n>=MAP_DATES.length) return;
  _mapDateIdx=n;
  var d=MAP_DATES[n];
  document.getElementById('map-date-label').textContent=d;
  document.getElementById('map-prev').disabled=n===0;
  document.getElementById('map-next').disabled=n===MAP_DATES.length-1;
  _renderDate(d);
}

document.addEventListener('DOMContentLoaded',function(){
  _map=L.map('vendor-map').setView([44.5,-69.0],7);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
    attribution:'&copy; OpenStreetMap contributors',maxZoom:18
  }).addTo(_map);
  var idx=MAP_DATES.indexOf(MAP_TODAY);
  if(idx<0) idx=MAP_DATES.length>0?0:-1;
  if(idx>=0){
    _mapDateIdx=idx;
    document.getElementById('map-date-label').textContent=MAP_DATES[idx];
    document.getElementById('map-prev').disabled=idx===0;
    document.getElementById('map-next').disabled=idx===MAP_DATES.length-1;
    _renderDate(MAP_DATES[idx]);
  } else {
    document.getElementById('map-date-label').textContent='No dates';
    document.getElementById('map-prev').disabled=true;
    document.getElementById('map-next').disabled=true;
  }
});
</script>
<script>
// Route panel — uses same BREWER_SET/BIDDEFORD_SET as map pins
var _RT_START = {
  brewer:    {name: '88 Stevens Rd, Brewer ME',    c: [44.7884, -68.7401]},
  biddeford: {name: '415 Hill St, Biddeford ME',  c: [43.4930, -70.4640]}
};
var _rt_tab = 'brewer';
var _rt_lines = [];

function _rt_hav(a, b) {
  var R=6371, p=Math.PI/180;
  var dl=(b[0]-a[0])*p, dn=(b[1]-a[1])*p;
  var x=Math.sin(dl/2)*Math.sin(dl/2)+Math.cos(a[0]*p)*Math.cos(b[0]*p)*Math.sin(dn/2)*Math.sin(dn/2);
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
}
function _rt_nn(origin, stops) {
  var rem=stops.slice(), out=[], cur=origin;
  while(rem.length){
    var bi=0, bd=1e9;
    for(var i=0;i<rem.length;i++){var d=_rt_hav(cur,rem[i].co);if(d<bd){bd=d;bi=i;}}
    out.push(rem[bi]); cur=rem[bi].co; rem.splice(bi,1);
  }
  return out;
}

function _rt_buildRoute(key, orders) {
  // Use same sets as working map pins
  var SET = (key==='brewer') ? BREWER_SET : BIDDEFORD_SET;
  var rs  = _RT_START[key];
  var stops = [];
  Object.keys(orders).forEach(function(sn) {
    var sc = sn.replace(/\s*\(\d+\)\s*$/, '').trim();
    if (SET.has(sc) && STORE_COORDS[sc]) {
      stops.push({n: sn, sc: sc, co: STORE_COORDS[sc], items: orders[sn]});
    }
  });
  return {route: _rt_nn(rs.c, stops), rs: rs};
}

function _rt_renderList(key, orders) {
  var el = document.getElementById('route-list');
  if (!el) return;
  var res = _rt_buildRoute(key, orders);
  var route = res.route, rs = res.rs;
  var brew = (key === 'brewer');
  if (!route.length) {
    el.innerHTML = '<p style="color:#888;font-size:.88rem">No stops for this date.</p>';
    return;
  }
  var h = '<div style="font-size:.82rem;color:#888;margin-bottom:.6rem">' + route.length +
    ' stop' + (route.length!==1?'s':'') + ' — optimized from ' + rs.name + '</div>';
  h += '<div class="rstop"><span class="rnum go">S</span><div><strong>' + rs.name +
    '</strong> <small style="color:#888">(start)</small></div></div>';
  route.forEach(function(s, i) {
    h += '<div class="rstop"><span class="rnum' + (brew ? '' : ' bid') + '">' + (i+1) + '</span>' +
         '<div><strong>' + s.n + '</strong>';
    if (s.items && s.items.length) {
      h += '<div style="color:#888;font-size:.8rem;margin-top:2px">';
      s.items.forEach(function(it){ h += it.item + ' &times; ' + it.qty + '; '; });
      h += '</div>';
    }
    h += '</div></div>';
  });
  el.innerHTML = h;
}

function _rt_renderMap(key, orders) {
  // Clear previous route lines and markers
  _rt_lines.forEach(function(l){try{_map.removeLayer(l);}catch(e){}});
  _rt_lines = [];
  _markers.forEach(function(m){try{_map.removeLayer(m);}catch(e){}});
  _markers = [];
  var res = _rt_buildRoute(key, orders);
  var route = res.route, rs = res.rs;
  var brew = (key === 'brewer');
  var col  = brew ? '#7c3aed' : '#0ea5e9';
  if (!route.length) return;
  // Start marker
  var startIcon = L.divIcon({className:'',html:'<div style="background:#52c97a;border:2.5px solid #fff;border-radius:5px;padding:2px 6px;font-size:10px;font-weight:700;color:#fff;white-space:nowrap">Start</div>',iconSize:[44,18],iconAnchor:[22,9],popupAnchor:[0,-12]});
  _markers.push(L.marker(rs.c, {icon:startIcon}).bindPopup('<strong>'+rs.name+'</strong>').addTo(_map));
  // Polyline
  var lc = [rs.c];
  route.forEach(function(s){ lc.push(s.co); });
  _rt_lines.push(L.polyline(lc, {color:col,weight:2.5,opacity:.5,dashArray:'6,5'}).addTo(_map));
  // Numbered markers
  var bounds = [rs.c];
  route.forEach(function(s, i) {
    var icon = L.divIcon({className:'',html:'<div style="width:26px;height:26px;border-radius:50%;background:'+col+';border:2.5px solid #fff;box-shadow:0 1px 5px rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:11px;color:#fff">'+(i+1)+'</div>',iconSize:[26,26],iconAnchor:[13,13],popupAnchor:[0,-14]});
    var ph = '<strong>'+(i+1)+'. '+s.n+'</strong><div style="margin-top:.35rem;max-height:120px;overflow-y:auto">';
    (s.items||[]).forEach(function(it){ ph += '<div style="font-size:.82rem">&bull; '+it.item+' &times; '+it.qty+'</div>'; });
    ph += '</div>';
    _markers.push(L.marker(s.co, {icon:icon}).bindPopup(ph, {maxWidth:230}).addTo(_map));
    bounds.push(s.co);
  });
  if (bounds.length > 1) _map.fitBounds(bounds, {padding:[50,50],maxZoom:11});
}

function _rt_tabs(d) {
  var orders = MAP_ORDERS[d] || {};
  var bs=0, bis=0;
  Object.keys(orders).forEach(function(sn) {
    var sc = sn.replace(/\s*\(\d+\)\s*$/, '').trim();
    if (BREWER_SET.has(sc) && STORE_COORDS[sc]) bs++;
    else if (BIDDEFORD_SET.has(sc) && STORE_COORDS[sc]) bis++;
  });
  var te = document.getElementById('route-tabs');
  var el = document.getElementById('route-list');
  if (!bs && !bis) {
    if (te) te.innerHTML = '';
    if (el) el.innerHTML = '<p style="color:#888;font-size:.88rem">No orders for this date.</p>';
    _rt_lines.forEach(function(l){try{_map.removeLayer(l);}catch(e){}});
    _rt_lines = [];
    return;
  }
  var tabs = [];
  if (bs)  tabs.push({k:'brewer',    l:'Brewer ('    +bs +' stops)', bid:false});
  if (bis) tabs.push({k:'biddeford', l:'Biddeford ('+bis+' stops)', bid:true});
  if (!tabs.find(function(t){return t.k===_rt_tab;})) _rt_tab = tabs[0].k;
  if (te) te.innerHTML = tabs.map(function(t) {
    var on = (t.k===_rt_tab) ? (' on' + (t.bid?' bid':'')) : '';
    return '<button class="rtab'+on+'" onclick="window._rt_click(&#39;'+t.k+'&#39;,this)">'+t.l+'</button>';
  }).join('');
  _rt_renderList(_rt_tab, orders);
  try { _rt_renderMap(_rt_tab, orders); } catch(e) { console.warn('map render error:', e); }
}

window._rt_click = function(key, btn) {
  _rt_tab = key;
  document.querySelectorAll('.rtab').forEach(function(b){ b.className='rtab'; });
  btn.className = 'rtab on' + (key==='biddeford' ? ' bid' : '');
  var orders = MAP_ORDERS[MAP_DATES[_mapDateIdx]] || {};
  _rt_renderList(key, orders);
  try { _rt_renderMap(key, orders); } catch(e) { console.warn('map render error:', e); }
};

// Hook into existing navigation
var _orig_mapStepDate = mapStepDate;
mapStepDate = function(dir) { _orig_mapStepDate(dir); _rt_tabs(MAP_DATES[_mapDateIdx]); };
var _orig_renderDate = _renderDate;
_renderDate = function(d) { _orig_renderDate(d); _rt_tabs(d); };

document.addEventListener('DOMContentLoaded', function() {
  setTimeout(function() {
    if (MAP_DATES.length) _rt_tabs(MAP_DATES[_mapDateIdx]);
  }, 400);
});
</script>
""")

_VENDOR_SETTINGS = _page("""
<h1>Settings</h1>
<form method="post" action="{{ url_for('vendor_settings_save') }}">
{{ csrf_field }}

  <div class="card" style="margin-bottom:1.5rem">
    <h2 style="margin-bottom:1rem">Business Info</h2>
    <div style="display:flex;flex-direction:column;gap:1rem">
      <div class="field">
        <label>Business Name</label>
        <input type="text" name="name" value="{{ vendor.name or '' }}" placeholder="Your business name">
      </div>
      <div class="field">
        <label>Office / Notification Email</label>
        <input type="email" name="office_email" value="{{ vendor.office_email or '' }}" placeholder="office@example.com">
        <span style="font-size:.8rem;color:#aaa">Order summaries and alerts are sent here.</span>
      </div>
      <div class="field">
        <label>Contact Phone</label>
        <input type="tel" name="contact_phone" value="{{ vendor.get('contact_phone', '') }}" placeholder="(555) 555-5555">
        <span style="font-size:.8rem;color:#aaa">Shown on invoices and order confirmations.</span>
      </div>
      <div class="field">
        <label>Order Cutoff Time</label>
        <input type="time" name="cutoff_time" value="{{ vendor.get('cutoff_time', '') }}">
        <span style="font-size:.8rem;color:#aaa">Orders placed after this time may not be fulfilled same-day.</span>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:1.5rem">
    <h2 style="margin-bottom:.5rem">Notifications</h2>
    <div style="display:flex;flex-direction:column;gap:1.2rem;margin-top:1rem">
      <label style="display:flex;align-items:center;gap:1rem;cursor:pointer">
        <input type="checkbox" name="send_confirmations" value="1" {{ 'checked' if vendor.get('send_confirmations', True) else '' }}
          style="width:18px;height:18px;accent-color:#7c3aed">
        <span>
          <strong>Send Order Confirmation Emails</strong>
          <span style="display:block;color:#aaa;font-size:.85rem">Email stores when their order is received.</span>
        </span>
      </label>
    </div>
  </div>

  <div class="card" style="margin-bottom:1.5rem{% if not can_automate %};opacity:.6{% endif %}">
    <h2 style="margin-bottom:.25rem">Automation</h2>
    {% if not can_automate %}
    <p style="margin:.25rem 0 1rem"><span style="background:#7c3aed22;color:#a78bfa;font-size:.8rem;padding:.2rem .6rem;border-radius:4px;border:1px solid #7c3aed55">&#128274; Standard, Pro &amp; Seasonal</span></p>
    {% endif %}
    <div style="display:flex;flex-direction:column;gap:1.2rem;margin-top:.75rem">
      <label style="display:flex;align-items:center;gap:1rem;{{ 'cursor:not-allowed' if not can_automate else 'cursor:pointer' }}">
        <input type="checkbox" name="auto_invoice" value="1" {{ 'checked' if vendor.auto_invoice else '' }}
          {{ 'disabled' if not can_automate else '' }}
          style="width:18px;height:18px;accent-color:#7c3aed">
        <span>
          <strong>Auto-Generate Invoice</strong>
          <span style="display:block;color:#aaa;font-size:.85rem">Automatically create an invoice when a store submits an order.</span>
        </span>
      </label>
      <label style="display:flex;align-items:center;gap:1rem;{{ 'cursor:not-allowed' if not can_automate else 'cursor:pointer' }}">
        <input type="checkbox" name="auto_qb_sync" value="1" {{ 'checked' if vendor.auto_qb_sync else '' }}
          {{ 'disabled' if not can_automate else '' }}
          style="width:18px;height:18px;accent-color:#7c3aed">
        <span>
          <strong>Auto-Sync to QuickBooks</strong>
          <span style="display:block;color:#aaa;font-size:.85rem">Automatically push invoices to QuickBooks Online when created. Requires QB connection.</span>
        </span>
      </label>
    </div>
  </div>

  <button class="btn btn-green" type="submit">Save Settings</button>
</form>
""")


@app.route("/vendor/users")
@vendor_required
def vendor_users():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    _vendor_obj = _get_vendor(vendor_id)
    _vendor_plan = "admin" if session.get("role") == "admin" else ("pro" if vendor_id == "gmf" else (_vendor_obj or {}).get("plan", "starter"))
    all_users = _load_users()
    # Build order summary per store name
    all_orders = cli.orders_list()
    order_summary = {}  # store_name -> {count, last_date}
    for o in all_orders:
        sn = o.get("store_name", "")
        dt = o.get("delivery_date", "") or o.get("date", "")
        if sn not in order_summary:
            order_summary[sn] = {"count": 0, "last_date": ""}
        order_summary[sn]["count"] += 1
        if dt and dt > order_summary[sn]["last_date"]:
            order_summary[sn]["last_date"] = dt
    store_users = [
        {
            "username": u["username"],
            "store_name": u.get("store_name", ""),
            "qb_customer_name": u.get("qb_customer_name", ""),
            "store_number": u.get("store_number", ""),
            "role": u.get("role", "store"),
            "order_count": order_summary.get(u.get("store_name", ""), {}).get("count", 0),
            "last_order": order_summary.get(u.get("store_name", ""), {}).get("last_date", ""),
        }
        for u in all_users
        if u.get("role") == "store" and (
            u.get("vendor_id") == vendor_id or vendor_id in u.get("vendor_ids", [])
        )
    ]
    # Sort: users with orders first (most recent first), then never-ordered alphabetically
    _with_orders = sorted([u for u in store_users if u["last_order"]], key=lambda u: u["last_order"], reverse=True)
    _no_orders   = sorted([u for u in store_users if not u["last_order"]], key=lambda u: u["store_name"].lower())
    store_users  = _with_orders + _no_orders
    edit_username = request.args.get("edit_user")
    edit_store = edit_qb_name = edit_store_number = ""
    if edit_username:
        eu = _get_user(edit_username)
        if eu:
            edit_store = eu.get("store_name", "")
            edit_qb_name = eu.get("qb_customer_name", "")
            edit_store_number = eu.get("store_number", "")
    return _render(_VENDOR_USERS, user_list=store_users,
                   edit_store=edit_store, edit_qb_name=edit_qb_name,
                   edit_store_number=edit_store_number, vendor_plan=_vendor_plan)


@app.route("/vendor/users/edit", methods=["POST"])
@csrf_protect
@vendor_required
def vendor_users_edit():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    username = request.form["username"]
    all_users = _load_users()
    for u in all_users:
        if u["username"] == username and (
            u.get("vendor_id") == vendor_id or vendor_id in u.get("vendor_ids", [])
        ):
            u["store_name"] = request.form.get("store", u.get("store_name", ""))
            qb = request.form.get("qb_customer_name", "").strip()
            if qb:
                u["qb_customer_name"] = qb
            sn = request.form.get("store_number", "").strip()
            if sn:
                u["store_number"] = sn
            break
    _save_users(all_users)
    return _redirect("vendor_users", f"User '{username}' updated.")


@app.route("/vendor/users/add", methods=["POST"])
@csrf_protect
@vendor_required
def vendor_users_add():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    username = request.form["username"]
    if _get_user(username):
        return _redirect("vendor_users", f"Username '{username}' already exists.", cls="err")
    # Check store limit (skip for gmf)
    if vendor_id != "gmf":
        vendor_obj = _get_vendor(vendor_id)
        plan = (vendor_obj or {}).get("plan", "starter")
        limit = 30 if plan == "pro" else 10
        existing = [u for u in _load_users() if u.get("role") == "store" and (
            u.get("vendor_id") == vendor_id or vendor_id in u.get("vendor_ids", []))]
        if len(existing) >= limit:
            return _redirect("vendor_users", f"Store limit reached ({limit} on {plan} plan).", cls="err")
    from werkzeug.security import generate_password_hash as _gph
    all_users = _load_users()
    new_user = {
        "id": max((u.get("id", 0) for u in all_users), default=0) + 1,
        "username": username,
        "password": _gph(request.form["password"]),
        "role": "store",
        "store_name": request.form.get("store", ""),
        "qb_customer_name": request.form.get("qb_customer_name", ""),
        "vendor_id": vendor_id,
        "vendor_ids": [vendor_id],
    }
    all_users.append(new_user)
    _save_users(all_users)
    return _redirect("vendor_users", f"User '{username}' added.")


@app.route("/vendor/users/remove", methods=["POST"])
@csrf_protect
@vendor_required
def vendor_users_remove():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    username = request.form["username"]
    all_users = _load_users()
    # Only allow removing users belonging to this vendor
    target = next((u for u in all_users if u["username"] == username), None)
    if not target or (
        target.get("vendor_id") != vendor_id and vendor_id not in target.get("vendor_ids", [])
    ):
        return _redirect("vendor_users", "User not found or not yours.", cls="err")
    _save_users([u for u in all_users if u["username"] != username])
    _revoke_qr_token(username)
    return _redirect("vendor_users", f"User '{username}' removed.")


@app.route("/vendor/users/password", methods=["POST"])
@csrf_protect
@vendor_required
def vendor_users_password():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    username = request.form["username"]
    new_pw = request.form.get("password", "")
    if not new_pw:
        return _redirect("vendor_users", "Password cannot be empty.", cls="err")
    all_users = _load_users()
    for u in all_users:
        if u["username"] == username and (
            u.get("vendor_id") == vendor_id or vendor_id in u.get("vendor_ids", [])
        ):
            from werkzeug.security import generate_password_hash as _gph
            u["password"] = _gph(new_pw)
            u["session_version"] = u.get("session_version", 0) + 1
            _save_users(all_users)
            return _redirect("vendor_users", f"Password updated for '{username}'.")
    return _redirect("vendor_users", "User not found or not yours.", cls="err")


@app.route("/vendor/map")
@vendor_required
def vendor_map():
    from datetime import date as _date
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    vendor_obj = _get_vendor(vendor_id)
    _plan = (vendor_obj or {}).get("plan", "starter")
    _vendor_plan = "admin" if session.get("role") == "admin" else ("pro" if _is_internal_vendor(vendor_id) else _plan)
    if _vendor_plan not in ("pro", "admin"):
        return _redirect("orders", "Map view is available on the Pro plan.", cls="err")
    all_orders = cli.orders_list()
    if session.get("role") == "vendor":
        vendor_ids = session.get("vendor_ids", [vendor_id])
        all_orders = [o for o in all_orders if o.get("vendor_id") in vendor_ids]
    map_orders = {}
    for o in all_orders:
        d = o.get("delivery_date", "").strip()
        sn = o.get("store_name", "")
        if not d or not sn:
            continue
        if d not in map_orders:
            map_orders[d] = {}
        if sn not in map_orders[d]:
            map_orders[d][sn] = []
        map_orders[d][sn].append({"item": o.get("item", ""), "qty": _disp_qty(o.get("qty", 1), o.get("case_size", ""))})
    # Use all dates that actually have orders, not just configured delivery dates
    map_dates = sorted(map_orders.keys())
    today = _date.today().isoformat()
    return _render(_VENDOR_MAP, map_orders=map_orders, allowed_dates=map_dates,
                   today=today, vendor_plan=_vendor_plan)

@app.route("/settings")
@vendor_required
def vendor_settings():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    vendor = _get_vendor(vendor_id)
    if not vendor:
        return _redirect("invoices", "Vendor not found.", cls="err")
    _vendor_plan = "admin" if session.get("role") == "admin" else ("pro" if vendor_id == "gmf" else vendor.get("plan", "starter"))
    can_automate = vendor.get("plan", "starter") in ("standard", "pro", "seasonal") or vendor_id == "gmf"
    return _render(_VENDOR_SETTINGS, vendor=vendor, can_automate=can_automate, vendor_plan=_vendor_plan)

@app.route("/settings/save", methods=["POST"])
@csrf_protect
@vendor_required
def vendor_settings_save():
    vendor_id = session.get("vendor_id", session.get("vendor_ids", ["gmf"])[0])
    vendors = _load_vendors()
    for v in vendors:
        if v["id"] == vendor_id:
            # Universal settings — all plans
            v["name"]               = request.form.get("name", v.get("name", "")).strip()
            v["office_email"]       = request.form.get("office_email", "").strip()
            v["contact_phone"]      = request.form.get("contact_phone", "").strip()
            v["cutoff_time"]        = request.form.get("cutoff_time", "").strip()
            v["send_confirmations"] = bool(request.form.get("send_confirmations"))
            # Gated settings — Standard+ only
            can_automate = v.get("plan", "starter") in ("standard", "pro", "seasonal") or vendor_id == "gmf"
            if can_automate:
                v["auto_invoice"] = bool(request.form.get("auto_invoice"))
                v["auto_qb_sync"] = bool(request.form.get("auto_qb_sync"))
            _save_vendors(vendors)
            return _redirect("vendor_settings", "Settings saved.")
    return _redirect("invoices", "Vendor not found.", cls="err")

# ---------------------------------------------------------------------------
# Legal Pages
# ---------------------------------------------------------------------------

_TERMS = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms of Use — Everblack™ Orders</title>
<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:3rem auto;padding:0 1.5rem;color:#222;line-height:1.7}
h1{font-size:1.8rem;margin-bottom:.25rem}h2{font-size:1.1rem;margin-top:2rem;color:#7c3aed}
p,li{font-size:.97rem}a{color:#7c3aed}footer{margin-top:3rem;font-size:.85rem;color:#888;border-top:1px solid #eee;padding-top:1rem}</style>
</head><body>
<h1>End User License Agreement</h1>
<p><strong>Everblack Orders Platform</strong> &mdash; Effective Date: April 26, 2026</p>
<h2>1. Acceptance of Terms</h2>
<p>By accessing or using the Everblack Orders Platform (&ldquo;the Platform&rdquo;), you agree to be bound by this Agreement. If you do not agree, do not use the Platform.</p>
<h2>2. Description of Service</h2>
<p>Everblack Orders is a web-based order management platform enabling vendors to manage product catalogs, receive store orders, and process invoices. Access is granted on a per-account basis to authorized users only.</p>
<h2>3. Account Access and Credentials</h2>
<p>You are responsible for maintaining the confidentiality of your credentials. You may not share login credentials with unauthorized persons. Notify the administrator immediately of any unauthorized account use. Everblack reserves the right to suspend or terminate accounts that violate this Agreement.</p>
<h2>4. Permitted Use</h2>
<p>You may use the Platform solely for its intended purpose: submitting, managing, and reviewing product orders and invoices. You may not access other users&rsquo; accounts, reverse engineer the Platform, or use it for any unlawful purpose.</p>
<h2>5. Intellectual Property</h2>
<p>All content, design, code, and functionality is the exclusive property of Everblack. No rights are granted other than the limited license to use the Platform as described herein.</p>
<h2>6. Third-Party Integrations</h2>
<p>The Platform may integrate with QuickBooks Online (Intuit Inc.). Your use of those services is subject to their respective terms and privacy policies. Everblack is not responsible for third-party practices.</p>
<h2>7. Disclaimer of Warranties</h2>
<p>The Platform is provided &ldquo;as is&rdquo; without warranties of any kind. Everblack does not warrant uninterrupted or error-free operation.</p>
<h2>8. Limitation of Liability</h2>
<p>To the fullest extent permitted by law, Everblack shall not be liable for any indirect, incidental, or consequential damages arising from use of the Platform.</p>
<h2>9. Modifications &amp; Termination</h2>
<p>Everblack may modify this Agreement or terminate access at any time. Continued use after changes constitutes acceptance.</p>
<h2>10. Governing Law</h2>
<p>This Agreement is governed by the laws of the State of Maine, United States.</p>
<h2>11. Contact</h2>
<p><a href="mailto:everblack@watcherhq.net">everblack@watcherhq.net</a></p>
<footer>&copy; 2026 Everblack &mdash; <a href="/privacy">Privacy Policy</a></footer>
</body></html>
"""

_PRIVACY = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy — Everblack™ Orders</title>
<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:3rem auto;padding:0 1.5rem;color:#222;line-height:1.7}
h1{font-size:1.8rem;margin-bottom:.25rem}h2{font-size:1.1rem;margin-top:2rem;color:#7c3aed}
p,li{font-size:.97rem}a{color:#7c3aed}footer{margin-top:3rem;font-size:.85rem;color:#888;border-top:1px solid #eee;padding-top:1rem}</style>
</head><body>
<h1>Privacy Policy</h1>
<p><strong>Everblack Orders Platform</strong> &mdash; Effective Date: April 26, 2026</p>
<h2>1. Information We Collect</h2>
<p>We collect usernames, business names, email addresses (when provided), and encrypted passwords. We collect order and invoice data submitted through the Platform including delivery dates, quantities, and item details.</p>
<h2>2. How We Use Your Information</h2>
<p>We use collected information solely to operate the Platform, process orders and invoices, send transactional emails, and secure accounts. We do not sell, rent, or share your data with third parties for marketing purposes.</p>
<h2>3. Data Storage and Security</h2>
<p>Data is stored on secured private servers. Passwords are encrypted using industry-standard hashing (scrypt). Session data is protected using encrypted cookies. Access is restricted to authorized administrators only.</p>
<h2>4. Third-Party Services</h2>
<p><strong>QuickBooks Online (Intuit Inc.):</strong> If you connect QuickBooks, we store an OAuth access token to act on your behalf. We never store your QuickBooks password. Your QuickBooks data is governed by <a href="https://intuit.com/privacy" target="_blank">Intuit&rsquo;s Privacy Policy</a>.</p>
<p><strong>Email:</strong> Confirmation emails and invoices are sent via SMTP. Email addresses are used only for transactional communications.</p>
<h2>5. Cookies and Sessions</h2>
<p>We use session-only cookies to maintain login state. They are not used for advertising or tracking and are not shared with third parties.</p>
<p>We also use one-time QR login tokens, which are stored server-side and linked to individual store accounts. These tokens allow passwordless access via a unique URL and can be invalidated at any time by generating new codes.</p>
<h2>6. Data Retention</h2>
<p>Order and invoice records are retained for the duration of the business relationship. Account data is retained until removed by an administrator.</p>
<h2>7. Your Rights</h2>
<p>You may request access, correction, or deletion of your data at any time. You may disconnect QuickBooks at any time from within the app.</p>
<h2>8. Children&rsquo;s Privacy</h2>
<p>This Platform is intended for business use only and is not directed at individuals under the age of 18.</p>
<h2>9. Changes to This Policy</h2>
<p>We may update this Privacy Policy at any time. Continued use after changes constitutes acceptance.</p>
<h2>10. Contact</h2>
<p><a href="mailto:everblack@watcherhq.net">everblack@watcherhq.net</a> &mdash; <a href="https://orders.everblack.cloud">orders.everblack.cloud</a></p>
<footer>&copy; 2026 Everblack &mdash; <a href="/terms">Terms of Use</a></footer>
</body></html>
"""

@app.route("/static/logo.png")
def serve_logo():
    """Serve the Everblack logo as a static file from the data directory."""
    import io as _io
    import base64 as _b64
    logo_bytes = _b64.b64decode(_LOGO_B64)
    return app.response_class(
        response=logo_bytes,
        status=200,
        mimetype='image/png',
        headers={"Cache-Control": "public, max-age=604800"}  # 7-day browser cache
    )

@app.route("/terms")
def terms():
    return _TERMS

@app.route("/privacy")
def privacy():
    return _PRIVACY

@app.route("/health")
def health():
    """Health check endpoint for monitoring and container orchestration."""
    data_ok = os.path.isdir(DATA_DIR)
    users_ok = os.path.exists(USERS_FILE)
    return jsonify({
        "status": "ok" if (data_ok and users_ok) else "degraded",
        "data_dir": data_ok,
        "users_file": users_ok,
    }), 200 if (data_ok and users_ok) else 503

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# One-time: clear test orders and invoices
def _clear_test_data():
    flag = os.path.join(DATA_DIR, ".test_data_cleared")
    if os.path.exists(flag):
        return
    orders_file = os.path.join(DATA_DIR, "orders.json")
    if os.path.exists(orders_file):
        with _get_file_lock(orders_file):
            _atomic_write(orders_file, [])
    if os.path.exists(INVOICES_FILE):
        _save_invoices([])
    with open(flag, "w") as f:
        f.write("done")

_clear_test_data()

if __name__ == "__main__":
    app.run(debug=False)
