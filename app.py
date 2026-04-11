"""
Produce Order App – Web edition
================================
Flask web interface wrapping the same JSON-file data layer as the CLI.
"""

from flask import Flask, redirect, render_template_string, request, url_for

import main as cli

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Base HTML layout
# ---------------------------------------------------------------------------

_BASE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Produce Order App</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f5f7fa; color: #222; }
    nav { background: #2d6a4f; padding: 0.75rem 1.5rem; display: flex; gap: 1.5rem; align-items: center; }
    nav a { color: #fff; text-decoration: none; font-weight: 600; font-size: 0.95rem; }
    nav a:hover { text-decoration: underline; }
    nav .brand { font-size: 1.1rem; margin-right: auto; }
    .container { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: 1.25rem; font-size: 1.5rem; }
    h2 { margin-bottom: 1rem; font-size: 1.15rem; color: #2d6a4f; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
            padding: 1.25rem; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th { background: #e9f5ee; text-align: left; padding: 0.5rem 0.75rem; }
    td { padding: 0.45rem 0.75rem; border-bottom: 1px solid #eee; }
    tr:last-child td { border-bottom: none; }
    .empty { color: #888; font-style: italic; }
    form.inline { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: flex-end; }
    label { display: block; font-size: 0.8rem; color: #555; margin-bottom: 2px; }
    input[type=text], input[type=number], select {
      padding: 0.4rem 0.6rem; border: 1px solid #ccc; border-radius: 4px;
      font-size: 0.9rem; width: 100%; }
    .field { display: flex; flex-direction: column; }
    .btn { padding: 0.45rem 1rem; border: none; border-radius: 4px; cursor: pointer;
           font-size: 0.9rem; font-weight: 600; }
    .btn-green  { background: #2d6a4f; color: #fff; }
    .btn-green:hover  { background: #1b4332; }
    .btn-red   { background: #c0392b; color: #fff; }
    .btn-red:hover   { background: #922b21; }
    .btn-blue  { background: #1a6fa8; color: #fff; }
    .btn-blue:hover  { background: #145582; }
    .flash { padding: 0.6rem 1rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }
    .flash.ok  { background: #d1fae5; color: #065f46; }
    .flash.err { background: #fee2e2; color: #991b1b; }
    .pill { display: inline-block; background: #e9f5ee; color: #2d6a4f;
            border-radius: 999px; padding: 0.2rem 0.6rem; font-size: 0.8rem; margin: 2px; }
  </style>
</head>
<body>
<nav>
  <span class="brand">🥬 Produce Order App</span>
  <a href="{{ url_for('inventory') }}">Inventory</a>
  <a href="{{ url_for('orders') }}">Orders</a>
  <a href="{{ url_for('dates') }}">Dates</a>
  <a href="{{ url_for('users') }}">Users</a>
</nav>
<div class="container">
  {% if flash_msg %}
    <div class="flash {{ flash_cls }}">{{ flash_msg }}</div>
  {% endif %}
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

_INVENTORY = _BASE.replace(
    "{% block content %}{% endblock %}",
    """{% block content %}
<h1>Inventory</h1>

<div class="card">
  <h2>Add / Update Item</h2>
  <form class="inline" method="post" action="{{ url_for('inventory_add') }}">
    <div class="field"><label>Category</label><input name="category" type="text" required></div>
    <div class="field"><label>Item</label><input name="item" type="text" required></div>
    <div class="field"><label>Qty</label><input name="qty" type="number" min="0" required style="width:80px"></div>
    <button class="btn btn-green" type="submit">Save</button>
  </form>
</div>

<div class="card">
  <h2>Current Inventory ({{ items|length }} items)</h2>
  {% if items %}
  <table>
    <tr><th>ID</th><th>Category</th><th>Item</th><th>Qty</th><th></th></tr>
    {% for r in items %}
    <tr>
      <td>{{ r.id }}</td><td>{{ r.category }}</td><td>{{ r.item }}</td><td>{{ r.qty }}</td>
      <td>
        <form method="post" action="{{ url_for('inventory_remove') }}" style="display:inline">
          <input type="hidden" name="category" value="{{ r.category }}">
          <input type="hidden" name="item" value="{{ r.item }}">
          <button class="btn btn-red" onclick="return confirm('Remove this item?')">Remove</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No inventory items yet.</p>{% endif %}
</div>
{% endblock %}""",
)

_ORDERS = _BASE.replace(
    "{% block content %}{% endblock %}",
    """{% block content %}
<h1>Orders</h1>

<div class="card">
  <h2>Submit Order</h2>
  <form class="inline" method="post" action="{{ url_for('orders_add') }}">
    <div class="field"><label>Store</label><input name="store" type="text" required></div>
    <div class="field"><label>Category</label><input name="category" type="text" required></div>
    <div class="field"><label>Item</label><input name="item" type="text" required></div>
    <div class="field"><label>Qty</label><input name="qty" type="number" min="1" required style="width:80px"></div>
    <div class="field">
      <label>Delivery Date</label>
      <select name="date" required>
        {% for d in allowed_dates %}
          <option value="{{ d }}">{{ d }}</option>
        {% else %}
          <option disabled>No dates configured – go to Dates page</option>
        {% endfor %}
      </select>
    </div>
    <div class="field"><label>Ordered By</label><input name="ordered_by" type="text"></div>
    <button class="btn btn-green" type="submit">Submit</button>
  </form>
</div>

<div class="card">
  <h2>Filter Orders</h2>
  <form class="inline" method="get" action="{{ url_for('orders') }}">
    <div class="field"><label>Store</label><input name="store" type="text" value="{{ filter_store }}"></div>
    <div class="field"><label>Date prefix</label><input name="date" type="text" value="{{ filter_date }}" placeholder="e.g. 2025-04"></div>
    <div class="field"><label>Item</label><input name="item" type="text" value="{{ filter_item }}"></div>
    <button class="btn btn-blue" type="submit">Filter</button>
    <a href="{{ url_for('orders') }}" class="btn btn-blue" style="text-decoration:none">Clear</a>
  </form>
</div>

<div class="card">
  <h2>Orders ({{ order_list|length }} records)</h2>
  {% if order_list %}
  <table>
    <tr><th>ID</th><th>Store</th><th>Category</th><th>Item</th><th>Qty</th><th>Delivery Date</th><th>Submitted At</th><th>By</th><th></th></tr>
    {% for o in order_list %}
    <tr>
      <td>{{ o.id }}</td><td>{{ o.store_name }}</td><td>{{ o.category }}</td>
      <td>{{ o.item }}</td><td>{{ o.qty }}</td><td>{{ o.delivery_date }}</td>
      <td>{{ o.submitted_at }}</td><td>{{ o.ordered_by }}</td>
      <td>
        <form method="post" action="{{ url_for('orders_remove') }}" style="display:inline">
          <input type="hidden" name="id" value="{{ o.id }}">
          <button class="btn btn-red" onclick="return confirm('Remove order #{{ o.id }}?')">Remove</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No orders match your filter.</p>{% endif %}
</div>
{% endblock %}""",
)

_DATES = _BASE.replace(
    "{% block content %}{% endblock %}",
    """{% block content %}
<h1>Delivery Dates</h1>

<div class="card">
  <h2>Auto-generate (tomorrow + 7 days)</h2>
  <form method="post" action="{{ url_for('dates_generate') }}">
    <button class="btn btn-blue">Generate</button>
  </form>
</div>

<div class="card">
  <h2>Set Custom Dates</h2>
  <form method="post" action="{{ url_for('dates_set') }}">
    <div class="field" style="margin-bottom:0.75rem">
      <label>Dates (one per line, e.g. "April 15, 2025")</label>
      <textarea name="dates" rows="5" style="width:100%;padding:0.4rem;border:1px solid #ccc;border-radius:4px;font-size:0.9rem">{{ current_dates|join('\n') }}</textarea>
    </div>
    <button class="btn btn-green" type="submit">Save</button>
  </form>
</div>

<div class="card">
  <h2>Current Allowed Dates</h2>
  {% if current_dates %}
    {% for d in current_dates %}<span class="pill">{{ d }}</span>{% endfor %}
  {% else %}<p class="empty">None configured yet.</p>{% endif %}
</div>
{% endblock %}""",
)

_USERS = _BASE.replace(
    "{% block content %}{% endblock %}",
    """{% block content %}
<h1>Users</h1>

<div class="card">
  <h2>Add User</h2>
  <form class="inline" method="post" action="{{ url_for('users_add') }}">
    <div class="field"><label>Store Name</label><input name="store" type="text" required></div>
    <div class="field"><label>Username</label><input name="username" type="text" required></div>
    <button class="btn btn-green" type="submit">Add</button>
  </form>
</div>

<div class="card">
  <h2>Users ({{ user_list|length }} records)</h2>
  {% if user_list %}
  <table>
    <tr><th>ID</th><th>Store</th><th>Username</th></tr>
    {% for u in user_list %}
    <tr><td>{{ u.id }}</td><td>{{ u.store_name }}</td><td>{{ u.username }}</td></tr>
    {% endfor %}
  </table>
  {% else %}<p class="empty">No users yet.</p>{% endif %}
</div>
{% endblock %}""",
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _render(template, **kwargs):
    kwargs.setdefault("flash_msg", request.args.get("msg", ""))
    kwargs.setdefault("flash_cls", request.args.get("cls", "ok"))
    return render_template_string(template, **kwargs)


def _redirect(endpoint, msg, cls="ok", **kw):
    return redirect(url_for(endpoint, msg=msg, cls=cls, **kw))


# ---------------------------------------------------------------------------
# Routes – Inventory
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("inventory"))


@app.route("/inventory")
def inventory():
    return _render(_INVENTORY, items=cli.inventory_list())


@app.route("/inventory/add", methods=["POST"])
def inventory_add():
    try:
        cli.inventory_add(request.form["category"], request.form["item"], int(request.form["qty"]))
        return _redirect("inventory", f"Saved {request.form['item']}.")
    except Exception as exc:
        return _redirect("inventory", str(exc), cls="err")


@app.route("/inventory/remove", methods=["POST"])
def inventory_remove():
    result = cli.inventory_remove(request.form["category"], request.form["item"])
    if result:
        return _redirect("inventory", f"Removed {result['item']}.")
    return _redirect("inventory", "Item not found.", cls="err")


# ---------------------------------------------------------------------------
# Routes – Orders
# ---------------------------------------------------------------------------

@app.route("/orders")
def orders():
    return _render(
        _ORDERS,
        order_list=cli.orders_list(
            store=request.args.get("store") or None,
            date=request.args.get("date") or None,
            item=request.args.get("item") or None,
        ),
        allowed_dates=cli.dates_list(),
        filter_store=request.args.get("store", ""),
        filter_date=request.args.get("date", ""),
        filter_item=request.args.get("item", ""),
    )


@app.route("/orders/add", methods=["POST"])
def orders_add():
    try:
        result = cli.orders_add(
            store=request.form["store"],
            category=request.form["category"],
            item=request.form["item"],
            qty=int(request.form["qty"]),
            date=request.form["date"],
            ordered_by=request.form.get("ordered_by", ""),
        )
        return _redirect("orders", f"Order #{result['id']} submitted.")
    except Exception as exc:
        return _redirect("orders", str(exc), cls="err")


@app.route("/orders/remove", methods=["POST"])
def orders_remove():
    result = cli.orders_remove(int(request.form["id"]))
    if result:
        return _redirect("orders", f"Order #{result['id']} removed.")
    return _redirect("orders", "Order not found.", cls="err")


# ---------------------------------------------------------------------------
# Routes – Dates
# ---------------------------------------------------------------------------

@app.route("/dates")
def dates():
    return _render(_DATES, current_dates=cli.dates_list())


@app.route("/dates/generate", methods=["POST"])
def dates_generate():
    result = cli.dates_generate()
    return _redirect("dates", f"Generated {len(result)} dates.")


@app.route("/dates/set", methods=["POST"])
def dates_set():
    raw = request.form.get("dates", "")
    new_dates = [d.strip() for d in raw.splitlines() if d.strip()]
    cli.dates_set(new_dates)
    return _redirect("dates", f"Saved {len(new_dates)} dates.")


# ---------------------------------------------------------------------------
# Routes – Users
# ---------------------------------------------------------------------------

@app.route("/users")
def users():
    return _render(_USERS, user_list=cli.users_list())


@app.route("/users/add", methods=["POST"])
def users_add():
    username = request.form["username"]
    existing = [u for u in cli.users_list() if u.get("username") == username]
    if existing:
        return _redirect("users", f"Username '{username}' already exists.", cls="err")
    result = cli.users_add(request.form["store"], username)
    return _redirect("users", f"User '{result['username']}' added.")


# ---------------------------------------------------------------------------
# Entry point (local dev only – Render uses gunicorn)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False)
