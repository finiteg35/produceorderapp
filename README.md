# Produce Order App

A full-stack produce ordering application with a FastAPI backend and a Flask web frontend. Designed for deployment on [Render](https://render.com) with a PostgreSQL database.

## Features

- Inventory management (list, create, update produce items)
- Order submission and retrieval with filtering by store, date, and item
- Configurable allowed delivery dates
- CORS-enabled for cross-origin clients (e.g., mobile/desktop apps)
- Browser-based store login and ordering dashboard (Flask frontend)

## Tech Stack

- **Backend API**: [FastAPI](https://fastapi.tiangolo.com/)
- **Web Frontend**: [Flask](https://flask.palletsprojects.com/) with Jinja2 templates
- **ORM**: [SQLAlchemy](https://www.sqlalchemy.org/)
- **Database**: PostgreSQL (via `psycopg2-binary`)
- **Server**: [Uvicorn](https://www.uvicorn.org/) (API) / Gunicorn or `python web_app.py` (frontend)
- **Deployment**: [Render](https://render.com)

## Prerequisites

- Python 3.9+
- PostgreSQL running locally (for local development)

## Local Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/finiteg35/produceorderapp.git
   cd produceorderapp
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate      # macOS/Linux
   venv\Scripts\activate         # Windows
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the database**

   Create a local PostgreSQL database named `produce_app`:

   ```sql
   CREATE DATABASE produce_app;
   ```

   By default the app connects to:

   ```
   postgresql://postgres:postgres@localhost:5432/produce_app
   ```

   To use a different connection string, set the `DATABASE_URL` environment variable:

   ```bash
   export DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<dbname>
   ```

5. **Run the FastAPI backend**

   ```bash
   uvicorn main:app --reload
   ```

   The API will be available at `http://localhost:8000`.

6. **Run the Flask web frontend** (in a separate terminal)

   ```bash
   python web_app.py
   ```

   The web interface will be available at `http://localhost:5000`.

## Flask Web Frontend

The Flask web frontend (`web_app.py`) provides a browser-based interface for store staff to log in and place produce orders. It communicates with the FastAPI backend over HTTP.

### Frontend Files Called When the App Runs

Below are the exact files loaded each time a page is served.

#### 1. `web_app.py` — Flask Application Entry Point

This is the main server file. It handles all HTTP routes, manages session state (cart, login), and communicates with the FastAPI backend.

Key routes:

| Route | Method | Handler | Template Rendered |
|-------|--------|---------|-------------------|
| `/` | GET | `index()` | redirects to `/login` or `/dashboard` |
| `/login` | GET, POST | `login()` | `templates/login.html` |
| `/logout` | GET | `logout()` | redirects to `/login` |
| `/dashboard` | GET | `dashboard()` | `templates/dashboard.html` |
| `/history` | GET | `history()` | `templates/history.html` |
| `/cart/add` | POST | `cart_add()` | JSON response |
| `/cart/remove` | POST | `cart_remove()` | JSON response |
| `/cart/clear` | POST | `cart_clear()` | JSON response |
| `/order/submit` | POST | `order_submit()` | JSON response |

#### 2. `templates/base.html` — Base HTML Template

Every page extends this file. It defines the shared page structure (navbar, footer) and loads the CSS and JavaScript files:

- **Loads** `static/style.css` via `<link>` tag (line 7)
- **Loads** `static/script.js` via `<script>` tag (line 48)

#### 3. HTML Page Templates (each extends `base.html`)

| File | Route | Description |
|------|-------|-------------|
| `templates/login.html` | `/login` | Store login form |
| `templates/dashboard.html` | `/dashboard` | Inventory browser and cart/ordering page |
| `templates/history.html` | `/history` | Submitted order history |

#### 4. `static/style.css` — Stylesheet

All visual styling for the app: navbar, forms, buttons, cart panel, modals, and responsive/mobile layout. Loaded on every page through `base.html`.

#### 5. `static/script.js` — Client-Side JavaScript

All browser-side interactivity. Loaded on every page through `base.html`. On `DOMContentLoaded` it runs:

- `initCategories()` — collapsible category headers
- `initCartToggle()` — mobile cart panel open/close
- `initEventDelegation()` — attaches click handlers for add/remove/clear/submit
- `setDefaultDeliveryDate()` — pre-selects tomorrow as the default delivery date

User actions trigger `fetch()` calls to the Flask cart and order routes listed above.

### Complete File Loading Chain

```
Browser visits http://localhost:5000/
        │
        ▼
web_app.py  (Flask app receives the request)
        │
        ├─ calls _api() → FastAPI backend (main.py) for inventory / dates / auth
        │
        ▼
Jinja2 renders the matching template:
        │
        ├─ templates/base.html
        │       ├─ <link>   static/style.css
        │       └─ <script> static/script.js
        │
        └─ templates/login.html     (on /login)
           templates/dashboard.html (on /dashboard)
           templates/history.html   (on /history)

Browser renders HTML + CSS
        │
        ▼
static/script.js  DOMContentLoaded fires
        │
        ├─ initCategories()
        ├─ initCartToggle()
        ├─ initEventDelegation()
        └─ setDefaultDeliveryDate()

User interaction → fetch() → Flask route → FastAPI backend → response
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/inventory` | List all inventory items |
| `GET` | `/inventory/item` | Get a single item by `category` and `item` query params |
| `POST` | `/inventory` | Create a new inventory item |
| `PUT` | `/inventory` | Update the quantity of an existing item |
| `POST` | `/orders` | Submit a new order |
| `GET` | `/orders` | List orders (filterable by `store_name`, `date_prefix`, `item_search`) |
| `GET` | `/orders/store/{store_name}` | List all orders for a specific store |
| `GET` | `/settings/allowed_dates` | Get the list of allowed delivery dates |
| `PUT` | `/settings/allowed_dates` | Update the list of allowed delivery dates |

Interactive API documentation is auto-generated by FastAPI and available at:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Deployment (Render)

The repository includes a `render.yaml` configuration file for one-click deployment to Render.

### Steps

1. Push this repository to GitHub.
2. Log in to [Render](https://render.com) and click **New → Blueprint**.
3. Connect your GitHub repository.
4. Render will automatically detect `render.yaml` and provision:
   - A free **Web Service** running the FastAPI app
   - A free **PostgreSQL** database
5. The `DATABASE_URL` environment variable is injected automatically from the linked database.

The build command is:

```bash
pip install -r requirements.txt
```

The start command is:

```bash
bash start.sh
```

`start.sh` expands the `PORT` environment variable that Render injects at runtime and starts Uvicorn on the correct port.

## Project Structure

```
produceorderapp/
│
├── Backend (FastAPI)
│   ├── main.py          # FastAPI application and route definitions
│   ├── database.py      # SQLAlchemy engine and session setup
│   ├── models.py        # ORM models (Inventory, Order, Setting)
│   ├── schemas.py       # Pydantic schemas for request/response validation
│   └── crud.py          # Database CRUD operations
│
├── Frontend (Flask)
│   ├── web_app.py               # Flask app, routes, session/cart logic
│   ├── templates/
│   │   ├── base.html            # Shared layout; loads style.css + script.js
│   │   ├── login.html           # Store login page
│   │   ├── dashboard.html       # Inventory browser and ordering page
│   │   └── history.html         # Order history page
│   └── static/
│       ├── style.css            # All page styles (navbar, forms, cart, modals)
│       └── script.js            # Client-side interactivity (cart, order submit)
│
└── Configuration & Deployment
    ├── start.sh         # Startup script for Render (expands $PORT)
    ├── render.yaml      # Render deployment configuration
    ├── requirements.txt # Python dependencies
    └── README.md        # This file
```

## License

This project is open source. Feel free to use and modify it for your needs.
