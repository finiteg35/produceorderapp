# main.py
import logging
import os
import secrets
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import crud
import store as data_store
from auth_utils import verify_password
from schemas import (
    InventoryOut,
    InventoryCreate,
    InventoryUpdate,
    OrderCreate,
    OrderOut,
    AllowedDatesUpdate,
    StoreOut,
    StoreCreate,
    LoginRequest,
    StoreLoginResponse,
    OrderSubmitItem,
    ResetPasswordRequest,
)

# ---------------------------------------------------------------------------
# Logging – write to stdout so Render captures it in its log viewer
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan – ensure data directory exists on startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up – ensuring data directory exists...")
    try:
        data_store.DATA_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Data directory ready: %s", data_store.DATA_DIR.resolve())
    except Exception:
        logger.exception("Could not create data directory – continuing anyway")
    yield
    logger.info("Shutting down cleanly")


app = FastAPI(title="Produce Ordering Backend", lifespan=lifespan)

# CORS so your Kivy app (or anything else) can talk to it
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- ROOT ----------

@app.get("/")
def read_root():
    logger.info("GET / health-check")
    return {"status": "ok", "message": "Produce Ordering Backend running"}


@app.head("/")
def head_root():
    """Render's health-check sends HEAD /; return 200 with no body."""
    return None


# ---------- INVENTORY ----------

@app.get("/inventory", response_model=List[InventoryOut])
def list_inventory():
    logger.info("GET /inventory")
    items = crud.get_inventory()
    logger.info("Returning %d inventory items", len(items))
    return items


@app.get("/inventory/item", response_model=InventoryOut)
def get_inventory_item(category: str, item: str):
    logger.info("GET /inventory/item category=%s item=%s", category, item)
    db_item = crud.get_inventory_item(category, item)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@app.post("/inventory", response_model=InventoryOut)
def create_inventory_item(inv: InventoryCreate):
    logger.info("POST /inventory category=%s item=%s", inv.category, inv.item)
    return crud.upsert_inventory_item(inv)


@app.put("/inventory", response_model=InventoryOut)
def update_inventory(category: str, item: str, body: InventoryUpdate):
    logger.info("PUT /inventory category=%s item=%s qty=%s", category, item, body.qty)
    updated = crud.update_inventory_qty(category, item, body.qty)
    if not updated:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated


@app.delete("/inventory/category/{category}", response_model=List[InventoryOut])
def delete_inventory_category(category: str):
    logger.info("DELETE /inventory/category/%s", category)
    deleted = crud.delete_inventory_category(category)
    if not deleted:
        raise HTTPException(status_code=404, detail="Category not found or already empty")
    logger.info("Deleted %d items from category %s", len(deleted), category)
    return deleted


@app.delete("/inventory/{category}/{item}", response_model=InventoryOut)
def delete_inventory_item(category: str, item: str):
    logger.info("DELETE /inventory/%s/%s", category, item)
    deleted = crud.delete_inventory_item(category, item)
    if not deleted:
        raise HTTPException(status_code=404, detail="Item not found")
    logger.info("Deleted item %s from category %s", item, category)
    return deleted


# ---------- ORDERS ----------

@app.post("/orders", response_model=OrderOut)
def create_order(order: OrderCreate):
    logger.info("POST /orders store=%s item=%s qty=%s", order.store_name, order.item, order.qty)
    return crud.create_order(order)


@app.get("/orders", response_model=List[OrderOut])
def list_orders(
        store_name: Optional[str] = None,
        date_prefix: Optional[str] = None,
        item_search: Optional[str] = None,
):
    logger.info(
        "GET /orders store_name=%s date_prefix=%s item_search=%s",
        store_name, date_prefix, item_search,
    )
    orders = crud.get_orders(store_name, date_prefix, item_search)
    logger.info("Returning %d orders", len(orders))
    return orders


@app.get("/orders/store/{store_name}", response_model=List[OrderOut])
def list_store_orders(store_name: str):
    logger.info("GET /orders/store/%s", store_name)
    orders = crud.get_store_orders(store_name)
    logger.info("Returning %d orders for store %s", len(orders), store_name)
    return orders


@app.delete("/orders/{order_id}", response_model=OrderOut)
def delete_order(order_id: int):
    logger.info("DELETE /orders/%d", order_id)
    deleted = crud.delete_order(order_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Order not found")
    logger.info("Deleted order id=%d", order_id)
    return deleted


# ---------- SETTINGS / ALLOWED DATES ----------

@app.get("/settings/allowed_dates", response_model=List[str])
def get_allowed_dates():
    logger.info("GET /settings/allowed_dates")
    return crud.get_allowed_dates()


@app.put("/settings/allowed_dates", response_model=List[str])
def update_allowed_dates(body: AllowedDatesUpdate):
    logger.info("PUT /settings/allowed_dates dates=%s", body.dates)
    return crud.set_allowed_dates(body.dates)


@app.post("/settings/allowed_dates/generate-tomorrow-week", response_model=List[str])
def generate_allowed_dates():
    logger.info("POST /settings/allowed_dates/generate-tomorrow-week")
    dates = crud.generate_allowed_dates_tomorrow_week()
    logger.info("Generated allowed dates: %s", dates)
    return dates


# ---------- STORES ----------

@app.get("/stores/", response_model=List[StoreOut])
def list_stores():
    logger.info("GET /stores/")
    stores = crud.get_stores()
    logger.info("Returning %d stores", len(stores))
    return stores


@app.post("/stores", response_model=StoreOut, status_code=201)
def create_store(store: StoreCreate):
    logger.info("POST /stores store_name=%s username=%s", store.store_name, store.username)
    existing = crud.get_store_by_username(store.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    new_store = crud.create_store(store)
    logger.info("Created store id=%d name=%s", new_store["id"], new_store["store_name"])
    return new_store


@app.post("/stores/reset-password/{store_id}")
def reset_store_password(store_id: int, body: ResetPasswordRequest):
    logger.info("POST /stores/reset-password/%d", store_id)
    store = crud.reset_store_password(store_id, body.new_password)
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    return {"message": f"Password reset for {store['store_name']}"}


# ---------- AUTH ----------

@app.post("/auth/store-login", response_model=StoreLoginResponse)
def store_login(body: LoginRequest):
    logger.info("POST /auth/store-login username=%s", body.username)
    store = crud.get_store_by_username(body.username)
    if not store or not verify_password(body.password, store["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"store_id": store["id"], "store_name": store["store_name"], "email": store.get("email")}


@app.post("/auth/admin-login")
def admin_login(body: LoginRequest):
    logger.info("POST /auth/admin-login username=%s", body.username)
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    user_ok = secrets.compare_digest(body.username, admin_username)
    pass_ok = secrets.compare_digest(body.password, admin_password)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"message": "Admin login successful"}


@app.get("/auth/validate")
def validate_username(username: str):
    logger.info("GET /auth/validate username=%s", username)
    store = crud.get_store_by_username(username)
    return {"exists": store is not None}


# ---------- ORDERS SUBMIT ----------

@app.post("/orders/submit", response_model=List[OrderOut])
def submit_orders(items: List[OrderSubmitItem]):
    logger.info("POST /orders/submit count=%d", len(items))
    created = []
    for item in items:
        store = crud.get_store_by_id(item.store_id)
        if not store:
            raise HTTPException(status_code=404, detail=f"Store id {item.store_id} not found")
        order_in = OrderCreate(
            store_name=store["store_name"],
            category=item.category,
            item=item.item,
            qty=item.qty,
            delivery_date=item.delivery_date,
            submitted_at=item.submitted_at,
            ordered_by=item.ordered_by,
        )
        created.append(crud.create_order(order_in))
    logger.info("Submitted %d orders", len(created))
    return created
