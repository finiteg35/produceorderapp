# main.py
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Inventory, Order, Setting, Store
import crud
from schemas import (
    InventoryOut,
    InventoryCreate,
    InventoryUpdate,
    OrderCreate,
    OrderOut,
    AllowedDatesUpdate,
    StoreOut,
    LoginRequest,
    StoreLoginResponse,
    OrderSubmitItem,
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
# Lifespan – create tables on startup, log clean shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up – creating database tables if needed...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ready")
    except Exception:
        logger.exception("Database table creation failed – continuing anyway")
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
def list_inventory(db: Session = Depends(get_db)):
    logger.info("GET /inventory")
    items = crud.get_inventory(db)
    logger.info("Returning %d inventory items", len(items))
    return items


@app.get("/inventory/item", response_model=InventoryOut)
def get_inventory_item(
        category: str,
        item: str,
        db: Session = Depends(get_db),
):
    logger.info("GET /inventory/item category=%s item=%s", category, item)
    db_item = crud.get_inventory_item(db, category, item)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@app.post("/inventory", response_model=InventoryOut)
def create_inventory_item(inv: InventoryCreate, db: Session = Depends(get_db)):
    logger.info("POST /inventory category=%s item=%s", inv.category, inv.item)
    db_item = crud.get_inventory_item(db, inv.category, inv.item)
    if db_item:
        raise HTTPException(status_code=400, detail="Item already exists")
    return crud.create_inventory_item(db, inv)


@app.put("/inventory", response_model=InventoryOut)
def update_inventory(
        category: str,
        item: str,
        body: InventoryUpdate,
        db: Session = Depends(get_db),
):
    logger.info("PUT /inventory category=%s item=%s qty=%s", category, item, body.qty)
    updated = crud.update_inventory_qty(db, category, item, body.qty)
    if not updated:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated


# ---------- ORDERS ----------

@app.post("/orders", response_model=OrderOut)
def create_order(order: OrderCreate, db: Session = Depends(get_db)):
    logger.info("POST /orders store=%s item=%s qty=%s", order.store_name, order.item, order.qty)
    return crud.create_order(db, order)


@app.get("/orders", response_model=List[OrderOut])
def list_orders(
        store_name: Optional[str] = None,
        date_prefix: Optional[str] = None,
        item_search: Optional[str] = None,
        db: Session = Depends(get_db),
):
    logger.info(
        "GET /orders store_name=%s date_prefix=%s item_search=%s",
        store_name, date_prefix, item_search,
    )
    orders = crud.get_orders(db, store_name, date_prefix, item_search)
    logger.info("Returning %d orders", len(orders))
    return orders


@app.get("/orders/store/{store_name}", response_model=List[OrderOut])
def list_store_orders(store_name: str, db: Session = Depends(get_db)):
    logger.info("GET /orders/store/%s", store_name)
    orders = crud.get_store_orders(db, store_name)
    logger.info("Returning %d orders for store %s", len(orders), store_name)
    return orders


# ---------- SETTINGS / ALLOWED DATES ----------

@app.get("/settings/allowed_dates", response_model=List[str])
def get_allowed_dates(db: Session = Depends(get_db)):
    logger.info("GET /settings/allowed_dates")
    return crud.get_allowed_dates(db)


@app.put("/settings/allowed_dates", response_model=List[str])
def update_allowed_dates(body: AllowedDatesUpdate, db: Session = Depends(get_db)):
    logger.info("PUT /settings/allowed_dates dates=%s", body.dates)
    return crud.set_allowed_dates(db, body.dates)


# ---------- STORES ----------

@app.get("/stores/", response_model=List[StoreOut])
def list_stores(db: Session = Depends(get_db)):
    logger.info("GET /stores/")
    stores = crud.get_stores(db)
    logger.info("Returning %d stores", len(stores))
    return stores


@app.post("/stores/reset-password/{store_id}")
def reset_store_password(store_id: int, db: Session = Depends(get_db)):
    logger.info("POST /stores/reset-password/%d", store_id)
    store = crud.reset_store_password(db, store_id, "reset123")
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    return {"message": f"Password reset for {store.store_name}"}


# ---------- AUTH ----------

@app.post("/auth/store-login", response_model=StoreLoginResponse)
def store_login(body: LoginRequest, db: Session = Depends(get_db)):
    logger.info("POST /auth/store-login username=%s", body.username)
    store = crud.get_store_by_username(db, body.username)
    if not store or store.password != body.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"store_id": store.id, "store_name": store.store_name}


@app.post("/auth/admin-login")
def admin_login(body: LoginRequest):
    import secrets
    logger.info("POST /auth/admin-login username=%s", body.username)
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    user_ok = secrets.compare_digest(body.username, admin_username)
    pass_ok = secrets.compare_digest(body.password, admin_password)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"message": "Admin login successful"}


# ---------- ORDERS SUBMIT ----------

@app.post("/orders/submit", response_model=List[OrderOut])
def submit_orders(items: List[OrderSubmitItem], db: Session = Depends(get_db)):
    logger.info("POST /orders/submit count=%d", len(items))
    created = []
    for item in items:
        store = crud.get_store_by_id(db, item.store_id)
        if not store:
            raise HTTPException(status_code=404, detail=f"Store id {item.store_id} not found")
        order_in = OrderCreate(
            store_name=store.store_name,
            category=item.category,
            item=item.item,
            qty=item.qty,
            delivery_date=item.delivery_date,
            submitted_at=item.submitted_at,
        )
        created.append(crud.create_order(db, order_in))
    logger.info("Submitted %d orders", len(created))
    return created
