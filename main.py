# main.py
import logging
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Inventory, Order, Setting
import crud
from schemas import (
    InventoryOut,
    InventoryCreate,
    InventoryUpdate,
    OrderCreate,
    OrderOut,
    AllowedDatesUpdate,
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
