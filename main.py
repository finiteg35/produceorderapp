# main.py
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

# Create tables (for simple deployment; for serious prod use Alembic)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Produce Ordering Backend")

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
    return {"status": "ok", "message": "Produce Ordering Backend running"}


# ---------- INVENTORY ----------

@app.get("/inventory", response_model=List[InventoryOut])
def list_inventory(db: Session = Depends(get_db)):
    items = crud.get_inventory(db)
    return items


@app.get("/inventory/item", response_model=InventoryOut)
def get_inventory_item(
        category: str,
        item: str,
        db: Session = Depends(get_db),
):
    db_item = crud.get_inventory_item(db, category, item)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@app.post("/inventory", response_model=InventoryOut)
def create_inventory_item(inv: InventoryCreate, db: Session = Depends(get_db)):
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
    updated = crud.update_inventory_qty(db, category, item, body.qty)
    if not updated:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated


# ---------- ORDERS ----------

@app.post("/orders", response_model=OrderOut)
def create_order(order: OrderCreate, db: Session = Depends(get_db)):
    # You can add inventory checks here if you want the backend to enforce stock
    return crud.create_order(db, order)


@app.get("/orders", response_model=List[OrderOut])
def list_orders(
        store_name: Optional[str] = None,
        date_prefix: Optional[str] = None,
        item_search: Optional[str] = None,
        db: Session = Depends(get_db),
):
    return crud.get_orders(db, store_name, date_prefix, item_search)


@app.get("/orders/store/{store_name}", response_model=List[OrderOut])
def list_store_orders(store_name: str, db: Session = Depends(get_db)):
    return crud.get_store_orders(db, store_name)


# ---------- SETTINGS / ALLOWED DATES ----------

@app.get("/settings/allowed_dates", response_model=List[str])
def get_allowed_dates(db: Session = Depends(get_db)):
    return crud.get_allowed_dates(db)


@app.put("/settings/allowed_dates", response_model=List[str])
def update_allowed_dates(body: AllowedDatesUpdate, db: Session = Depends(get_db)):
    return crud.set_allowed_dates(db, body.dates)
