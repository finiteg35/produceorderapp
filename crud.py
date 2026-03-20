# crud.py
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from models import Inventory, Order, Setting, Store
from schemas import InventoryCreate, InventoryUpdate, OrderCreate, AllowedDatesUpdate, StoreCreate


# ---------- INVENTORY ----------

def get_inventory(db: Session) -> List[Inventory]:
    return db.query(Inventory).order_by(Inventory.category, Inventory.item).all()


def get_inventory_item(db: Session, category: str, item: str) -> Optional[Inventory]:
    return (
        db.query(Inventory)
        .filter(Inventory.category == category, Inventory.item == item)
        .first()
    )


def create_inventory_item(db: Session, inv: InventoryCreate) -> Inventory:
    db_item = Inventory(
        category=inv.category,
        item=inv.item,
        qty=inv.qty,
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def update_inventory_qty(db: Session, category: str, item: str, qty: int) -> Optional[Inventory]:
    db_item = get_inventory_item(db, category, item)
    if not db_item:
        return None
    db_item.qty = qty
    db.commit()
    db.refresh(db_item)
    return db_item


def delete_inventory_item(db: Session, category: str, item: str) -> Optional[Inventory]:
    db_item = get_inventory_item(db, category, item)
    if not db_item:
        return None
    db.delete(db_item)
    db.flush()
    db.expunge(db_item)
    db.commit()
    return db_item


def delete_inventory_category(db: Session, category: str) -> List[Inventory]:
    items = db.query(Inventory).filter(Inventory.category == category).all()
    for db_item in items:
        db.delete(db_item)
    db.flush()
    for db_item in items:
        db.expunge(db_item)
    db.commit()
    return items


# ---------- ORDERS ----------

def create_order(db: Session, order: OrderCreate) -> Order:
    db_order = Order(
        store_name=order.store_name,
        category=order.category,
        item=order.item,
        qty=order.qty,
        delivery_date=order.delivery_date,
        submitted_at=order.submitted_at,
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order


def get_orders(
        db: Session,
        store_name: Optional[str] = None,
        date_prefix: Optional[str] = None,
        item_search: Optional[str] = None,
) -> List[Order]:
    q = db.query(Order)
    if store_name:
        q = q.filter(Order.store_name.ilike(f"%{store_name}%"))
    if date_prefix:
        q = q.filter(Order.submitted_at.startswith(date_prefix))
    if item_search:
        q = q.filter(Order.item.ilike(f"%{item_search}%"))
    return q.order_by(Order.submitted_at.desc()).all()


def get_store_orders(db: Session, store_name: str) -> List[Order]:
    return (
        db.query(Order)
        .filter(Order.store_name == store_name)
        .order_by(Order.submitted_at.desc())
        .all()
    )


def delete_order(db: Session, order_id: int) -> Optional[Order]:
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if not db_order:
        return None
    db.delete(db_order)
    db.flush()
    db.expunge(db_order)
    db.commit()
    return db_order


# ---------- SETTINGS (ALLOWED DATES) ----------

ALLOWED_DATES_KEY = "allowed_dates"


def get_allowed_dates(db: Session) -> List[str]:
    setting = db.query(Setting).filter(Setting.key == ALLOWED_DATES_KEY).first()
    if not setting or not setting.value:
        return []
    return setting.value.split("|")


def set_allowed_dates(db: Session, dates: List[str]) -> List[str]:
    value = "|".join(dates)
    setting = db.query(Setting).filter(Setting.key == ALLOWED_DATES_KEY).first()
    if not setting:
        setting = Setting(key=ALLOWED_DATES_KEY, value=value)
        db.add(setting)
    else:
        setting.value = value
    db.commit()
    return dates


def generate_allowed_dates_tomorrow_week(db: Session) -> List[str]:
    tomorrow = datetime.now() + timedelta(days=1)
    dates = [
        (tomorrow + timedelta(days=i)).strftime("%B %d, %Y")
        for i in range(7)
    ]
    value = "|".join(dates)
    setting = db.query(Setting).filter(Setting.key == ALLOWED_DATES_KEY).first()
    if not setting:
        setting = Setting(key=ALLOWED_DATES_KEY, value=value)
        db.add(setting)
    else:
        setting.value = value
    db.commit()
    return dates


# ---------- STORES ----------

def get_stores(db: Session) -> List[Store]:
    return db.query(Store).order_by(Store.store_name).all()


def get_store_by_id(db: Session, store_id: int) -> Optional[Store]:
    return db.query(Store).filter(Store.id == store_id).first()


def get_store_by_username(db: Session, username: str) -> Optional[Store]:
    return db.query(Store).filter(Store.username == username).first()


def create_store(db: Session, store: StoreCreate) -> Store:
    db_store = Store(
        store_name=store.store_name,
        username=store.username,
        password=store.password,
    )
    db.add(db_store)
    db.commit()
    db.refresh(db_store)
    return db_store


def reset_store_password(db: Session, store_id: int, new_password: str) -> Optional[Store]:
    store = get_store_by_id(db, store_id)
    if not store:
        return None
    store.password = new_password
    db.commit()
    db.refresh(store)
    return store
