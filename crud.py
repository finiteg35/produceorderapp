# crud.py
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import store as data_store
from schemas import InventoryCreate, OrderCreate, StoreCreate
from auth_utils import hash_password


# ---------- INVENTORY ----------

def get_inventory() -> List[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    return sorted(data["inventory"], key=lambda x: (x["category"], x["item"]))


def get_inventory_item(category: str, item: str) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    for inv in data["inventory"]:
        if inv["category"] == category and inv["item"] == item:
            return dict(inv)
    return None


def upsert_inventory_item(inv: InventoryCreate) -> Dict:
    with data_store.get_lock():
        data = data_store.load()
        for existing in data["inventory"]:
            if existing["category"] == inv.category and existing["item"] == inv.item:
                existing["qty"] = inv.qty
                data_store.save(data)
                return dict(existing)
        new_item = {
            "id": data_store.next_id(data, "inventory"),
            "category": inv.category,
            "item": inv.item,
            "qty": inv.qty,
        }
        data["inventory"].append(new_item)
        data_store.save(data)
    return dict(new_item)


def update_inventory_qty(category: str, item: str, qty: int) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
        for existing in data["inventory"]:
            if existing["category"] == category and existing["item"] == item:
                existing["qty"] = qty
                data_store.save(data)
                return dict(existing)
    return None


def delete_inventory_item(category: str, item: str) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
        for i, inv in enumerate(data["inventory"]):
            if inv["category"] == category and inv["item"] == item:
                removed = data["inventory"].pop(i)
                data_store.save(data)
                return dict(removed)
    return None


def delete_inventory_category(category: str) -> List[Dict]:
    with data_store.get_lock():
        data = data_store.load()
        removed = [inv for inv in data["inventory"] if inv["category"] == category]
        if not removed:
            return []
        data["inventory"] = [inv for inv in data["inventory"] if inv["category"] != category]
        data_store.save(data)
    return [dict(r) for r in removed]


# ---------- ORDERS ----------

def create_order(order: OrderCreate) -> Dict:
    with data_store.get_lock():
        data = data_store.load()
        new_order = {
            "id": data_store.next_id(data, "orders"),
            "store_name": order.store_name,
            "category": order.category,
            "item": order.item,
            "qty": order.qty,
            "delivery_date": order.delivery_date,
            "submitted_at": order.submitted_at,
            "ordered_by": order.ordered_by,
        }
        data["orders"].append(new_order)
        data_store.save(data)
    return dict(new_order)


def get_orders(
        store_name: Optional[str] = None,
        date_prefix: Optional[str] = None,
        item_search: Optional[str] = None,
) -> List[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    orders = [
        o for o in data["orders"]
        if (not store_name or store_name.lower() in o["store_name"].lower())
        and (not date_prefix or o["submitted_at"].startswith(date_prefix))
        and (not item_search or item_search.lower() in o["item"].lower())
    ]
    return sorted(orders, key=lambda x: x["submitted_at"], reverse=True)


def get_store_orders(store_name: str) -> List[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    orders = [o for o in data["orders"] if o["store_name"] == store_name]
    return sorted(orders, key=lambda x: x["submitted_at"], reverse=True)


def delete_order(order_id: int) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
        for i, order in enumerate(data["orders"]):
            if order["id"] == order_id:
                removed = data["orders"].pop(i)
                data_store.save(data)
                return dict(removed)
    return None


# ---------- SETTINGS (ALLOWED DATES) ----------

ALLOWED_DATES_KEY = "allowed_dates"


def get_allowed_dates() -> List[str]:
    with data_store.get_lock():
        data = data_store.load()
    value = data["settings"].get(ALLOWED_DATES_KEY, "")
    return value.split("|") if value else []


def set_allowed_dates(dates: List[str]) -> List[str]:
    with data_store.get_lock():
        data = data_store.load()
        data["settings"][ALLOWED_DATES_KEY] = "|".join(dates)
        data_store.save(data)
    return dates


def generate_allowed_dates_tomorrow_week() -> List[str]:
    tomorrow = datetime.now() + timedelta(days=1)
    dates = [
        (tomorrow + timedelta(days=i)).strftime("%B %d, %Y")
        for i in range(7)
    ]
    with data_store.get_lock():
        data = data_store.load()
        data["settings"][ALLOWED_DATES_KEY] = "|".join(dates)
        data_store.save(data)
    return dates


# ---------- STORES ----------

def get_stores() -> List[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    return sorted(data["stores"], key=lambda x: x["store_name"])


def get_store_by_id(store_id: int) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    for s in data["stores"]:
        if s["id"] == store_id:
            return dict(s)
    return None


def get_store_by_username(username: str) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
    for s in data["stores"]:
        if s["username"] == username:
            return dict(s)
    return None


def create_store(store_in: StoreCreate) -> Dict:
    with data_store.get_lock():
        data = data_store.load()
        new_store = {
            "id": data_store.next_id(data, "stores"),
            "store_name": store_in.store_name,
            "username": store_in.username,
            "password": hash_password(store_in.password),
            "email": store_in.email,
        }
        data["stores"].append(new_store)
        data_store.save(data)
    return dict(new_store)


def reset_store_password(store_id: int, new_password: str) -> Optional[Dict]:
    with data_store.get_lock():
        data = data_store.load()
        for s in data["stores"]:
            if s["id"] == store_id:
                s["password"] = hash_password(new_password)
                data_store.save(data)
                return dict(s)
    return None
