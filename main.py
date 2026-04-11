#!/usr/bin/env python3
"""
Produce Order App – CLI edition
================================
Single-script application that manages produce inventory, orders, delivery
dates, and store users using plain JSON files for storage.

Usage
-----
    python main.py <command> [subcommand] [options]

Commands
--------
    inventory list
    inventory add   --category CAT --item ITEM --qty QTY
    inventory update --category CAT --item ITEM --qty QTY
    inventory remove --category CAT --item ITEM

    orders list    [--store STORE] [--date DATE] [--item ITEM]
    orders add     --store STORE --category CAT --item ITEM --qty QTY --date DATE [--by USER]
    orders remove  --id ID

    dates list
    dates set   DATE [DATE ...]
    dates generate

    users list
    users add   --store STORE --username USERNAME

Run ``python main.py --help`` or ``python main.py <command> --help`` for details.
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Data directory / file paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))

INVENTORY_FILE = DATA_DIR / "inventory.json"
ORDERS_FILE = DATA_DIR / "orders.json"
USERS_FILE = DATA_DIR / "users.json"
SETTINGS_FILE = DATA_DIR / "settings.json"


# ---------------------------------------------------------------------------
# Low-level JSON helpers
# ---------------------------------------------------------------------------

def _load(path: Path, default: Any) -> Any:
    """Load JSON from *path*; return *default* when the file is absent."""
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"ERROR: {path} is corrupted and could not be parsed: {exc}")


def _save(path: Path, data: Any) -> None:
    """Atomically write *data* as JSON to *path*."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        Path(tmp_path).replace(path)
    except Exception:
        os.unlink(tmp_path)
        raise


def _next_id(records: List[Dict]) -> int:
    """Return max(id) + 1 across *records*, or 1 if the list is empty."""
    return max((r.get("id", 0) for r in records), default=0) + 1


# ---------------------------------------------------------------------------
# Inventory operations
# ---------------------------------------------------------------------------

def inventory_list() -> List[Dict]:
    items = _load(INVENTORY_FILE, [])
    return sorted(items, key=lambda x: (x["category"], x["item"]))


def inventory_add(category: str, item: str, qty: int) -> Dict:
    items = _load(INVENTORY_FILE, [])
    for existing in items:
        if existing["category"] == category and existing["item"] == item:
            existing["qty"] = qty
            _save(INVENTORY_FILE, items)
            return existing
    new_item = {"id": _next_id(items), "category": category, "item": item, "qty": qty}
    items.append(new_item)
    _save(INVENTORY_FILE, items)
    return new_item


def inventory_update(category: str, item: str, qty: int) -> Optional[Dict]:
    items = _load(INVENTORY_FILE, [])
    for existing in items:
        if existing["category"] == category and existing["item"] == item:
            existing["qty"] = qty
            _save(INVENTORY_FILE, items)
            return existing
    return None


def inventory_remove(category: str, item: str) -> Optional[Dict]:
    items = _load(INVENTORY_FILE, [])
    for i, inv in enumerate(items):
        if inv["category"] == category and inv["item"] == item:
            removed = items.pop(i)
            _save(INVENTORY_FILE, items)
            return removed
    return None


# ---------------------------------------------------------------------------
# Order operations
# ---------------------------------------------------------------------------

def orders_list(
    store: Optional[str] = None,
    date: Optional[str] = None,
    item: Optional[str] = None,
) -> List[Dict]:
    orders = _load(ORDERS_FILE, [])
    results = [
        o for o in orders
        if (not store or store.lower() in o.get("store_name", "").lower())
        and (not date or o.get("submitted_at", "").startswith(date))
        and (not item or item.lower() in o.get("item", "").lower())
    ]
    return sorted(results, key=lambda x: x.get("submitted_at", ""), reverse=True)


def orders_add(
    store: str,
    category: str,
    item: str,
    qty: int,
    date: str,
    ordered_by: str = "",
) -> Dict:
    orders = _load(ORDERS_FILE, [])
    new_order = {
        "id": _next_id(orders),
        "store_name": store,
        "category": category,
        "item": item,
        "qty": qty,
        "delivery_date": date,
        "submitted_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "ordered_by": ordered_by,
    }
    orders.append(new_order)
    _save(ORDERS_FILE, orders)
    return new_order


def orders_remove(order_id: int) -> Optional[Dict]:
    orders = _load(ORDERS_FILE, [])
    for i, order in enumerate(orders):
        if order.get("id") == order_id:
            removed = orders.pop(i)
            _save(ORDERS_FILE, orders)
            return removed
    return None


# ---------------------------------------------------------------------------
# Delivery-date operations
# ---------------------------------------------------------------------------

def dates_list() -> List[str]:
    settings = _load(SETTINGS_FILE, {})
    value = settings.get("allowed_dates", "")
    return value.split("|") if value else []


def dates_set(new_dates: List[str]) -> List[str]:
    settings = _load(SETTINGS_FILE, {})
    settings["allowed_dates"] = "|".join(new_dates)
    _save(SETTINGS_FILE, settings)
    return new_dates


def dates_generate() -> List[str]:
    """Populate allowed dates with tomorrow through 7 days from now."""
    tomorrow = datetime.now() + timedelta(days=1)
    new_dates = [
        (tomorrow + timedelta(days=i)).strftime("%B %d, %Y")
        for i in range(7)
    ]
    return dates_set(new_dates)


# ---------------------------------------------------------------------------
# User operations
# ---------------------------------------------------------------------------

def users_list() -> List[Dict]:
    return sorted(_load(USERS_FILE, []), key=lambda x: x.get("store_name", ""))


def users_add(store: str, username: str) -> Dict:
    users = _load(USERS_FILE, [])
    for u in users:
        if u.get("username") == username:
            sys.exit(f"ERROR: username '{username}' already exists.")
    new_user = {"id": _next_id(users), "store_name": store, "username": username}
    users.append(new_user)
    _save(USERS_FILE, users)
    return new_user


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

def _print_table(rows: List[Dict], columns: List[str]) -> None:
    if not rows:
        print("  (no records)")
        return
    col_widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    header = "  ".join(c.upper().ljust(col_widths[c]) for c in columns)
    separator = "  ".join("-" * col_widths[c] for c in columns)
    print(header)
    print(separator)
    for row in rows:
        print("  ".join(str(row.get(c, "")).ljust(col_widths[c]) for c in columns))


# ---------------------------------------------------------------------------
# CLI command handlers
# ---------------------------------------------------------------------------

def cmd_inventory(args: argparse.Namespace) -> None:
    sub = args.inventory_cmd

    if sub == "list":
        items = inventory_list()
        print(f"\nInventory ({len(items)} items)\n")
        _print_table(items, ["id", "category", "item", "qty"])
        print()

    elif sub == "add":
        result = inventory_add(args.category, args.item, args.qty)
        print(f"✅  Saved: [{result['id']}] {result['category']} / {result['item']}  qty={result['qty']}")

    elif sub == "update":
        result = inventory_update(args.category, args.item, args.qty)
        if result is None:
            sys.exit(f"ERROR: Item not found: {args.category} / {args.item}")
        print(f"✅  Updated: [{result['id']}] {result['category']} / {result['item']}  qty={result['qty']}")

    elif sub == "remove":
        result = inventory_remove(args.category, args.item)
        if result is None:
            sys.exit(f"ERROR: Item not found: {args.category} / {args.item}")
        print(f"🗑️  Removed: [{result['id']}] {result['category']} / {result['item']}")

    else:
        args.inventory_parser.print_help()


def cmd_orders(args: argparse.Namespace) -> None:
    sub = args.orders_cmd

    if sub == "list":
        orders = orders_list(
            store=getattr(args, "store", None),
            date=getattr(args, "date", None),
            item=getattr(args, "item", None),
        )
        print(f"\nOrders ({len(orders)} records)\n")
        _print_table(orders, ["id", "store_name", "category", "item", "qty", "delivery_date", "submitted_at"])
        print()

    elif sub == "add":
        result = orders_add(
            store=args.store,
            category=args.category,
            item=args.item,
            qty=args.qty,
            date=args.date,
            ordered_by=getattr(args, "by", ""),
        )
        print(f"✅  Order submitted: [{result['id']}] {result['store_name']} – {result['item']} x{result['qty']} for {result['delivery_date']}")

    elif sub == "remove":
        result = orders_remove(args.id)
        if result is None:
            sys.exit(f"ERROR: Order id {args.id} not found.")
        print(f"🗑️  Removed order [{result['id']}] – {result['store_name']} / {result['item']}")

    else:
        args.orders_parser.print_help()


def cmd_dates(args: argparse.Namespace) -> None:
    sub = args.dates_cmd

    if sub == "list":
        dates = dates_list()
        if dates:
            print("\nAllowed delivery dates:")
            for d in dates:
                print(f"  • {d}")
            print()
        else:
            print("No allowed delivery dates configured. Run: python main.py dates generate")

    elif sub == "set":
        result = dates_set(args.dates)
        print("✅  Allowed delivery dates updated:")
        for d in result:
            print(f"  • {d}")

    elif sub == "generate":
        result = dates_generate()
        print("✅  Generated allowed delivery dates (tomorrow + 7 days):")
        for d in result:
            print(f"  • {d}")

    else:
        args.dates_parser.print_help()


def cmd_users(args: argparse.Namespace) -> None:
    sub = args.users_cmd

    if sub == "list":
        users = users_list()
        print(f"\nUsers ({len(users)} records)\n")
        _print_table(users, ["id", "store_name", "username"])
        print()

    elif sub == "add":
        result = users_add(args.store, args.username)
        print(f"✅  User added: [{result['id']}] {result['store_name']} ({result['username']})")

    else:
        args.users_parser.print_help()


# ---------------------------------------------------------------------------
# Argument parser setup
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Produce Order App – CLI for managing inventory, orders, delivery dates, and users.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sub_cmds = parser.add_subparsers(dest="command", metavar="<command>")

    # ---- inventory ----------------------------------------------------------
    inv_parser = sub_cmds.add_parser("inventory", help="Manage inventory items")
    inv_parser.set_defaults(inventory_parser=inv_parser)
    inv_sub = inv_parser.add_subparsers(dest="inventory_cmd", metavar="<subcommand>")

    inv_sub.add_parser("list", help="List all inventory items")

    inv_add = inv_sub.add_parser("add", help="Add or update an inventory item")
    inv_add.add_argument("--category", required=True, help="Item category (e.g. Potatoes)")
    inv_add.add_argument("--item", required=True, help="Item name (e.g. 'White Chef - 50# bags')")
    inv_add.add_argument("--qty", required=True, type=int, help="Stock quantity")

    inv_upd = inv_sub.add_parser("update", help="Update the quantity of an existing item")
    inv_upd.add_argument("--category", required=True)
    inv_upd.add_argument("--item", required=True)
    inv_upd.add_argument("--qty", required=True, type=int)

    inv_rem = inv_sub.add_parser("remove", help="Remove an inventory item")
    inv_rem.add_argument("--category", required=True)
    inv_rem.add_argument("--item", required=True)

    # ---- orders -------------------------------------------------------------
    ord_parser = sub_cmds.add_parser("orders", help="Manage orders")
    ord_parser.set_defaults(orders_parser=ord_parser)
    ord_sub = ord_parser.add_subparsers(dest="orders_cmd", metavar="<subcommand>")

    ord_list = ord_sub.add_parser("list", help="List orders (with optional filters)")
    ord_list.add_argument("--store", help="Filter by store name (partial match)")
    ord_list.add_argument("--date", help="Filter by submission date prefix (e.g. 2025-04)")
    ord_list.add_argument("--item", help="Filter by item name (partial match)")

    ord_add = ord_sub.add_parser("add", help="Submit a new order")
    ord_add.add_argument("--store", required=True, help="Store name")
    ord_add.add_argument("--category", required=True, help="Item category")
    ord_add.add_argument("--item", required=True, help="Item name")
    ord_add.add_argument("--qty", required=True, type=int, help="Quantity ordered")
    ord_add.add_argument("--date", required=True, help="Delivery date (e.g. 'April 15, 2025')")
    ord_add.add_argument("--by", default="", help="Username placing the order")

    ord_rem = ord_sub.add_parser("remove", help="Remove an order by ID")
    ord_rem.add_argument("--id", required=True, type=int, help="Order ID")

    # ---- dates --------------------------------------------------------------
    dat_parser = sub_cmds.add_parser("dates", help="Manage allowed delivery dates")
    dat_parser.set_defaults(dates_parser=dat_parser)
    dat_sub = dat_parser.add_subparsers(dest="dates_cmd", metavar="<subcommand>")

    dat_sub.add_parser("list", help="Show allowed delivery dates")

    dat_set = dat_sub.add_parser("set", help="Set allowed delivery dates")
    dat_set.add_argument("dates", nargs="+", metavar="DATE", help="One or more delivery dates")

    dat_sub.add_parser("generate", help="Auto-generate dates for the next 7 days starting tomorrow")

    # ---- users --------------------------------------------------------------
    usr_parser = sub_cmds.add_parser("users", help="Manage store users")
    usr_parser.set_defaults(users_parser=usr_parser)
    usr_sub = usr_parser.add_subparsers(dest="users_cmd", metavar="<subcommand>")

    usr_sub.add_parser("list", help="List all users")

    usr_add = usr_sub.add_parser("add", help="Add a new user")
    usr_add.add_argument("--store", required=True, help="Store name")
    usr_add.add_argument("--username", required=True, help="Login username")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "inventory":
        cmd_inventory(args)
    elif args.command == "orders":
        cmd_orders(args)
    elif args.command == "dates":
        cmd_dates(args)
    elif args.command == "users":
        cmd_users(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
