import requests
from requests.exceptions import RequestException

API_URL = "https://produce-backend.onrender.com"

inventory_items = [
    # Potatoes
    {"category": "Potatoes", "item": "White Chef - 50# bags", "qty": 25},
    {"category": "Potatoes", "item": "Yellow Chef - 50# bags", "qty": 25},
    {"category": "Potatoes", "item": "Red A - 50# bags", "qty": 20},
    {"category": "Potatoes", "item": "Red B - 50# bags", "qty": 20},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 60 count", "qty": 15},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 70 count", "qty": 15},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 80 count", "qty": 15},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 90 count", "qty": 15},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 100 count", "qty": 15},
    {"category": "Potatoes", "item": "Russets - 50# boxes, 120 count", "qty": 15},
    # Apples
    {"category": "Apples", "item": "Macintosh - Loose Bulk 40#", "qty": 20},
    {"category": "Apples", "item": "Macintosh - 3# Bags in Case of 12", "qty": 30},
    {"category": "Apples", "item": "Cortland - Loose Bulk 40#", "qty": 20},
    {"category": "Apples", "item": "Cortland - 3# Bags in Case of 12", "qty": 30},
    {"category": "Apples", "item": "Honeycrisp - Loose Bulk 40#", "qty": 15},
    {"category": "Apples", "item": "Honeycrisp - 3# Bags in Case of 12", "qty": 25},
    # Onions
    {"category": "Onions", "item": "Red - 25# bags", "qty": 30},
    {"category": "Onions", "item": "Yellow - 25# bags", "qty": 35},
    # Eggs
    {"category": "Eggs", "item": "Loose Case - 15 dozen", "qty": 40},
    {"category": "Eggs", "item": "Retail Cartons Case - 15 dozen", "qty": 35},
    # Beets
    {"category": "Beets", "item": "Red - 20# bags", "qty": 40},
    {"category": "Beets", "item": "Candy Striped - 20# bags", "qty": 40},
    {"category": "Beets", "item": "gold - 20# bags", "qty": 40},
]

for inv in inventory_items:
    try:
        response = requests.post(
            f"{API_URL}/inventory",
            json=inv,
            timeout=30
        )
        if response.status_code == 200:
            print(f"✅ Created: {inv['category']} - {inv['item']} (qty: {inv['qty']})\n")
        elif response.status_code == 400 and "already exists" in response.text:
            print(f"⚠️  Already exists: {inv['category']} - {inv['item']}\n")
        else:
            print(f"❌ Failed to create {inv['category']} - {inv['item']}: {response.text}\n")
    except RequestException as e:
        print(f"❌ Error creating {inv['category']} - {inv['item']}: {e}\n")