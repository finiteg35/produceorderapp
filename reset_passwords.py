import os
import sys
import requests
from requests.exceptions import RequestException

API_URL = os.environ.get("API_URL", "https://produce-backend.onrender.com")

# Map usernames to their passwords (matches setup_stores.py)
store_passwords = {
    "scarborough_hannaford": "Scarborough123!",
    "westbrook_hannaford": "Westbrook123!",
    "riverside_hannaford": "Riverside123!",
    "rosemont_bakery": "Rosemont123!",
    "scratch_bakery": "Scratch123!",
    "two_fat_cats": "TwoFatCats123!",
    "beckys_diner": "Beckys123!",
}

# Fetch all stores to get their IDs
try:
    response = requests.get(f"{API_URL}/stores/", timeout=30)
    response.raise_for_status()
    stores = response.json()
except RequestException as e:
    print(f"❌ Failed to fetch stores: {e}")
    sys.exit(1)

for store in stores:
    store_id = store["id"]
    username = store["username"]
    store_name = store["store_name"]

    password = store_passwords.get(username)
    if not password:
        print(f"⚠️  No password found for {store_name} (username: {username}), skipping\n")
        continue

    try:
        resp = requests.post(
            f"{API_URL}/stores/reset-password/{store_id}",
            json={"new_password": password},
            timeout=30,
        )
        if resp.status_code == 200:
            print(f"✅ Reset password for {store_name} (username: {username})\n")
        else:
            print(f"❌ Failed to reset password for {store_name}: {resp.text}\n")
    except RequestException as e:
        print(f"❌ Error resetting password for {store_name}: {e}\n")
