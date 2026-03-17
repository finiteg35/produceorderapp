import requests
from requests.exceptions import RequestException

API_URL = "https://produce-backend.onrender.com"

stores = [
    {
        "store_name": "Scarborough Hannaford",
        "username": "scarborough_hannaford",
        "password": "Scarborough123!"
    },
    {
        "store_name": "Westbrook Hannaford",
        "username": "westbrook_hannaford",
        "password": "Westbrook123!"
    },
    {
        "store_name": "Riverside Hannaford",
        "username": "riverside_hannaford",
        "password": "Riverside123!"
    },
    {
        "store_name": "Rosemont Bakery",
        "username": "rosemont_bakery",
        "password": "Rosemont123!"
    },
    {
        "store_name": "Scratch Bakery",
        "username": "scratch_bakery",
        "password": "Scratch123!"
    },
    {
        "store_name": "Two Fat Cats Bakery",
        "username": "two_fat_cats",
        "password": "TwoFatCats123!"
    },
    {
        "store_name": "Becky's Diner",
        "username": "beckys_diner",
        "password": "Beckys123!"
    }
]

for store in stores:
    try:
        response = requests.post(
            f"{API_URL}/stores",
            json=store,
            timeout=30
        )
        if response.status_code == 201:
            print(f"✅ Created: {store['store_name']} (username: {store['username']})\n")
        else:
            print(f"❌ Failed to create {store['store_name']}: {response.text}\n")
    except RequestException as e:
        print(f"❌ Error creating {store['store_name']}: {e}\n")
