# screens/checkout_screen.py
import json, os
from datetime import datetime
from kivy.uix.screenmanager import Screen
from kivy.properties import ObjectProperty

ORDERS_FILE = "data/orders.json"


class CheckoutScreen(Screen):
    cart = ObjectProperty(None)

    def on_pre_enter(self):
        summary = "\n".join([f"{item}: {qty}" for item, qty in self.cart.items()])
        self.ids.order_summary.text = summary

    def confirm_order(self):
        order = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "items": dict(self.cart)
        }

        if not os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, "w") as f:
                json.dump([], f)

        with open(ORDERS_FILE, "r") as f:
            orders = json.load(f)

        orders.append(order)

        with open(ORDERS_FILE, "w") as f:
            json.dump(orders, f, indent=4)

        self.cart.clear()

        history = self.manager.get_screen("order_history")
        history.load_orders()
        self.manager.current = "order_history"
