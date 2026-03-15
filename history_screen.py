# screens/order_history_screen.py
import json, os
from kivy.uix.screenmanager import Screen

ORDERS_FILE = "data/orders.json"


class OrderHistoryScreen(Screen):

    def load_orders(self):
        container = self.ids.order_list
        container.clear_widgets()

        if not os.path.exists(ORDERS_FILE):
            return

        with open(ORDERS_FILE, "r") as f:
            orders = json.load(f)

        from kivy.uix.boxlayout import BoxLayout
        from kivy.uix.label import Label

        for order in reversed(orders):
            box = BoxLayout(orientation="vertical", size_hint_y=None, height=120, padding=10)
            box.add_widget(Label(text=f"Date: {order['timestamp']}", font_size=18, size_hint_y=None, height=30))

            items_text = "\n".join([f"{item}: {qty}" for item, qty in order["items"].items()])
            box.add_widget(Label(text=items_text, font_size=16))

            container.add_widget(box)
