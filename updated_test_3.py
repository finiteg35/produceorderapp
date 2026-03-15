import requests
from datetime import datetime, timedelta

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.uix.image import Image
from kivy.animation import Animation

# ---------------------------------------------------------
# API CONFIG
# ---------------------------------------------------------
API_URL = "http://localhost:8000"

# ---------------------------------------------------------
# THEME COLORS
# ---------------------------------------------------------
BG_LIGHT = (0.88, 0.96, 0.88, 1)
BTN_GREEN = (0.20, 0.55, 0.20, 1)
BTN_GREEN_LIGHT = (0.35, 0.70, 0.35, 1)
BTN_YELLOW = (0.95, 0.85, 0.40, 1)
BTN_RED = (0.75, 0.25, 0.25, 1)
SCROLL_GREEN = (0.25, 0.55, 0.25, 1)
CYAN_TEXT = (0.0, 0.7, 0.8, 1)


class ProduceApp(App):
    def build(self):
        self.cart = []
        self.all_orders = []
        self.current_store = None
        self.allowed_dates = []
        self.inventory = {}
        self.stores = []

        self.root_layout = BoxLayout()

        # load initial data from backend
        self.load_inventory_from_backend()
        self.load_allowed_dates_from_backend()
        self.load_stores_from_backend()
        self.load_all_orders_from_backend()

        self.show_screen(self.start_screen())
        return self.root_layout

    # ---------------------------------------------------------
    # BACKEND HELPERS
    # ---------------------------------------------------------
    def load_inventory_from_backend(self):
        try:
            resp = requests.get(f"{API_URL}/inventory")
            if resp.status_code == 200:
                items = resp.json()
                inv = {}
                for item in items:
                    cat = item["category"]
                    if cat not in inv:
                        inv[cat] = {}
                    inv[cat][item["item"]] = {
                        "qty": item["qty"],
                        "image": item.get("image_path", "")
                    }
                self.inventory = inv
        except Exception as e:
            print("Error loading inventory:", e)

    def load_allowed_dates_from_backend(self):
        try:
            resp = requests.get(f"{API_URL}/settings/delivery-dates")
            if resp.status_code == 200:
                data = resp.json()
                self.allowed_dates = data.get("dates", [])
            else:
                self.allowed_dates = []
        except Exception as e:
            print("Error loading allowed dates:", e)
            self.allowed_dates = []

    def save_allowed_dates_to_backend(self):
        try:
            resp = requests.post(
                f"{API_URL}/settings/delivery-dates",
                json={"dates": self.allowed_dates}
            )
            if resp.status_code != 200:
                print("Error saving allowed dates:", resp.text)
        except Exception as e:
            print("Error saving allowed dates:", e)

    def load_stores_from_backend(self):
        try:
            resp = requests.get(f"{API_URL}/stores/")
            if resp.status_code == 200:
                self.stores = resp.json()
            else:
                self.stores = []
        except Exception as e:
            print("Error loading stores:", e)
            self.stores = []

    def reset_store_password_backend(self, store_id):
        try:
            resp = requests.post(f"{API_URL}/stores/reset-password/{store_id}")
            if resp.status_code == 200:
                return True
        except Exception as e:
            print("Error resetting password:", e)
        return False

    def load_all_orders_from_backend(self):
        try:
            resp = requests.get(f"{API_URL}/orders/all")
            if resp.status_code == 200:
                self.all_orders = resp.json()
            else:
                self.all_orders = []
        except Exception as e:
            print("Error loading all orders:", e)
            self.all_orders = []

    def load_store_orders_from_backend(self, store_id):
        try:
            resp = requests.get(f"{API_URL}/orders/store/{store_id}")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print("Error loading store orders:", e)
        return []

    def update_inventory_backend(self, updates):
        # updates: list of {"category", "item", "qty"} from current inventory
        # we need ids, but for now we assume admin inventory is mostly visual;
        # real inventory sync can be added once IDs are wired into UI.
        # Placeholder: no-op to avoid breaking flow.
        pass

    # ---------------------------------------------------------
    # SCREEN SWITCH WITH SIMPLE FADE ANIMATION
    # ---------------------------------------------------------
    def show_screen(self, widget):
        self.root_layout.clear_widgets()
        widget.opacity = 0
        self.root_layout.add_widget(widget)
        Animation(opacity=1, d=0.2).start(widget)

    # ---------------------------------------------------------
    # START SCREEN
    # ---------------------------------------------------------
    def start_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=20)

        title = Label(
            text="Produce Ordering System",
            font_size=32,
            size_hint=(1, 0.3),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        store_btn = Button(
            text="Store Login",
            font_size=26,
            size_hint=(1, 0.3),
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        store_btn.bind(on_press=lambda instance: self.show_screen(self.store_login_screen()))
        layout.add_widget(store_btn)

        admin_btn = Button(
            text="Admin Login",
            font_size=26,
            size_hint=(1, 0.3),
            background_normal='',
            background_color=BTN_YELLOW,
            color=(0.2, 0.2, 0.2, 1),
            border=(20, 20, 20, 20)
        )
        admin_btn.bind(on_press=lambda instance: self.show_screen(self.admin_login_screen()))
        layout.add_widget(admin_btn)

        return layout

    # ---------------------------------------------------------
    # STORE LOGIN
    # ---------------------------------------------------------
    def store_login_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Store Login",
            font_size=32,
            size_hint=(1, 0.2),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        user_input = TextInput(
            hint_text="Username",
            multiline=False,
            font_size=22,
            size_hint=(1, 0.15)
        )
        layout.add_widget(user_input)

        pass_input = TextInput(
            hint_text="Password",
            multiline=False,
            password=True,
            font_size=22,
            size_hint=(1, 0.15)
        )
        layout.add_widget(pass_input)

        btn_row = BoxLayout(orientation='horizontal', size_hint=(1, 0.2), spacing=10)

        back_btn = Button(
            text="← Back",
            font_size=22,
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.start_screen()))
        btn_row.add_widget(back_btn)

        login_btn = Button(
            text="Login",
            font_size=22,
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )

        def do_login(instance):
            username = user_input.text.strip()
            password = pass_input.text.strip()
            try:
                resp = requests.post(
                    f"{API_URL}/auth/store-login",
                    json={"username": username, "password": password}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self.current_store = {
                        "id": data["store_id"],
                        "store_name": data["store_name"]
                    }
                    self.cart = []
                    self.show_screen(self.main_menu())
                    return
            except Exception as e:
                print("Store login error:", e)

            Popup(
                title="Login Failed",
                content=Label(text="Invalid store username or password.", font_size=20),
                size_hint=(0.6, 0.4)
            ).open()

        login_btn.bind(on_press=do_login)
        btn_row.add_widget(login_btn)

        layout.add_widget(btn_row)

        return layout

    # ---------------------------------------------------------
    # ADMIN LOGIN
    # ---------------------------------------------------------
    def admin_login_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Admin Login",
            font_size=32,
            size_hint=(1, 0.2),
            color=(0.0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        user_input = TextInput(
            hint_text="Admin Username",
            multiline=False,
            font_size=22,
            size_hint=(1, 0.15)
        )
        layout.add_widget(user_input)

        pass_input = TextInput(
            hint_text="Admin Password",
            multiline=False,
            password=True,
            font_size=22,
            size_hint=(1, 0.15)
        )
        layout.add_widget(pass_input)

        btn_row = BoxLayout(orientation='horizontal', size_hint=(1, 0.2), spacing=10)

        back_btn = Button(
            text="← Back",
            font_size=22,
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.start_screen()))
        btn_row.add_widget(back_btn)

        login_btn = Button(
            text="Login",
            font_size=22,
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )

        def do_login(instance):
            username = user_input.text.strip()
            password = pass_input.text.strip()
            try:
                resp = requests.post(
                    f"{API_URL}/auth/admin-login",
                    json={"username": username, "password": password}
                )
                if resp.status_code == 200:
                    self.show_screen(self.admin_dashboard_screen())
                    return
            except Exception as e:
                print("Admin login error:", e)

            Popup(
                title="Login Failed",
                content=Label(text="Invalid admin credentials.", font_size=20),
                size_hint=(0.6, 0.4)
            ).open()

        login_btn.bind(on_press=do_login)
        btn_row.add_widget(login_btn)

        layout.add_widget(btn_row)

        return layout

    # ---------------------------------------------------------
    # ADMIN DASHBOARD
    # ---------------------------------------------------------
    def admin_dashboard_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Admin Dashboard",
            font_size=32,
            size_hint=(1, 0.2),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        btn_stores = Button(
            text="View Stores / Reset Passwords",
            font_size=22,
            size_hint=(1, 0.2),
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        btn_stores.bind(on_press=lambda instance: self.show_screen(self.admin_stores_screen()))
        layout.add_widget(btn_stores)

        btn_inventory = Button(
            text="View / Edit Inventory",
            font_size=22,
            size_hint=(1, 0.2),
            background_normal='',
            background_color=BTN_GREEN_LIGHT,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        btn_inventory.bind(on_press=lambda instance: self.show_screen(self.admin_inventory_screen()))
        layout.add_widget(btn_inventory)

        btn_orders = Button(
            text="View / Filter Orders",
            font_size=22,
            size_hint=(1, 0.2),
            background_normal='',
            background_color=BTN_YELLOW,
            color=(0.2, 0.2, 0.2, 1),
            border=(20, 20, 20, 20)
        )
        btn_orders.bind(on_press=lambda instance: self.show_screen(self.admin_orders_screen()))
        layout.add_widget(btn_orders)

        btn_calendar = Button(
            text="Delivery Calendar Settings",
            font_size=22,
            size_hint=(1, 0.2),
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        btn_calendar.bind(on_press=lambda instance: self.show_screen(self.admin_calendar_screen()))
        layout.add_widget(btn_calendar)

        back_btn = Button(
            text="← Back to Start",
            font_size=22,
            size_hint=(1, 0.2),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.start_screen()))
        layout.add_widget(back_btn)

        return layout

    # ---------------------------------------------------------
    # ADMIN STORES
    # ---------------------------------------------------------
    def admin_stores_screen(self):
        # refresh stores from backend
        self.load_stores_from_backend()

        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Stores",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back to Admin Dashboard",
            font_size=22,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.admin_dashboard_screen()))
        layout.add_widget(back_btn)

        scroll = ScrollView(
            size_hint=(1, 0.7),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=10, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        if not self.stores:
            grid.add_widget(Label(
                text="No stores found.",
                font_size=20,
                size_hint_y=None,
                height=60,
                color=(0, 0.3, 0, 1)
            ))
        else:
            for store in self.stores:
                row = BoxLayout(orientation='horizontal', size_hint_y=None, height=80, spacing=10)

                info = Label(
                    text=f"{store['store_name']}\nUser: {store['username']}",
                    font_size=18,
                    halign='left',
                    valign='middle'
                )
                info.bind(size=lambda instance, value: setattr(instance, 'text_size', value))

                reset_btn = Button(
                    text="Reset Password",
                    font_size=18,
                    size_hint=(0.35, 1),
                    background_normal='',
                    background_color=BTN_YELLOW,
                    color=(0.2, 0.2, 0.2, 1),
                    border=(20, 20, 20, 20)
                )

                def make_reset(s):
                    def do_reset(instance):
                        ok = self.reset_store_password_backend(s["id"])
                        if ok:
                            Popup(
                                title="Password Reset",
                                content=Label(text=f"{s['store_name']} password set to: reset123", font_size=18),
                                size_hint=(0.7, 0.4)
                            ).open()
                        else:
                            Popup(
                                title="Error",
                                content=Label(text="Could not reset password.", font_size=18),
                                size_hint=(0.7, 0.4)
                            ).open()

                    return do_reset

                reset_btn.bind(on_press=make_reset(store))

                row.add_widget(info)
                row.add_widget(reset_btn)
                grid.add_widget(row)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    # ---------------------------------------------------------
    # ADMIN INVENTORY
    # ---------------------------------------------------------
    def admin_inventory_screen(self):
        # refresh inventory from backend
        self.load_inventory_from_backend()

        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Inventory",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back to Admin Dashboard",
            font_size=22,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.admin_dashboard_screen()))
        layout.add_widget(back_btn)

        scroll = ScrollView(
            size_hint=(1, 0.7),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=10, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        for category, items in self.inventory.items():
            cat_label = Label(
                text=category,
                font_size=24,
                size_hint_y=None,
                height=50,
                color=(0, 0.3, 0, 1)
            )
            grid.add_widget(cat_label)

            for item_name, data in items.items():
                qty = data["qty"]
                row = BoxLayout(orientation='horizontal', size_hint_y=None, height=70, spacing=10)

                info = Label(
                    text=f"{item_name}\nQty: {qty}",
                    font_size=18,
                    halign='left',
                    valign='middle'
                )
                info.bind(size=lambda instance, value: setattr(instance, 'text_size', value))

                btns = BoxLayout(orientation='horizontal', size_hint=(0.5, 1), spacing=5)

                def make_btn(delta, cat=category, item=item_name):
                    b = Button(
                        text=f"{'+' if delta > 0 else ''}{delta}",
                        font_size=18,
                        background_normal='',
                        background_color=BTN_GREEN if delta > 0 else BTN_RED,
                        color=(1, 1, 1, 1),
                        border=(20, 20, 20, 20)
                    )

                    def do_change(instance):
                        self.change_inventory(cat, item, delta)
                        # here we could push changes to backend if we tracked IDs
                        self.show_screen(self.admin_inventory_screen())

                    b.bind(on_press=do_change)
                    return b

                btns.add_widget(make_btn(-10))
                btns.add_widget(make_btn(-1))
                btns.add_widget(make_btn(1))
                btns.add_widget(make_btn(10))

                row.add_widget(info)
                row.add_widget(btns)
                grid.add_widget(row)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    def change_inventory(self, category, item, delta):
        current = self.inventory[category][item]["qty"]
        new = max(0, current + delta)
        self.inventory[category][item]["qty"] = new

    # ---------------------------------------------------------
    # ADMIN ORDERS WITH FILTERS
    # ---------------------------------------------------------
    def admin_orders_screen(self):
        # refresh all orders from backend
        self.load_all_orders_from_backend()

        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="All Orders",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back to Admin Dashboard",
            font_size=22,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.admin_dashboard_screen()))
        layout.add_widget(back_btn)

        filter_row = BoxLayout(orientation='horizontal', size_hint=(1, 0.15), spacing=10)

        store_filter = TextInput(
            hint_text="Filter by store",
            multiline=False,
            font_size=18
        )
        date_filter = TextInput(
            hint_text="Filter by date (YYYY-MM-DD)",
            multiline=False,
            font_size=18
        )
        item_filter = TextInput(
            hint_text="Search item",
            multiline=False,
            font_size=18
        )

        filter_row.add_widget(store_filter)
        filter_row.add_widget(date_filter)
        filter_row.add_widget(item_filter)

        layout.add_widget(filter_row)

        scroll = ScrollView(
            size_hint=(1, 0.55),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=10, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        def refresh_orders(*args):
            grid.clear_widgets()
            if not self.all_orders:
                grid.add_widget(Label(
                    text="No orders have been submitted yet.",
                    font_size=22,
                    size_hint_y=None,
                    height=60,
                    color=(0, 0.3, 0, 1)
                ))
                return

            sf = store_filter.text.strip().lower()
            df = date_filter.text.strip()
            itf = item_filter.text.strip().lower()

            for order in self.all_orders:
                if sf and sf not in order["store_name"].lower():
                    continue
                if df and not order["submitted_at"].startswith(df):
                    continue
                if itf and itf not in order["item"].lower():
                    continue

                text = (
                    f"Store: {order['store_name']}\n"
                    f"{order['qty']} × {order['item']} ({order['category']})\n"
                    f"Delivery: {order['delivery_date']}\n"
                    f"Submitted: {order['submitted_at']}"
                )
                lbl = Label(
                    text=text,
                    font_size=18,
                    size_hint_y=None,
                    height=110,
                    halign='left',
                    valign='middle'
                )
                lbl.bind(size=lambda instance, value: setattr(instance, 'text_size', value))
                grid.add_widget(lbl)

        store_filter.bind(text=refresh_orders)
        date_filter.bind(text=refresh_orders)
        item_filter.bind(text=refresh_orders)

        refresh_orders()

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    # ---------------------------------------------------------
    # ADMIN DELIVERY CALENDAR
    # ---------------------------------------------------------
    def admin_calendar_screen(self):
        # refresh allowed dates
        self.load_allowed_dates_from_backend()

        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Delivery Calendar",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back to Admin Dashboard",
            font_size=22,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.admin_dashboard_screen()))
        layout.add_widget(back_btn)

        info = Label(
            text="Allowed delivery dates (next 30 days).\nTap to toggle allowed/blocked.",
            font_size=18,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(info)

        scroll = ScrollView(
            size_hint=(1, 0.55),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )
        grid = GridLayout(cols=1, spacing=8, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        today = datetime.now()
        for i in range(1, 31):
            d = today + timedelta(days=i)
            label = d.strftime("%B %d, %Y")
            allowed = (not self.allowed_dates) or (label in self.allowed_dates)
            bg = BTN_GREEN if allowed else BTN_RED

            btn = Button(
                text=label,
                size_hint_y=None,
                height=50,
                font_size=18,
                background_normal='',
                background_color=bg,
                color=(1, 1, 1, 1),
                border=(20, 20, 20, 20)
            )

            def make_toggle(date_label):
                def toggle(instance):
                    if date_label in self.allowed_dates:
                        self.allowed_dates.remove(date_label)
                    else:
                        self.allowed_dates.append(date_label)
                    self.save_allowed_dates_to_backend()
                    self.show_screen(self.admin_calendar_screen())

                return toggle

            btn.bind(on_press=make_toggle(label))
            grid.add_widget(btn)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    # ---------------------------------------------------------
    # MAIN MENU (STORE SIDE)
    # ---------------------------------------------------------
    def main_menu(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        store_name = self.current_store["store_name"] if self.current_store else "Produce Categories"
        title = Label(
            text=f"{store_name}",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        scroll = ScrollView(
            size_hint=(1, 0.55),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=12, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        for category in self.inventory.keys():
            btn = Button(
                text=category,
                font_size=24,
                size_hint_y=None,
                height=80,
                background_normal='',
                background_color=BTN_GREEN,
                color=(1, 1, 1, 1),
                border=(20, 20, 20, 20)
            )
            btn.bind(on_press=lambda instance, cat=category: self.show_screen(self.subcategory_screen(cat)))
            grid.add_widget(btn)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        bottom_row = BoxLayout(orientation='horizontal', size_hint=(1, 0.3), spacing=10)

        cart_btn = Button(
            text="View Cart",
            font_size=22,
            background_normal='',
            background_color=BTN_YELLOW,
            color=(0.2, 0.2, 0.2, 1),
            border=(20, 20, 20, 20)
        )
        cart_btn.bind(on_press=lambda instance: self.show_screen(self.cart_screen()))
        bottom_row.add_widget(cart_btn)

        history_btn = Button(
            text="Order History",
            font_size=22,
            background_normal='',
            background_color=BTN_GREEN_LIGHT,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        history_btn.bind(on_press=lambda instance: self.show_screen(self.store_history_screen()))
        bottom_row.add_widget(history_btn)

        logout_btn = Button(
            text="Logout",
            font_size=22,
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        logout_btn.bind(on_press=lambda instance: self.logout_store())
        bottom_row.add_widget(logout_btn)

        layout.add_widget(bottom_row)

        return layout

    def logout_store(self):
        self.current_store = None
        self.cart = []
        self.show_screen(self.start_screen())

    # ---------------------------------------------------------
    # STORE ORDER HISTORY
    # ---------------------------------------------------------
    def store_history_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Order History",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back",
            font_size=24,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.main_menu()))
        layout.add_widget(back_btn)

        scroll = ScrollView(
            size_hint=(1, 0.7),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=10, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        if not self.current_store:
            store_orders = []
        else:
            store_orders = self.load_store_orders_from_backend(self.current_store["id"])

        if not store_orders:
            grid.add_widget(Label(
                text="No past orders.",
                font_size=22,
                size_hint_y=None,
                height=60,
                color=(0, 0.3, 0, 1)
            ))
        else:
            for order in store_orders:
                text = (
                    f"{order['qty']} × {order['item']} ({order['category']})\n"
                    f"Delivery: {order['delivery_date']}\n"
                    f"Submitted: {order['submitted_at']}"
                )
                lbl = Label(
                    text=text,
                    font_size=18,
                    size_hint_y=None,
                    height=100,
                    halign='left',
                    valign='middle'
                )
                lbl.bind(size=lambda instance, value: setattr(instance, 'text_size', value))
                grid.add_widget(lbl)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    # ---------------------------------------------------------
    # SUBCATEGORY SCREEN
    # ---------------------------------------------------------
    def subcategory_screen(self, category):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text=category,
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back",
            font_size=24,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.main_menu()))
        layout.add_widget(back_btn)

        scroll = ScrollView(
            size_hint=(1, 0.7),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=12, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        for item_name, data in self.inventory[category].items():
            available = data["qty"]
            btn = Button(
                text=f"{item_name} (Available: {available})",
                font_size=22,
                size_hint_y=None,
                height=70,
                background_normal='',
                background_color=BTN_GREEN_LIGHT,
                color=(1, 1, 1, 1),
                border=(20, 20, 20, 20)
            )
            btn.bind(on_press=lambda instance, cat=category, item=item_name: self.open_quantity_selector(cat, item))
            grid.add_widget(btn)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        return layout

    # ---------------------------------------------------------
    # DATE PICKER POPUP (RESPECTS ALLOWED DATES)
    # ---------------------------------------------------------
    def open_date_picker(self, callback):
        popup = Popup(title="Select Delivery Date", size_hint=(0.85, 0.8))

        outer = BoxLayout(orientation='vertical', spacing=10, padding=10)

        back_btn = Button(
            text="← Back",
            font_size=22,
            size_hint=(1, None),
            height=60,
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: popup.dismiss())
        outer.add_widget(back_btn)

        scroll = ScrollView(
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        layout = GridLayout(cols=1, spacing=12, size_hint_y=None, padding=20)
        layout.bind(minimum_height=layout.setter('height'))

        today = datetime.now()
        date_options = [
            (today + timedelta(days=i)).strftime("%B %d, %Y")
            for i in range(1, 15)
        ]

        for d in date_options:
            if self.allowed_dates and d not in self.allowed_dates:
                continue

            btn = Button(
                text=d,
                size_hint_y=None,
                height=60,
                font_size=22,
                background_normal='',
                background_color=BTN_YELLOW,
                color=(0.2, 0.2, 0.2, 1),
                border=(20, 20, 20, 20)
            )
            btn.bind(on_press=lambda instance, date=d: (callback(date), popup.dismiss()))
            layout.add_widget(btn)

        if len(layout.children) == 0:
            layout.add_widget(Label(
                text="No delivery dates available.\nAsk admin to update calendar.",
                font_size=20,
                size_hint_y=None,
                height=80,
                color=(0, 0.3, 0, 1)
            ))

        scroll.add_widget(layout)
        outer.add_widget(scroll)

        popup.content = outer
        popup.open()

    # ---------------------------------------------------------
    # QUANTITY SELECTOR POPUP (WITH IMAGE)
    # ---------------------------------------------------------
    def open_quantity_selector(self, category, item):
        outer = BoxLayout(orientation='vertical', padding=10, spacing=10)

        scroll = ScrollView(
            size_hint=(1, 1),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        content = BoxLayout(orientation='vertical', padding=20, spacing=15, size_hint_y=None)
        content.bind(minimum_height=content.setter('height'))

        popup = Popup(title="Select Quantity", size_hint=(0.85, 0.8))

        back_btn = Button(
            text="← Back",
            font_size=22,
            size_hint=(1, None),
            height=60,
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: popup.dismiss())
        content.add_widget(back_btn)

        img_path = self.inventory[category][item].get("image", "")
        img = Image(source=img_path, size_hint=(1, None), height=150, allow_stretch=True, keep_ratio=True)
        content.add_widget(img)

        title = Label(
            text=item,
            font_size=26,
            size_hint=(1, None),
            height=60,
            color=CYAN_TEXT
        )
        content.add_widget(title)

        available_label = Label(
            text=f"Available: {self.inventory[category][item]['qty']}",
            font_size=20,
            size_hint=(1, None),
            height=40,
            color=CYAN_TEXT
        )
        content.add_widget(available_label)

        qty_layout = GridLayout(cols=5, spacing=10, size_hint=(1, None), height=80)

        minus10 = Button(text="-10", font_size=24, background_normal='', background_color=BTN_GREEN)
        minus1 = Button(text="-1", font_size=32, background_normal='', background_color=BTN_GREEN)
        qty_label = Label(text="1", font_size=32, color=CYAN_TEXT)
        plus1 = Button(text="+1", font_size=32, background_normal='', background_color=BTN_GREEN)
        plus10 = Button(text="+10", font_size=24, background_normal='', background_color=BTN_GREEN)

        max_qty = self.inventory[category][item]["qty"]

        def change_qty(amount):
            current = int(qty_label.text)
            new = max(1, min(max_qty, current + amount))
            qty_label.text = str(new)

        minus10.bind(on_press=lambda instance: change_qty(-10))
        minus1.bind(on_press=lambda instance: change_qty(-1))
        plus1.bind(on_press=lambda instance: change_qty(1))
        plus10.bind(on_press=lambda instance: change_qty(10))

        qty_layout.add_widget(minus10)
        qty_layout.add_widget(minus1)
        qty_layout.add_widget(qty_label)
        qty_layout.add_widget(plus1)
        qty_layout.add_widget(plus10)

        content.add_widget(qty_layout)

        date_label = Label(
            text="Delivery Date:",
            font_size=22,
            size_hint=(1, None),
            height=40,
            color=CYAN_TEXT
        )
        content.add_widget(date_label)

        date_btn = Button(
            text="Select Date",
            font_size=22,
            size_hint=(1, None),
            height=60,
            background_normal='',
            background_color=BTN_YELLOW,
            color=(0.2, 0.2, 0.2, 1),
            border=(20, 20, 20, 20)
        )
        content.add_widget(date_btn)

        selected_date = {"value": None}
        default_date = (datetime.now() + timedelta(days=1)).strftime("%B %d, %Y")
        selected_date["value"] = default_date
        date_btn.text = default_date

        def set_date(d):
            selected_date["value"] = d
            date_btn.text = d

        date_btn.bind(on_press=lambda instance: self.open_date_picker(set_date))

        add_btn = Button(
            text="Add to Cart",
            font_size=24,
            size_hint=(1, None),
            height=70,
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )

        def add_to_cart(instance):
            qty = int(qty_label.text)
            available = self.inventory[category][item]["qty"]

            if qty > available:
                qty = available

            if qty <= 0:
                Popup(
                    title="Out of Stock",
                    content=Label(text="No inventory remaining for this item."),
                    size_hint=(0.6, 0.4)
                ).open()
                popup.dismiss()
                return

            delivery_date = selected_date["value"]

            self.cart.append({
                "category": category,
                "item": item,
                "qty": qty,
                "delivery_date": delivery_date
            })

            self.inventory[category][item]["qty"] -= qty

            popup.dismiss()

            Popup(
                title="Added to Cart",
                content=Label(text=f"{qty} × {item}\nDelivery: {delivery_date}", font_size=20),
                size_hint=(0.6, 0.4)
            ).open()

        add_btn.bind(on_press=add_to_cart)
        content.add_widget(add_btn)

        scroll.add_widget(content)
        outer.add_widget(scroll)
        popup.content = outer
        popup.open()

    # ---------------------------------------------------------
    # CART SCREEN
    # ---------------------------------------------------------
    def cart_screen(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        title = Label(
            text="Cart",
            font_size=32,
            size_hint=(1, 0.15),
            color=(0, 0.3, 0, 1)
        )
        layout.add_widget(title)

        back_btn = Button(
            text="← Back to Categories",
            font_size=24,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_RED,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        back_btn.bind(on_press=lambda instance: self.show_screen(self.main_menu()))
        layout.add_widget(back_btn)

        scroll = ScrollView(
            size_hint=(1, 0.55),
            bar_width=20,
            scroll_type=['bars', 'content'],
            bar_color=SCROLL_GREEN,
            bar_inactive_color=SCROLL_GREEN
        )

        grid = GridLayout(cols=1, spacing=10, size_hint_y=None, padding=10)
        grid.bind(minimum_height=grid.setter('height'))

        if not self.cart:
            grid.add_widget(Label(
                text="Your cart is empty.",
                font_size=22,
                size_hint_y=None,
                height=60,
                color=(0, 0.3, 0, 1)
            ))
        else:
            for index, entry in enumerate(self.cart):
                row = BoxLayout(orientation='horizontal', size_hint_y=None, height=80, spacing=10)

                info = Label(
                    text=f"{entry['qty']} × {entry['item']}\n{entry['category']} • {entry['delivery_date']}",
                    font_size=18,
                    halign='left',
                    valign='middle'
                )
                info.bind(size=lambda instance, value: setattr(instance, 'text_size', value))

                remove_btn = Button(
                    text="Remove",
                    font_size=18,
                    size_hint=(0.25, 1),
                    background_normal='',
                    background_color=BTN_RED,
                    color=(1, 1, 1, 1),
                    border=(20, 20, 20, 20)
                )
                remove_btn.bind(on_press=lambda instance, idx=index: self.remove_from_cart(idx))

                row.add_widget(info)
                row.add_widget(remove_btn)
                grid.add_widget(row)

        scroll.add_widget(grid)
        layout.add_widget(scroll)

        submit_btn = Button(
            text="Submit Order",
            font_size=24,
            size_hint=(1, 0.15),
            background_normal='',
            background_color=BTN_GREEN,
            color=(1, 1, 1, 1),
            border=(20, 20, 20, 20)
        )
        submit_btn.bind(on_press=self.submit_order)
        layout.add_widget(submit_btn)

        return layout

    def remove_from_cart(self, index):
        if 0 <= index < len(self.cart):
            entry = self.cart.pop(index)
            self.inventory[entry["category"]][entry["item"]]["qty"] += entry["qty"]

        self.show_screen(self.cart_screen())

    def submit_order(self, instance):
        if not self.cart:
            Popup(
                title="Cart Empty",
                content=Label(text="There are no items to submit.", font_size=20),
                size_hint=(0.6, 0.4)
            ).open()
            return

        if not self.current_store:
            Popup(
                title="Error",
                content=Label(text="No store logged in.", font_size=20),
                size_hint=(0.6, 0.4)
            ).open()
            return

        store_id = self.current_store["id"]
        submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M")

        payload = []
        for entry in self.cart:
            payload.append({
                "store_id": store_id,
                "category": entry["category"],
                "item": entry["item"],
                "qty": entry["qty"],
                "delivery_date": entry["delivery_date"],
                "submitted_at": submitted_at
            })

        try:
            resp = requests.post(f"{API_URL}/orders/submit", json=payload)
            if resp.status_code == 200:
                summary = "\n\n".join(
                    f"{e['qty']} × {e['item']} ({e['category']})\nDelivery: {e['delivery_date']}"
                    for e in self.cart
                )
                Popup(
                    title="Order Submitted",
                    content=Label(text=summary, font_size=18),
                    size_hint=(0.8, 0.8)
                ).open()
                self.cart.clear()
                self.load_all_orders_from_backend()
                self.show_screen(self.main_menu())
                return
        except Exception as e:
            print("Order submit error:", e)

        Popup(
            title="Error",
            content=Label(text="Could not submit order.", font_size=20),
            size_hint=(0.6, 0.4)
        ).open()


if __name__ == "__main__":
    ProduceApp().run()
