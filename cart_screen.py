# screens/cart_screen.py
from kivy.uix.screenmanager import Screen
from kivy.properties import ObjectProperty


class CartScreen(Screen):
    cart = ObjectProperty(None)

    def on_pre_enter(self):
        self.build_cart_list()

    def build_cart_list(self):
        container = self.ids.cart_list
        container.clear_widgets()

        total_items = 0

        for item, qty in self.cart.items():
            total_items += qty

            from kivy.uix.boxlayout import BoxLayout
            from kivy.uix.label import Label
            from kivy.uix.button import Button

            row = BoxLayout(size_hint_y=None, height=50, spacing=10)
            row.add_widget(Label(text=f"{item}", size_hint_x=0.6))
            row.add_widget(Label(text=f"{qty}", size_hint_x=0.2))

            remove_btn = Button(text="Remove", size_hint_x=0.2)
            remove_btn.bind(on_release=lambda x, i=item: self.remove_item(i))
            row.add_widget(remove_btn)

            container.add_widget(row)

        self.ids.total_label.text = f"Total Items: {total_items}"

    def remove_item(self, item):
        if item in self.cart:
            del self.cart[item]
        self.build_cart_list()

    def go_checkout(self):
        checkout = self.manager.get_screen("checkout")
        checkout.cart = self.cart
        self.manager.current = "checkout"
