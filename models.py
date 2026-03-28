# models.py
from sqlalchemy import Column, Integer, String, Text
from database import Base


class Inventory(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, index=True)
    item = Column(String, index=True)
    qty = Column(Integer)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    store_name = Column(String, index=True)
    category = Column(String)
    item = Column(String)
    qty = Column(Integer)
    delivery_date = Column(String)
    submitted_at = Column(String, index=True)
    ordered_by = Column(String, nullable=True)


class Store(Base):
    __tablename__ = "stores"

    id = Column(Integer, primary_key=True, index=True)
    store_name = Column(String, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    email = Column(String, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(Text)
