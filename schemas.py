# schemas.py
from typing import Optional, List
from pydantic import BaseModel


class InventoryBase(BaseModel):
    category: str
    item: str
    qty: int


class InventoryCreate(InventoryBase):
    pass


class InventoryUpdate(BaseModel):
    qty: int


class InventoryOut(InventoryBase):
    id: int

    class Config:
        from_attributes = True


class OrderBase(BaseModel):
    store_name: str
    category: str
    item: str
    qty: int
    delivery_date: str
    submitted_at: str


class OrderCreate(OrderBase):
    pass


class OrderOut(OrderBase):
    id: int

    class Config:
        from_attributes = True


class SettingBase(BaseModel):
    key: str
    value: str


class SettingOut(SettingBase):
    class Config:
        from_attributes = True


class AllowedDatesUpdate(BaseModel):
    dates: List[str]
