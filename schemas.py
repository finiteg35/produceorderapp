# schemas.py
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


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

    model_config = ConfigDict(from_attributes=True)


class OrderBase(BaseModel):
    store_name: str
    category: str
    item: str
    qty: int
    delivery_date: str
    submitted_at: str
    ordered_by: Optional[str] = None


class OrderCreate(OrderBase):
    pass


class OrderOut(OrderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class SettingBase(BaseModel):
    key: str
    value: str


class SettingOut(SettingBase):
    model_config = ConfigDict(from_attributes=True)


class AllowedDatesUpdate(BaseModel):
    dates: List[str]


class StoreCreate(BaseModel):
    store_name: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=6, max_length=128)
    email: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=6, max_length=128)


class StoreOut(BaseModel):
    id: int
    store_name: str
    username: str
    email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str


class StoreLoginResponse(BaseModel):
    store_id: int
    store_name: str
    email: Optional[str] = None


class OrderSubmitItem(BaseModel):
    store_id: int
    category: str
    item: str
    qty: int
    delivery_date: str
    submitted_at: str
    ordered_by: Optional[str] = None
