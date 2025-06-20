from typing import Set
from pydantic import BaseModel, Field
from typing import Optional


class SignUpModel(BaseModel):
    username: str
    email: str
    password: str
    is_staff: Optional[bool]
    is_active: Optional[bool]

    class Config:
        from_attributes = True
        json_schema_extra = {
            'example': {
                "username": "abcd",
                "email": "abcd@gmail.com",
                "password": "password",
                "is_staff": False,
                "is_active": True
            }
        }


class UserResponseModel(BaseModel):
    username: str
    email: str
    is_staff: Optional[bool]
    is_active: Optional[bool]

    class Config:
        from_attributes = True
        json_schema_extra = {
            'example': {
                "username": "abcd",
                "email": "abcd@gmail.com",
                "is_staff": False,
                "is_active": True
            }
        }

class Settings(BaseModel):
    authjwt_secret_key: str = 'c27ef4b9f6e485e5865f5de8edca3d5cfb345f7be9f4e535c7e529ebeefaf2a6'
    authjwt_token_location: Set[str] = Field(default_factory=lambda: {'headers'})
    authjwt_access_token_expires: int = 3600  # 1 hour
    authjwt_refresh_token_expires: int = 86400  # 24 hours
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: Set[str] = Field(default_factory=lambda: {'access', 'refresh'})
    authjwt_cookie_csrf_protect: bool = False  # Disable if not using cookies

class LoginModel(BaseModel):
    username: str
    password: str

class OrderModel(BaseModel):
    id: Optional[int]
    quantity : int
    order_status: Optional[str] = "PENDING"
    pizza_size: Optional[str] = "SMALL"
    user_id: Optional[int]

    class Config:
        orm_mode= True
        schema_extra = {
            "example": {
                "quantity": 2,
                "pizza_size": "LARGE"
            }
        }

class OrderStatusModel(BaseModel):
    order_status: Optional[str] = "PENDING"

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "order_status": "PENDING"
            }
        }
