from pydantic import BaseModel
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

class Settings(BaseModel):
    authjwt_secret_key: str = 'c27ef4b9f6e485e5865f5de8edca3d5cfb345f7be9f4e535c7e529ebeefaf2a6'

class LoginModel(BaseModel):
    username: str
    password: str


