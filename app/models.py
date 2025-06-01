from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = False


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
