from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
import uuid
from app.config import ALGORITHM, PRIVATE_KEY

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    to_encode.update(
        {"exp": datetime.utcnow() + expires_delta, "iat": datetime.utcnow(), "nbf": datetime.utcnow(), "jti": jti})
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
