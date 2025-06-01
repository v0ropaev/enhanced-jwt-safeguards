from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from app.db import fake_users_db, revoked_tokens
from app.models import UserInDB, User
from app.security import verify_password
from app.config import PUBLIC_KEY, ALGORITHM
from app.logging_config import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_user(username: str):
    user = fake_users_db.get(username)
    if user:
        return UserInDB(**user)
    return None


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    if token in revoked_tokens:
        logger.warning("Attempt to use revoked token")
        raise HTTPException(status_code=401, detail="Token revoked")

    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            logger.error("Invalid signing algorithm: %s", header.get("alg"))
            raise HTTPException(status_code=401, detail="Invalid signing algorithm")

        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            logger.error("Token missing subject (sub)")
            raise HTTPException(status_code=401, detail="Invalid subject")
    except JWTError as e:
        logger.error("JWT validation failed: %s", str(e))
        raise HTTPException(status_code=401, detail="Token validation error")

    user = get_user(username)
    if not user:
        logger.warning("User from token not found: %s", username)
        raise HTTPException(status_code=404, detail="User not found")
    return user
