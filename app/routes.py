from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta

from app.config import PUBLIC_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES
from app.models import Token, User
from app.auth import authenticate_user, get_current_user
from app.security import create_token, get_password_hash
from app.db import fake_users_db, revoked_tokens, used_refresh_tokens
from app.logging_config import logger
from app.limiter import limiter

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register")
@limiter.limit("5/minute")
def register(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username in fake_users_db:
        logger.info("Registration attempt for existing user: %s", form_data.username)
        raise HTTPException(status_code=400, detail="User already exists")
    fake_users_db[form_data.username] = {"username": form_data.username, "full_name": form_data.username,
        "hashed_password": get_password_hash(form_data.password), "disabled": False}
    logger.info("New user registered: %s", form_data.username)
    return {"msg": "User created"}


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning("Failed login attempt: %s", form_data.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": user.username, "scope": "refresh_token"},
        timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    logger.info("User logged in: %s", user.username)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
@limiter.limit("5/minute")
def refresh_token(request: Request, token: str = Depends(oauth2_scheme)):
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            raise HTTPException(status_code=401, detail="Invalid signing algorithm")

        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "refresh_token":
            raise HTTPException(status_code=401, detail="Invalid scope for refresh")
        if token in used_refresh_tokens:
            raise HTTPException(status_code=401, detail="Token already used")

        used_refresh_tokens.add(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token subject")

    except JWTError as e:
        logger.error("Refresh token invalid: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

    new_access_token = create_token({"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    new_refresh_token = create_token({"sub": username, "scope": "refresh_token"},
        timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    logger.info("Token refreshed for user: %s", username)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


@router.post("/logout")
@limiter.limit("5/minute")
def logout(request: Request, token: str = Depends(oauth2_scheme)):
    if token in revoked_tokens or token in used_refresh_tokens:
        logger.warning("Attempt to reuse a revoked or used token")
        raise HTTPException(status_code=401, detail="Token already used or revoked")

    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            raise HTTPException(status_code=401, detail="Invalid signing algorithm")

        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "refresh_token":
            raise HTTPException(status_code=400, detail="Only refresh tokens can be revoked")
    except JWTError as e:
        logger.error("Invalid token on logout: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

    revoked_tokens.add(token)
    used_refresh_tokens.add(token)
    logger.info("Token revoked: %s", token)
    return {"msg": "Token revoked"}


@router.get("/protected")
@limiter.limit("5/minute")
def protected_route(request: Request, current_user: User = Depends(get_current_user)):
    logger.info("Protected route accessed by user: %s", current_user.username)
    return {"msg": f"Hello, {current_user.username}. You're authenticated."}
