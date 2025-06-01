from fastapi.testclient import TestClient
from datetime import timedelta

from app.main import app
from app.security import create_token, get_password_hash
from app.db import fake_users_db, revoked_tokens, used_refresh_tokens

client = TestClient(app)


def test_register_and_login():
    fake_users_db.clear()
    payload = {"username": "testuser", "password": "secret"}

    res = client.post("/register", data=payload)
    assert res.status_code == 200

    res = client.post("/login", data=payload)
    assert res.status_code == 200
    assert "access_token" in res.json()
    assert "refresh_token" in res.json()


def test_protected_with_valid_token():
    fake_users_db["validuser"] = {
        "username": "validuser",
        "full_name": "validuser",
        "hashed_password": get_password_hash("1234"),
        "disabled": False
    }
    token = create_token({"sub": "validuser"}, timedelta(minutes=5))
    res = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200


def test_protected_with_revoked_token():
    token = create_token({"sub": "revokeduser"}, timedelta(minutes=5))
    revoked_tokens.add(token)
    res = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Token revoked"


def test_refresh_token_twice():
    token = create_token({"sub": "refresher", "scope": "refresh_token"}, timedelta(minutes=5))

    res1 = client.post("/refresh", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200

    res2 = client.post("/refresh", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Token already used"


def test_logout_revokes_token():
    token = create_token({"sub": "logoutuser", "scope": "refresh_token"}, timedelta(minutes=5))
    res = client.post("/logout", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert token in revoked_tokens
    assert token in used_refresh_tokens


def test_logout_with_used_token():
    token = create_token({"sub": "useduser", "scope": "refresh_token"}, timedelta(minutes=5))
    used_refresh_tokens.add(token)
    res = client.post("/logout", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Token already used or revoked"
