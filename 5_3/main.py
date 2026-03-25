import base64
import hashlib
import hmac
import time
import uuid

from fastapi import FastAPI, Response, Request, status
from pydantic import BaseModel

app = FastAPI()

SECRET_KEY = "super-secret-key"

SESSION_MAX_AGE = 300
SESSION_RENEW_THRESHOLD = 180

fake_users_db = {
    "user123": {
        "id": str(uuid.uuid4()),
        "username": "user123",
        "password": "password123",
        "email": "user123@example.com",
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _sign(user_id: str, ts: int) -> str:
    msg = f"{user_id}.{ts}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), msg, hashlib.sha256).digest()
    return _b64url(sig)


def create_session_cookie(user_id: str) -> str:
    ts = int(time.time())
    sig = _sign(user_id, ts)
    return f"{user_id}.{ts}.{sig}"


def parse_session_cookie(cookie_value: str):
    parts = cookie_value.split(".")
    if len(parts) != 3:
        return None, None
    user_id, ts_raw, sig = parts
    if not ts_raw.isdigit():
        return None, None
    ts = int(ts_raw)
    expected = _sign(user_id, ts)
    if not hmac.compare_digest(expected, sig):
        return None, None
    return user_id, ts


@app.post("/login")
def login(data: LoginRequest, response: Response):
    user = fake_users_db.get(data.username)
    if not user or user["password"] != data.password:
        response.status_code = 401
        return {"message": "Invalid credentials"}

    cookie_value = create_session_cookie(user["id"])
    response.set_cookie(
        key="session_token",
        value=cookie_value,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE,
    )
    return {"message": "Logged in"}


@app.get("/profile")
def profile(request: Request, response: Response):
    cookie = request.cookies.get("session_token")
    if not cookie:
        response.status_code = 401
        return {"message": "Session expired"}

    user_id, last_activity = parse_session_cookie(cookie)
    if not user_id or not last_activity:
        response.status_code = 401
        return {"message": "Invalid session"}

    now = int(time.time())
    elapsed = now - last_activity

    if elapsed >= SESSION_MAX_AGE:
        response.status_code = 401
        return {"message": "Session expired"}

    if SESSION_RENEW_THRESHOLD <= elapsed < SESSION_MAX_AGE:
        new_cookie = create_session_cookie(user_id)
        response.set_cookie(
            key="session_token",
            value=new_cookie,
            httponly=True,
            secure=False,
            max_age=SESSION_MAX_AGE,
        )

    user = None
    for u in fake_users_db.values():
        if u["id"] == user_id:
            user = u
            break

    if not user:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Invalid session"}

    return {"id": user["id"], "username": user["username"], "email": user["email"]}

