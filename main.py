from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field, field_validator


app = FastAPI(title="KR2 FastAPI")


# ===== Задание 3.1 =====
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1)
    email: EmailStr
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = None


@app.post("/create_user")
def create_user(user: UserCreate):
    return user


# ===== Задание 3.2 =====
sample_products = [
    {
        "product_id": 123,
        "name": "Smartphone",
        "category": "Electronics",
        "price": 599.99,
    },
    {
        "product_id": 456,
        "name": "Phone Case",
        "category": "Accessories",
        "price": 19.99,
    },
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]


@app.get("/product/{product_id}")
def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/search")
def search_products(keyword: str, category: Optional[str] = None, limit: int = 10):
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit must be > 0")

    keyword_lc = keyword.lower()
    filtered = [p for p in sample_products if keyword_lc in p["name"].lower()]

    if category:
        filtered = [p for p in filtered if p["category"].lower() == category.lower()]

    return filtered[:limit]


class LoginInput(BaseModel):
    username: str
    password: str


VALID_USERS = {
    "user123": {
        "password": "password123",
        "user_id": str(uuid4()),
        "full_name": "User 123",
    }
}

SESSION_MAX_AGE_SECONDS = 300
SESSION_REFRESH_THRESHOLD_SECONDS = 180
COOKIE_NAME = "session_token"
SECRET_KEY = "very-secret-key-change-me"


# ===== Задания 5.1, 5.2, 5.3 =====
def _sign_payload(user_id: str, ts: int) -> str:
    from itsdangerous import Signer

    signer = Signer(SECRET_KEY)
    value = f"{user_id}.{ts}"
    return signer.sign(value.encode("utf-8")).decode("utf-8")


def _verify_and_parse_session(token: str) -> tuple[str, int]:
    from itsdangerous import BadSignature, Signer

    signer = Signer(SECRET_KEY)
    try:
        unsigned = signer.unsign(token.encode("utf-8")).decode("utf-8")
    except BadSignature as exc:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"}) from exc

    parts = unsigned.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})

    user_id, ts_raw = parts
    try:
        UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"}) from exc

    if not ts_raw.isdigit():
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})
    ts = int(ts_raw)
    return user_id, ts


def _set_session_cookie(response: Response, user_id: str, timestamp: int) -> None:
    signed = _sign_payload(user_id, timestamp)
    response.set_cookie(
        key=COOKIE_NAME,
        value=signed,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE_SECONDS,
    )


@app.post("/login")
def login(payload: LoginInput, response: Response):
    user = VALID_USERS.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    _set_session_cookie(response, user["user_id"], now_ts)

    return {
        "message": "Logged in successfully",
        "user_id": user["user_id"],
    }


def _get_authorized_user(request: Request, response: Response) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})

    user_id, last_activity_ts = _verify_and_parse_session(token)
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    elapsed = now_ts - last_activity_ts

    if elapsed > SESSION_MAX_AGE_SECONDS:
        raise HTTPException(status_code=401, detail={"message": "Session expired"})

    if SESSION_REFRESH_THRESHOLD_SECONDS <= elapsed < SESSION_MAX_AGE_SECONDS:
        _set_session_cookie(response, user_id, now_ts)

    for username, data in VALID_USERS.items():
        if data["user_id"] == user_id:
            return {
                "username": username,
                "user_id": user_id,
                "full_name": data["full_name"],
            }

    raise HTTPException(status_code=401, detail={"message": "Unauthorized"})


@app.get("/user")
def get_user_profile(request: Request, response: Response):
    return _get_authorized_user(request, response)


@app.get("/profile")
def get_profile(request: Request, response: Response):
    return _get_authorized_user(request, response)


# ===== Задания 5.4, 5.5 =====
class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, value: str) -> str:
        pattern = r"^[a-zA-Z]{2,3}(?:-[a-zA-Z]{2,4})?(?:,\s*[a-zA-Z]{2,3}(?:-[a-zA-Z]{2,4})?(?:;q=(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?))?)*$"
        if not re.match(pattern, value):
            raise ValueError("Invalid Accept-Language format")
        return value


def get_common_headers(
    user_agent: Optional[str] = Header(default=None),
    accept_language: Optional[str] = Header(default=None),
) -> CommonHeaders:
    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Missing required headers")

    try:
        return CommonHeaders(user_agent=user_agent, accept_language=accept_language)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Accept-Language format") from exc


@app.get("/headers")
def read_headers(common: CommonHeaders = Depends(get_common_headers)):
    return {
        "User-Agent": common.user_agent,
        "Accept-Language": common.accept_language,
    }


@app.get("/info")
def info(response: Response, common: CommonHeaders = Depends(get_common_headers)):
    response.headers["X-Server-Time"] = datetime.now(tz=timezone.utc).replace(
        microsecond=0
    ).isoformat()
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": common.user_agent,
            "Accept-Language": common.accept_language,
        },
    }
