import uuid

from fastapi import FastAPI, HTTPException, Request, Response, status
from itsdangerous import BadSignature, Signer
from pydantic import BaseModel

app = FastAPI()

SECRET_KEY = "super-secret-key"
signer = Signer(SECRET_KEY)

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


@app.post("/login")
def login(data: LoginRequest, response: Response):
    user = fake_users_db.get(data.username)
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = user["id"]
    signed_value = signer.sign(user_id.encode()).decode()

    response.set_cookie(key="session_token", value=signed_value, httponly=True, max_age=3600)
    return {"message": "Logged in"}


@app.get("/profile")
def profile(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    try:
        user_id = signer.unsign(session_token.encode()).decode()
    except BadSignature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    user = None
    for u in fake_users_db.values():
        if u["id"] == user_id:
            user = u
            break

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    return {"id": user["id"], "username": user["username"], "email": user["email"]}

