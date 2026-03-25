import uuid

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel

app = FastAPI()

fake_users_db = {
    "user123": {"username": "user123", "password": "password123", "email": "user123@example.com"}
}

sessions: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(data: LoginRequest, response: Response):
    user = fake_users_db.get(data.username)
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_token = str(uuid.uuid4())
    sessions[session_token] = user["username"]

    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=False)
    return {"message": "Logged in successfully"}


@app.get("/user")
def get_user(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token or session_token not in sessions:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    username = sessions[session_token]
    user = fake_users_db.get(username)
    return {"username": user["username"], "email": user["email"]}

