import re
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, validator

app = FastAPI()

LANGUAGE_PATTERN = re.compile(r"^[a-z]{2}-[A-Z]{2}(,[a-z]{2}-[A-Z]{2}(;q=\d(\.\d+)?)?)*$")


class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @validator("accept_language")
    def validate_accept_language(cls, v):
        if not LANGUAGE_PATTERN.match(v):
            raise HTTPException(status_code=400, detail="Invalid Accept-Language format")
        return v

    @classmethod
    def from_headers(
        cls,
        user_agent: str = Header(...),
        accept_language: str = Header(...),
    ):
        return cls(user_agent=user_agent, accept_language=accept_language)


@app.get("/headers")
def get_headers(headers: CommonHeaders = CommonHeaders.from_headers()):
    return {"User-Agent": headers.user_agent, "Accept-Language": headers.accept_language}


@app.get("/info")
def get_info(headers: CommonHeaders = CommonHeaders.from_headers(), response: Response = None):
    response.headers["X-Server-Time"] = datetime.utcnow().isoformat()
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {"User-Agent": headers.user_agent, "Accept-Language": headers.accept_language},
    }

