import re

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

LANGUAGE_PATTERN = re.compile(r"^[a-z]{2}-[A-Z]{2}(,[a-z]{2}-[A-Z]{2}(;q=\d(\.\d+)?)?)*$")


@app.get("/headers")
def read_headers(request: Request):
    user_agent = request.headers.get("User-Agent")
    accept_language = request.headers.get("Accept-Language")

    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Missing required headers")

    if not LANGUAGE_PATTERN.match(accept_language):
        raise HTTPException(status_code=400, detail="Invalid Accept-Language format")

    return {"User-Agent": user_agent, "Accept-Language": accept_language}

