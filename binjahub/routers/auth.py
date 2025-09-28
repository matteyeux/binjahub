import jwt
import time
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from pydantic import BaseModel
from fastapi import HTTPException, Depends, APIRouter

from binjahub.auth import jwt_secret, ldap_connect, uses_auth


class Token(BaseModel):
    access_token: str


router = APIRouter()


@router.post("/login", tags=["auth"], response_model=Token)
def login(data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    if not uses_auth():
        raise HTTPException(status_code=404, detail="page not found")
    conn = ldap_connect(data.username, data.password)
    if not conn:
        raise HTTPException(status_code=401, detail="invalid credentials")
    # 10 minute token, may be increased if databases get very large when uploading/downloading
    payload = {"sub": data.username, "exp": int(time.time()) + 60 * 10}
    token = jwt.encode(payload=payload, key=jwt_secret())
    return {"access_token": token}


@router.get("/auth-required", tags=["auth"])
def auth_required():
    if uses_auth():
        return {"auth_required": True}
    return {"auth_required": False}
