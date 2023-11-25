import glob
import os
from pathlib import Path
import time
from fastapi import APIRouter, HTTPException, Depends
from fastapi import UploadFile, File
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated

import jwt
from pydantic import BaseModel

from binjahub.auth import jwt_secret, ldap_connect, uses_auth

router = APIRouter()


class Token(BaseModel):
    access_token: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def authenticated():
    if not uses_auth():
        return lambda: None

    async def _authenticated(token: Annotated[str, Depends(oauth2_scheme)]):
        try:
            payload = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
            return payload["sub"]
        except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.DecodeError):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    return _authenticated


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


@router.get("/bndb", tags=["bndb"])
def list_bndbs(user: Annotated[str, Depends(authenticated())]):
    """Route to list BNDBs."""
    files = {}
    for file in glob.glob("BNDB/*"):
        f = Path(file)
        filesize = (f.stat().st_size) / (1024 * 1024)
        files[os.path.basename(file)] = f"{filesize:.2f} MB"
    return files


@router.post("/bndb", tags=["bndb"])
async def upload_bndb(
    user: Annotated[str, Depends(authenticated())], file: UploadFile = File(...)
):
    with open(f"BNDB/{file.filename}", "wb") as buffer:
        buffer.write(await file.read())
    return {"filename": file.filename}


@router.get("/bndb/{filename}", tags=["bndb"])
def download_bndb(user: Annotated[str, Depends(authenticated())], filename: str):
    if not os.path.exists(os.path.join("BNDB", filename.strip(os.path.sep))):
        raise HTTPException(status_code=404, detail="BNDB not found")
    return FileResponse(f"BNDB/{filename}")
