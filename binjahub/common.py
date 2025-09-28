from typing import Annotated

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from binjahub.auth import jwt_secret, uses_auth

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
