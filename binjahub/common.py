import jwt
from binjahub.auth import jwt_secret, uses_auth
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, Depends

from typing import Annotated

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
