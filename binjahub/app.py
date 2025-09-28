"""Main app module to initialize the FastAPI framework."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from binjahub.auth import ldap_connect, uses_auth
from binjahub.routers import auth, bndb


@asynccontextmanager
async def lifespan(app: FastAPI):
    if uses_auth():
        ldap_conn = ldap_connect()
        if not ldap_conn:
            print("[!]\t\tUnable to establish connection to LDAP server!")
    os.makedirs("./BNDB", exist_ok=True)
    yield


app = FastAPI(lifespan=lifespan)


app.include_router(bndb.router)
app.include_router(auth.router)


@app.get("/")
def read_root():
    """Default root."""
    return {"message": "bro"}
