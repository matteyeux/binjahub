"""Main app module to initialize the FastAPI framework."""
from fastapi import FastAPI
from binjahub.routers import bndb

app = FastAPI()

app.include_router(bndb.router, tags=["bndb"])


@app.get("/")
def read_root():
    """Default root."""
    return {"message": "bro"}
