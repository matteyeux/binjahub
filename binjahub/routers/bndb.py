import glob
import os
from fastapi import APIRouter
from fastapi import HTTPException


router = APIRouter()

@router.get("/bndb", tags=["bndb"])
async def list_bndbs():
    """Route to list BNDBs."""
    files = [os.path.basename(x) for x in glob.glob('BNDB/*')]
    return {
        "files": files,
    }


@router.get("/bndb/{bndb}", tags=["bndb"])
async def get_bndb(bndb: str = None):
    """Route to bndb A12 AP kbag."""
    return {
        "kbag": "kbag",
        "key": "key",
    }

