import glob
import os
from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import UploadFile, File, Response
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/bndb", tags=["bndb"])
async def list_bndbs():
    """Route to list BNDBs."""
    files = [os.path.basename(x) for x in glob.glob('BNDB/*')]
    return {
        "files": files,
    }


@router.post("/bndb", tags=["bndb"])
def upload_bndb(file: UploadFile = File(...)):
    with open(file.filename, "wb") as buffer:
        buffer.write(file.read())

    return {"filename": file.filename}

@router.get("/bndb/{filename}", tags=["bndb"])
def download_bndb(filename: str):
    # TODO check if file exits
    return FileResponse(f"BNDB/{filename}")
