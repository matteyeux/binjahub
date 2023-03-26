import glob
import os
from pathlib import Path
from fastapi import APIRouter
from fastapi import UploadFile, File
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/bndb", tags=["bndb"])
def list_bndbs():
    """Route to list BNDBs."""
    files = {}
    for file in glob.glob('BNDB/*'):
        f = Path(file)
        filesize = (f.stat().st_size) / (1024 * 1024)
        files[os.path.basename(file)] = f"{filesize:.2f} MB"
    return files


@router.post("/bndb", tags=["bndb"])
async def upload_bndb(file: UploadFile = File(...)):
    with open(f"BNDB/{file.filename}", "wb") as buffer:
        buffer.write(await file.read())
    return {"filename": file.filename}


@router.get("/bndb/{filename}", tags=["bndb"])
def download_bndb(filename: str):
    # TODO check if file exits
    return FileResponse(f"BNDB/{filename}")
