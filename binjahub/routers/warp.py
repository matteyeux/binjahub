import glob
import os
from pathlib import Path

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/warp", tags=["warp"])
def list_warps():
    """Route to list WARPs."""
    files = {}
    for file in glob.glob('WARP/*'):
        f = Path(file)
        filesize = (f.stat().st_size) / (1024 * 1024)
        files[os.path.basename(file)] = f"{filesize:.2f} MB"
    return files


@router.post("/warp", tags=["warp"])
async def upload_warp(file: UploadFile = File(...)):
    with open(f"WARP/{file.filename}", "wb") as buffer:
        buffer.write(await file.read())
    return {"filename": file.filename}


@router.get("/warp/{filename}", tags=["warp"])
def download_warp(filename: str):
    # TODO check if file exits
    return FileResponse(f"WARP/{filename}")
