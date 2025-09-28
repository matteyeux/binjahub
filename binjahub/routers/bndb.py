import glob
import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from binjahub.common import authenticated

router = APIRouter()


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
