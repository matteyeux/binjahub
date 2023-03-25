import glob
import os
from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import UploadFile, File, Response


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


# @router.get("/bndb/{filename}", tags=["bndb"])
# def download_bndb(filename: str):
#    with open(f"BNDB/{filename}", "rb") as buffer:
#        contents = buffer.read()
#    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
#    response.headers["Content-Type"] = "application/octet-stream"
#    return contents


@router.get("/bndb/{filename}", tags=["bndb"])
def download_file(filename: str, response: Response):
    with open(f"BNDB/{filename}", "rb") as buffer:
        contents = buffer.read()
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "application/octet-stream"
    return contents
