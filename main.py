"""
FastAPI application providing REST endpoints for 1C RAS monitoring dashboard.
"""
from __future__ import annotations

import logging
from typing import Dict, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

import ras_client

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="1C RAS Dashboard")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/cluster")
async def api_cluster() -> Dict:
    try:
        info = ras_client.get_cluster_info()
        return {"cluster": info}
    except ras_client.RacError as exc:
        logger.exception("Failed to get cluster info")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/infobases")
async def api_infobases() -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"infobases": ras_client.get_infobases()}
    except ras_client.RacError as exc:
        logger.exception("Failed to get infobases")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/sessions")
async def api_sessions(
    user: str | None = Query(default=None), infobase: str | None = Query(default=None)
) -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"sessions": ras_client.get_sessions(user=user, infobase=infobase)}
    except ras_client.RacError as exc:
        logger.exception("Failed to get sessions")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/processes")
async def api_processes() -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"processes": ras_client.get_processes()}
    except ras_client.RacError as exc:
        logger.exception("Failed to get processes")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/connections")
async def api_connections() -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"connections": ras_client.get_connections()}
    except ras_client.RacError as exc:
        logger.exception("Failed to get connections")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/locks")
async def api_locks() -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"locks": ras_client.get_locks()}
    except ras_client.RacError as exc:
        logger.exception("Failed to get locks")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/licenses")
async def api_licenses() -> Dict[str, List[Dict[str, str]]]:
    try:
        return {"licenses": ras_client.get_licenses()}
    except ras_client.RacError as exc:
        logger.exception("Failed to get licenses")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
async def health() -> Dict:
    status = "ok"
    details = {}
    try:
        _ = ras_client.get_cluster_info()
        details["rac"] = "reachable"
    except ras_client.RacError as exc:
        status = "down"
        details["rac"] = f"error: {exc}"
    return {"status": status, "details": details}


# Example uvicorn command (run as root):
# python3 -m uvicorn main:app --host 0.0.0.0 --port 8080
