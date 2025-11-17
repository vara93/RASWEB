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
import monitoring

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


@app.get("/api/monitoring/summary")
async def api_monitoring_summary() -> Dict[str, Dict[str, object]]:
    logger.info("Fetching monitoring summary")
    return {
        "cpu": monitoring.get_cpu_info(),
        "memory": monitoring.get_memory_info(),
        "disk": monitoring.get_disk_info(),
    }


@app.get("/api/monitoring/services")
async def api_monitoring_services() -> Dict[str, List[Dict[str, object]]]:
    logger.info("Listing services for monitoring")
    services = monitoring.detect_services()
    enriched: List[Dict[str, object]] = []
    for service in services:
        status = monitoring.get_service_status(service.id)
        enriched.append({
            "id": service.id,
            "display_name": service.display_name,
            "category": service.category,
            "port": service.port,
            **status,
        })
    return {"services": enriched}


@app.post("/api/monitoring/services/{unit_name}/restart")
async def api_restart_service(unit_name: str) -> Dict[str, object]:
    logger.warning("Restart requested for service: %s", unit_name)
    result = monitoring.restart_service(unit_name)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Restart failed"))
    return result


@app.get("/api/monitoring/services/{unit_name}/logs")
async def api_service_logs(unit_name: str, lines: int = Query(default=100, ge=10, le=500)) -> Dict[str, List[str]]:
    logger.info("Fetching logs for service %s (lines=%s)", unit_name, lines)
    logs = monitoring.get_service_logs(unit_name, lines=lines)
    return {"logs": logs}


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
