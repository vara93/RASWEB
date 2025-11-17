"""Monitoring utilities for system resources and service status."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Represents a discovered systemd service relevant to the dashboard."""

    id: str
    display_name: str
    category: str
    port: Optional[int] = None


def _run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    logger.debug("Executing command: %s", " ".join(cmd))
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def get_cpu_info() -> Dict[str, object]:
    """Return CPU usage summary including per-core usage."""
    usage_percent = psutil.cpu_percent(interval=0.5)
    per_cpu = psutil.cpu_percent(interval=0.1, percpu=True)
    return {"usage_percent": usage_percent, "per_cpu": per_cpu}


def get_memory_info() -> Dict[str, float]:
    """Return memory usage details in megabytes."""
    mem = psutil.virtual_memory()
    total_mb = round(mem.total / (1024 * 1024), 2)
    used_mb = round(mem.used / (1024 * 1024), 2)
    free_mb = round(mem.available / (1024 * 1024), 2)
    usage_percent = mem.percent
    return {
        "total_mb": total_mb,
        "used_mb": used_mb,
        "free_mb": free_mb,
        "usage_percent": usage_percent,
    }


def get_disk_info() -> Dict[str, float]:
    """Return disk usage details for the root filesystem in gigabytes."""
    disk = psutil.disk_usage("/")
    total_gb = round(disk.total / (1024 * 1024 * 1024), 2)
    used_gb = round(disk.used / (1024 * 1024 * 1024), 2)
    free_gb = round(disk.free / (1024 * 1024 * 1024), 2)
    usage_percent = disk.percent
    return {
        "total_gb": total_gb,
        "used_gb": used_gb,
        "free_gb": free_gb,
        "usage_percent": usage_percent,
    }


def _parse_services_output(output: str) -> List[str]:
    units: List[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            units.append(parts[0])
    return units


def _find_ports() -> Dict[int, str]:
    """Try to map listening ports to service names using ss."""
    ports: Dict[int, str] = {}
    result = _run_command(["ss", "-tulpn"])
    if result.returncode != 0:
        logger.debug("ss returned non-zero exit: %s", result.stderr.strip())
        return ports
    for line in result.stdout.splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            address_part = parts[4]
            if ":" in address_part:
                port = int(address_part.rsplit(":", 1)[-1])
            else:
                continue
        except ValueError:
            continue
        service_field = parts[-1] if parts else ""
        ports[port] = service_field
    return ports


def detect_services() -> List[ServiceInfo]:
    """Detect relevant services by name patterns and enrich with ports when possible."""
    result = _run_command(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"])
    if result.returncode != 0:
        logger.error("Failed to list services: %s", result.stderr.strip())
        return []

    units = _parse_services_output(result.stdout)
    ports_map = _find_ports()

    detected: List[ServiceInfo] = []
    for unit in units:
        info: Optional[ServiceInfo] = None
        if unit.startswith("ras-"):
            info = ServiceInfo(id=unit, display_name="1C RAS", category="RAS", port=1545)
        elif unit.startswith("srv1cv8") or unit.startswith("srv1c"):
            info = ServiceInfo(id=unit, display_name="1C Server", category="1C", port=1541)
        elif unit.startswith("postgresql"):
            info = ServiceInfo(id=unit, display_name="PostgreSQL", category="DB", port=5432)
        elif unit == "apache2.service":
            info = ServiceInfo(id=unit, display_name="Apache HTTPD", category="WEB", port=80)

        if info:
            if info.port is None:
                info.port = _guess_port_for_unit(ports_map, unit)
            detected.append(info)
    return detected


def _guess_port_for_unit(port_map: Dict[int, str], unit: str) -> Optional[int]:
    for port, desc in port_map.items():
        if unit.split(".")[0] in desc or unit in desc:
            return port
    return None


def get_service_status(unit_name: str) -> Dict[str, object]:
    active_cp = _run_command(["systemctl", "is-active", unit_name])
    enabled_cp = _run_command(["systemctl", "is-enabled", unit_name])
    status_cp = _run_command(["systemctl", "status", unit_name, "--no-pager", "--lines", "1"])

    active = active_cp.stdout.strip() == "active"
    enabled = enabled_cp.stdout.strip() == "enabled"
    status_text = status_cp.stdout.strip() or status_cp.stderr.strip()
    return {
        "active": active,
        "enabled": enabled,
        "status_text": status_text,
    }


_ALLOWED_PREFIXES = ("ras-", "srv1cv8", "srv1c", "postgresql", "apache2")


def _is_allowed_service(unit_name: str) -> bool:
    return unit_name.startswith(_ALLOWED_PREFIXES)


def restart_service(unit_name: str) -> Dict[str, object]:
    if not _is_allowed_service(unit_name):
        logger.warning("Attempt to restart non-whitelisted service: %s", unit_name)
        return {
            "success": False,
            "message": "Сервис не разрешен к перезапуску",
            "unit_name": unit_name,
        }

    result = _run_command(["systemctl", "restart", unit_name])
    if result.returncode != 0:
        error_msg = result.stderr.strip() or "Failed to restart service"
        logger.error("Restart failed for %s: %s", unit_name, error_msg)
        return {
            "success": False,
            "message": f"Ошибка systemctl: {error_msg}",
            "unit_name": unit_name,
        }
    return {
        "success": True,
        "message": "Сервис успешно перезапущен",
        "unit_name": unit_name,
    }


def get_service_logs(unit_name: str, lines: int = 100) -> List[str]:
    result = _run_command(["journalctl", "-u", unit_name, "-n", str(lines), "--no-pager"])
    if result.returncode != 0:
        logger.error("Failed to get logs for %s: %s", unit_name, result.stderr.strip())
        return [f"Не удалось получить логи: {result.stderr.strip() or 'journalctl недоступен'}"]
    return result.stdout.splitlines()
