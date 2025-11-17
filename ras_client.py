"""
ras_client.py - Python wrapper around rac CLI for 1C:Enterprise RAS monitoring.

Assumptions:
- rac binary path and RAS endpoint are provided via environment variables or defaults.
- rac does not support JSON output; parsing is done on plain text blocks separated by blank lines.
- Functions return Python data structures that can be safely serialized to JSON.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

RAC_PATH = os.environ.get("RAC", "/opt/1cv8/x86_64/8.3.27.1719/rac")
RAS_ENDPOINT = os.environ.get("RAS", "localhost:1545")


class RacError(RuntimeError):
    """Raised when rac returns a non-zero exit code or malformed output."""


# Parsing utilities

def _parse_blocks(output: str) -> List[Dict[str, str]]:
    """
    Parse rac key/value blocks separated by blank lines into list of dicts.

    Each line is expected to be in format `key : value`. Values are trimmed of
    surrounding quotes. Missing values are stored as empty strings.
    """
    blocks: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" not in line:
            # skip malformed line but log for visibility
            logger.warning("Skipping unparsable line: %s", line)
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"')
        current[key] = value
    if current:
        blocks.append(current)
    return blocks


def _run_rac(args: List[str]) -> str:
    """Execute rac command and return stdout text."""
    cmd = [RAC_PATH] + args + [RAS_ENDPOINT]
    logger.debug("Running command: %s", shlex.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("rac command failed: %s", result.stderr.strip())
        raise RacError(result.stderr.strip() or "rac command failed")
    return result.stdout


def _get_cluster_uuid() -> str:
    """Return UUID of the first cluster found."""
    output = _run_rac(["cluster", "list"])
    blocks = _parse_blocks(output)
    if not blocks:
        raise RacError("No clusters found")
    cluster_uuid = blocks[0].get("cluster")
    if not cluster_uuid:
        raise RacError("Cluster UUID missing in rac output")
    return cluster_uuid


# Public API functions

def get_cluster_info() -> Dict[str, Optional[str]]:
    """Return basic info about the first cluster."""
    output = _run_rac(["cluster", "list"])
    blocks = _parse_blocks(output)
    if not blocks:
        raise RacError("No clusters found")
    info = blocks[0]
    # derive quick stats
    info.setdefault("ras", RAS_ENDPOINT)
    return info


def get_infobases() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    output = _run_rac(["infobase", "summary", "list", "--cluster", cluster_uuid])
    return _parse_blocks(output)


def get_sessions(user: Optional[str] = None, infobase: Optional[str] = None) -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    args = ["session", "list", "--cluster", cluster_uuid]
    output = _run_rac(args)
    sessions = _parse_blocks(output)
    if user:
        sessions = [s for s in sessions if s.get("user-name") == user]
    if infobase:
        sessions = [s for s in sessions if s.get("infobase") == infobase or s.get("name") == infobase]
    return sessions


def get_processes() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    output = _run_rac(["process", "list", "--cluster", cluster_uuid])
    blocks = _parse_blocks(output)
    # augment with derived numeric fields when possible
    for b in blocks:
        if "available-perfomance" in b:
            try:
                b["available-perfomance"] = str(int(b["available-perfomance"]))
            except ValueError:
                logger.debug("Non-integer performance value: %s", b["available-perfomance"])
    return blocks


def get_connections() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    output = _run_rac(["connection", "list", "--cluster", cluster_uuid])
    return _parse_blocks(output)


def get_locks() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    output = _run_rac(["lock", "list", "--cluster", cluster_uuid])
    return _parse_blocks(output)


def get_licenses() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    output = _run_rac(["session", "list", "--cluster", cluster_uuid, "--licenses"])
    return _parse_blocks(output)


# Optional: attempt to get workservers; may fail on older rac versions.
def get_workservers() -> List[Dict[str, str]]:
    cluster_uuid = _get_cluster_uuid()
    try:
        output = _run_rac(["cluster", "workserver", "list", "--cluster", cluster_uuid])
    except RacError as exc:
        logger.warning("Workserver command not supported: %s", exc)
        return []
    return _parse_blocks(output)


__all__ = [
    "get_cluster_info",
    "get_infobases",
    "get_sessions",
    "get_processes",
    "get_connections",
    "get_locks",
    "get_licenses",
    "get_workservers",
    "RacError",
]
