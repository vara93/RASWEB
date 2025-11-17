"""Utilities for managing 1C web publications via webinst and Apache2."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

# Configuration (can be adjusted later or externalized if needed)
WEBINST_BIN = "/opt/1cv8/x86_64/8.3.27.1719/webinst"
APACHE_CONF = "/etc/apache2/apache2.conf"
WEB_BASE_DIR = "/var/www/1C"
DESCRIPTOR_TEMPLATE = "/home/administrator/default.vrd"
ONEC_SERVER = "t03-1c11.fd.local"


@dataclass
class WebPublication:
    """Represents a web publication entry."""

    infobase_name: str
    infobase_uuid: Optional[str]
    wsdir: str
    dir: str
    url: str
    descriptor_path: str
    conn_str: str


_ALIAS_RE = re.compile(r'^Alias\s+"(/[^\"]+)"\s+"([^\"]+)"', re.IGNORECASE)
_DESCRIPTOR_RE = re.compile(r'^\s*ManagedApplicationDescriptor\s+"([^"]+)"', re.IGNORECASE)


def _run_command(args: List[str]) -> subprocess.CompletedProcess:
    logger.debug("Executing command: %s", " ".join(args))
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _parse_apache_conf() -> List[WebPublication]:
    publications: List[WebPublication] = []
    if not os.path.exists(APACHE_CONF):
        logger.warning("Apache config not found: %s", APACHE_CONF)
        return publications

    try:
        with open(APACHE_CONF, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to read Apache config: %s", exc)
        return publications

    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if not line.startswith("# 1c publication"):
            idx += 1
            continue

        descriptor_path: Optional[str] = None
        wsdir: Optional[str] = None
        directory: Optional[str] = None

        j = idx + 1
        while j < len(lines) and not lines[j].strip().startswith("# 1c publication"):
            stripped = lines[j].strip()
            alias_match = _ALIAS_RE.match(stripped)
            if alias_match:
                url_path = alias_match.group(1)  # e.g. /test
                directory = alias_match.group(2).rstrip("/")
                wsdir = url_path.lstrip("/")
            desc_match = _DESCRIPTOR_RE.match(stripped)
            if desc_match:
                descriptor_path = desc_match.group(1)
            j += 1
        idx = j

        if not wsdir or not directory:
            continue

        pub_dir = directory
        descriptor_effective = descriptor_path or os.path.join(pub_dir, "default.vrd")
        conn_str = f"Srvr={ONEC_SERVER};Ref={wsdir}"
        publications.append(
            WebPublication(
                infobase_name=wsdir,
                infobase_uuid=None,
                wsdir=wsdir,
                dir=pub_dir,
                url=f"/{wsdir}",
                descriptor_path=descriptor_effective,
                conn_str=conn_str,
            )
        )
    return publications


def list_publications() -> List[WebPublication]:
    """Return current web publications parsed from Apache config."""
    return _parse_apache_conf()


def is_infobase_published(name: str) -> bool:
    """Check whether an infobase name is already published (wsdir assumed equal to name)."""
    name_lower = name.lower()
    return any(pub.wsdir.lower() == name_lower for pub in list_publications())


def publish_infobase(name: str, conn_str: str, uuid: Optional[str] = None) -> WebPublication:
    """Publish an infobase via webinst and reload Apache.

    Assumes wsdir == infobase name and descriptor template is copied into the publication directory.
    """

    pub_dir = os.path.join(WEB_BASE_DIR, name)
    os.makedirs(pub_dir, exist_ok=True)

    descriptor_target = os.path.join(pub_dir, "default.vrd")
    try:
        shutil.copy(DESCRIPTOR_TEMPLATE, descriptor_target)
    except Exception as exc:
        logger.error("Failed to copy descriptor template: %s", exc)
        raise RuntimeError(f"Не удалось подготовить дескриптор: {exc}")

    cmd = [
        WEBINST_BIN,
        "-publish",
        "-apache24",
        "-wsdir",
        name,
        "-dir",
        pub_dir,
        "-connstr",
        conn_str,
        "-descriptor",
        descriptor_target,
        "-confpath",
        APACHE_CONF,
    ]

    result = _run_command(cmd)
    if result.returncode != 0:
        logger.error("webinst publish failed: %s", result.stderr.strip())
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "webinst publish failed")

    reload_cp = _run_command(["systemctl", "reload", "apache2"])
    if reload_cp.returncode != 0:
        logger.error("Apache reload failed: %s", reload_cp.stderr.strip())
        raise RuntimeError(reload_cp.stderr.strip() or "Не удалось перезагрузить Apache2")

    return WebPublication(
        infobase_name=name,
        infobase_uuid=uuid,
        wsdir=name,
        dir=pub_dir,
        url=f"/{name}",
        descriptor_path=descriptor_target,
        conn_str=conn_str,
    )


def delete_publication(name: str) -> None:
    """Delete a publication for the given infobase name (wsdir) and reload Apache."""
    pub_dir = os.path.join(WEB_BASE_DIR, name)
    descriptor_target = os.path.join(pub_dir, "default.vrd")
    conn_str = f"Srvr={ONEC_SERVER};Ref={name}"

    cmd = [
        WEBINST_BIN,
        "-delete",
        "-apache24",
        "-wsdir",
        name,
        "-dir",
        pub_dir,
        "-connstr",
        conn_str,
        "-descriptor",
        descriptor_target,
        "-confpath",
        APACHE_CONF,
    ]

    result = _run_command(cmd)
    if result.returncode != 0:
        logger.error("webinst delete failed: %s", result.stderr.strip())
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "webinst delete failed")

    reload_cp = _run_command(["systemctl", "reload", "apache2"])
    if reload_cp.returncode != 0:
        logger.error("Apache reload failed after delete: %s", reload_cp.stderr.strip())
        raise RuntimeError(reload_cp.stderr.strip() or "Не удалось перезагрузить Apache2")

    # We keep publication directory intact by default; adjust if cleanup is desired.
