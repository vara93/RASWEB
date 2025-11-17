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

SSO_MARK_TEMPLATE = "# 1c sso {wsdir}"
SSO_SNIPPET_TEMPLATE = """# 1c sso {wsdir}
<LocationMatch \"^/(?!server-status|server-info|icons/|\\.well-known/(?:acme-challenge/)?)(?:{wsdir})(?:/|$)\">\n    AuthType GSSAPI\n    AuthName \"Kerberos Login\"\n    Require valid-user\n\n    # серверный keytab с HTTP/FQDN\n    GssapiCredStore keytab:/etc/1C/http/http1cv8.keytab\n    GssapiCredStore client_keytab:/etc/1C/http/http1cv8.keytab\n    # Передача билета в 1С;\n    GssapiDelegCcacheDir /var/krb/1c\n    GssapiDelegCcacheUnique On\n\n    GssapiLocalName Off\n\n    # диагностика\n    Header always set X-Remote-User \"expr=%{{REMOTE_USER}}\"\n    Header always set X-GSS-Name    \"%{{GSS_NAME}}e\"\n</LocationMatch>\n"""


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
    sso_enabled: bool = False


_ALIAS_RE = re.compile(r'^Alias\s+"(/[^\"]+)"\s+"([^\"]+)"', re.IGNORECASE)
_DESCRIPTOR_RE = re.compile(r'^\s*ManagedApplicationDescriptor\s+"([^"]+)"', re.IGNORECASE)
_SSO_MARK_RE = re.compile(r'^#\s*1c\s+sso\s+(?P<wsdir>\S+)', re.IGNORECASE)


def _read_apache_conf() -> str:
    try:
        with open(APACHE_CONF, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        logger.warning("Apache config not found: %s", APACHE_CONF)
        return ""
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to read Apache config: %s", exc)
        return ""


def _write_apache_conf(content: str) -> None:
    with open(APACHE_CONF, "w", encoding="utf-8") as f:
        f.write(content)


def _run_command(args: List[str]) -> subprocess.CompletedProcess:
    logger.debug("Executing command: %s", " ".join(args))
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _is_sso_block_present(wsdir: str, conf_text: str) -> bool:
    if not conf_text:
        return False
    mark = re.compile(rf"#\s*1c\s+sso\s+{re.escape(wsdir)}", re.IGNORECASE)
    if mark.search(conf_text):
        return True
    location = re.compile(rf"<LocationMatch[^>]*{re.escape(wsdir)}[^>]*>", re.IGNORECASE)
    return bool(location.search(conf_text))


def _parse_apache_conf() -> List[WebPublication]:
    publications: List[WebPublication] = []
    conf_text = _read_apache_conf()
    if not conf_text:
        return publications
    lines = conf_text.splitlines()

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
                sso_enabled=_is_sso_block_present(wsdir, conf_text),
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
        sso_enabled=_is_sso_block_present(name, _read_apache_conf()),
    )


def delete_publication(name: str) -> None:
    """Delete a publication for the given infobase name (wsdir) and reload Apache."""

    # Try to detect actual paths from existing publications to avoid missing descriptor errors.
    pub_dir = os.path.join(WEB_BASE_DIR, name)
    descriptor_target = os.path.join(pub_dir, "default.vrd")
    conn_str = f"Srvr={ONEC_SERVER};Ref={name}"

    existing = next((p for p in list_publications() if p.wsdir.lower() == name.lower()), None)
    if existing:
        pub_dir = existing.dir
        descriptor_target = existing.descriptor_path

    # Fallback to the template descriptor if the expected one is absent (common when publish used a shared template).
    if not os.path.exists(descriptor_target) and os.path.exists(DESCRIPTOR_TEMPLATE):
        logger.info("Descriptor %s not found, falling back to template %s", descriptor_target, DESCRIPTOR_TEMPLATE)
        descriptor_target = DESCRIPTOR_TEMPLATE

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


def enable_sso(name: str) -> None:
    """Enable Kerberos SSO block for a specific wsdir (infobase name)."""

    conf_text = _read_apache_conf()
    if _is_sso_block_present(name, conf_text):
        logger.info("SSO already enabled for %s", name)
        return

    snippet = SSO_SNIPPET_TEMPLATE.format(wsdir=name)
    new_conf = conf_text.rstrip() + "\n\n" + snippet + "\n"

    _write_apache_conf(new_conf)
    reload_cp = _run_command(["systemctl", "reload", "apache2"])
    if reload_cp.returncode != 0:
        logger.error("Apache reload failed after enabling SSO: %s", reload_cp.stderr.strip())
        raise RuntimeError(reload_cp.stderr.strip() or "Не удалось перезагрузить Apache2 после включения SSO")


def disable_sso(name: str) -> None:
    """Remove Kerberos SSO block for a specific wsdir if present."""

    conf_text = _read_apache_conf()
    mark = SSO_MARK_TEMPLATE.format(wsdir=name)
    pattern = re.compile(rf"{re.escape(mark)}.*?</LocationMatch>\s*", re.IGNORECASE | re.DOTALL)
    new_conf, count = pattern.subn("", conf_text)

    if count == 0:
        logger.info("SSO block not found for %s; nothing to remove", name)
        return

    _write_apache_conf(new_conf)
    reload_cp = _run_command(["systemctl", "reload", "apache2"])
    if reload_cp.returncode != 0:
        logger.error("Apache reload failed after disabling SSO: %s", reload_cp.stderr.strip())
        raise RuntimeError(reload_cp.stderr.strip() or "Не удалось перезагрузить Apache2 после отключения SSO")
