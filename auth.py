"""Authentication and authorization helpers for Kerberos + AD roles."""
from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Set

import json

from fastapi import Depends, Header, HTTPException, Request
from ldap3 import ALL, Connection, Server

logger = logging.getLogger(__name__)

# AD / LDAP configuration
LDAP_SERVER = "fd.local"
LDAP_PORT = 389
LDAP_BIND_DN = "svc_http1cv8@fd.local"
LDAP_BIND_PASSWORD = "hg43f%Rfvc6FT%#7"
LDAP_BASE_DN = "DC=fd,DC=local"
LDAP_DEFAULT_DOMAIN = LDAP_BASE_DN.replace("DC=", "").replace(",", ".")
LDAP_NETBIOS_DOMAIN = LDAP_DEFAULT_DOMAIN.split(".")[0].upper()

BASE_DIR = Path(__file__).resolve().parent
GROUP_CONFIG_PATH = BASE_DIR / "auth_groups.json"

# Local fallback users (no LDAP). Keys are lower-case usernames.
LOCAL_USERS = {
    "administrator": {
        "password": "1qazWSX1qaz",
        "roles": ["Admin", "Support", "Read"],
        "domain": None,
        "groups": ["local-admin"],
    }
}

# Role-to-group mapping (case-insensitive comparison)
ADMIN_GROUPS = {"domain admins", "1c-ras-admins"}
SUPPORT_GROUPS = {"1c-ras-support"}
READ_GROUPS = {"1c-ras-readonly"}


def _load_custom_groups() -> dict:
    """Load mutable group configuration from disk (lower-cased)."""

    default = {"Admin": [], "Support": [], "Read": []}
    if not GROUP_CONFIG_PATH.exists():
        return default
    try:
        with GROUP_CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
            return {
                "Admin": [g.lower() for g in data.get("Admin", [])],
                "Support": [g.lower() for g in data.get("Support", [])],
                "Read": [g.lower() for g in data.get("Read", [])],
            }
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to load auth group config: %s", exc)
        return default


def _save_custom_groups(config: dict) -> None:
    """Persist custom groups configuration to disk."""

    GROUP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with GROUP_CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)


def get_group_config() -> dict:
    """Return current group configuration (builtin, custom, effective)."""

    custom = _load_custom_groups()
    effective = {
        "Admin": sorted({*ADMIN_GROUPS, *custom.get("Admin", [])}),
        "Support": sorted({*SUPPORT_GROUPS, *custom.get("Support", [])}),
        "Read": sorted({*READ_GROUPS, *custom.get("Read", [])}),
    }
    return {
        "builtin": {
            "Admin": sorted(ADMIN_GROUPS),
            "Support": sorted(SUPPORT_GROUPS),
            "Read": sorted(READ_GROUPS),
        },
        "custom": custom,
        "effective": effective,
    }


def update_group_config(role: str, groups: list[str]) -> dict:
    """Update custom groups for a given role and persist."""

    role_key = role.capitalize()
    if role_key not in {"Admin", "Support", "Read"}:
        raise HTTPException(status_code=400, detail="Неизвестная роль")

    custom = _load_custom_groups()
    custom[role_key] = [g.lower() for g in groups if g]
    _save_custom_groups(custom)
    return get_group_config()


@dataclass
class UserContext:
    """Resolved user information coming from Apache headers + LDAP."""

    username: str
    domain: str | None
    remote_user: str
    gss_name: str | None
    groups: List[str]
    roles: List[str]


def _normalize_remote_user(remote_user: str) -> tuple[str, str | None]:
    """Normalize REMOTE_USER style strings to (username, domain)."""

    if "@" in remote_user:
        user_part, domain = remote_user.split("@", 1)
        return user_part, domain
    if "\\" in remote_user:
        domain, user_part = remote_user.split("\\", 1)
        return user_part, domain
    return remote_user, None


def _bind_candidates(username: str, domain: str | None) -> List[str]:
    """Return possible LDAP principals for binding the user."""

    # If the caller already provided a principal with domain, try it first.
    if "@" in username or "\\" in username:
        return [username]

    candidates = [f"{username}@{LDAP_DEFAULT_DOMAIN}"]
    netbios = (
        (domain or LDAP_DEFAULT_DOMAIN).split(".")[0].upper()
        if domain
        else LDAP_NETBIOS_DOMAIN
    )
    candidates.append(f"{netbios}\\{username}")

    seen: Set[str] = set()
    unique: List[str] = []
    for cand in candidates:
        if cand not in seen:
            unique.append(cand)
            seen.add(cand)
    return unique


@lru_cache(maxsize=1)
def _server() -> Server:
    return Server(LDAP_SERVER, port=LDAP_PORT, get_info=ALL)


def _fetch_groups(username: str, upn: str | None = None) -> List[str]:
    """Fetch AD groups (CN) for the given user via LDAP bind using service account."""

    server = _server()
    try:
        conn = Connection(
            server,
            user=LDAP_BIND_DN,
            password=LDAP_BIND_PASSWORD,
            auto_bind=True,
            receive_timeout=10,
        )
    except Exception as exc:  # pragma: no cover - network/auth issues
        logger.error("LDAP bind failed: %s", exc)
        raise HTTPException(status_code=500, detail="LDAP недоступен")

    search_filter_parts = [f"(sAMAccountName={username})"]
    if upn:
        search_filter_parts.append(f"(userPrincipalName={upn})")
    search_filter = "(&(objectClass=user)(|" + "".join(search_filter_parts) + "))"

    try:
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=["memberOf", "sAMAccountName", "userPrincipalName"],
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("LDAP search failed: %s", exc)
        raise HTTPException(status_code=500, detail="Ошибка запроса LDAP")

    logger.info("LDAP search for %s returned %d entries", username, len(conn.entries))

    if not conn.entries:
        logger.warning("User %s not found in LDAP", username)
        return []

    entry = conn.entries[0]
    groups: List[str] = []
    for dn in entry.memberOf or []:
        match = re.search(r"CN=([^,]+)", str(dn))
        if match:
            groups.append(match.group(1))
    logger.info("Groups resolved for %s: %s", username, groups)
    return groups


def ldap_status(probe_user: str | None = None) -> dict:
    """Perform a lightweight LDAP bind + optional user lookup to validate connectivity."""

    server = _server()
    result: dict[str, object] = {
        "reachable": False,
        "base_dn": LDAP_BASE_DN,
        "default_domain": LDAP_DEFAULT_DOMAIN,
        "netbios_domain": LDAP_NETBIOS_DOMAIN,
        "probe_user": probe_user,
        "entries": 0,
        "user_found": None,
        "message": "",
    }

    try:
        conn = Connection(
            server,
            user=LDAP_BIND_DN,
            password=LDAP_BIND_PASSWORD,
            auto_bind=True,
            receive_timeout=10,
        )
        result["reachable"] = True
    except Exception as exc:  # pragma: no cover - network/auth issues
        msg = f"LDAP bind failed: {exc}"
        logger.error(msg)
        result["message"] = msg
        return result

    if not probe_user:
        result["message"] = "LDAP bind успешен"
        return result

    search_filter = (
        "(&(objectClass=user)(|"
        f"(sAMAccountName={probe_user})"
        f"(userPrincipalName={probe_user})"
        "))"
    )

    try:
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=["sAMAccountName", "userPrincipalName"],
        )
        result["entries"] = len(conn.entries)
        result["user_found"] = bool(conn.entries)
        result["message"] = (
            "Пользователь найден" if conn.entries else "Пользователь не найден"
        )
        logger.info(
            "LDAP probe for %s returned %d entries", probe_user, len(conn.entries)
        )
    except Exception as exc:  # pragma: no cover - defensive
        msg = f"LDAP search failed: {exc}"
        logger.error(msg)
        result["message"] = msg

    return result


def _effective_role_sets() -> dict:
    cfg = _load_custom_groups()
    return {
        "Admin": {"domain admins", "1c-ras-admins", *cfg.get("Admin", [])},
        "Support": {"1c-ras-support", *cfg.get("Support", [])},
        "Read": {"1c-ras-readonly", *cfg.get("Read", [])},
    }


def _roles_from_groups(groups: Iterable[str]) -> List[str]:
    group_set: Set[str] = {g.lower() for g in groups}
    roles: Set[str] = set()
    effective = _effective_role_sets()

    for role, mapped in effective.items():
        if mapped & group_set:
            roles.add(role)

    if "domain admins" in group_set:
        roles.add("Admin")

    return list(roles)


def authenticate_basic(username: str, password: str, gss_name: str | None = None) -> UserContext:
    """Validate credentials via LDAP bind and return a populated user context."""

    # Local override (no LDAP).
    user_lower = username.lower()
    local_user = LOCAL_USERS.get(user_lower)
    if local_user and password == local_user["password"]:
        return UserContext(
            username=username,
            domain=local_user.get("domain"),
            remote_user=username,
            gss_name=gss_name,
            groups=local_user.get("groups", []),
            roles=local_user.get("roles", ["Admin", "Support", "Read"]),
        )

    server = _server()
    user_part = username
    norm_user, domain = _normalize_remote_user(user_part)
    candidates = _bind_candidates(norm_user, domain)
    logger.info(
        "Authenticating via LDAP bind: user=%s, gss_name=%s, principals=%s",
        norm_user,
        gss_name or "<none>",
        candidates,
    )

    last_exc: Exception | None = None
    bound_principal: str | None = None
    for principal in candidates:
        try:
            Connection(
                server,
                user=principal,
                password=password,
                auto_bind=True,
                receive_timeout=10,
            ).unbind()
            bound_principal = principal
            break
        except Exception as exc:  # pragma: no cover - network/auth issues
            last_exc = exc
            logger.warning("LDAP bind failed for %s using %s: %s", norm_user, principal, exc)

    if not bound_principal:
        logger.warning(
            "User basic auth failed for %s after %d attempts: %s",
            norm_user,
            len(candidates),
            last_exc,
        )
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    upn = f"{norm_user}@{domain or LDAP_DEFAULT_DOMAIN}"
    logger.info(
        "LDAP bind succeeded for %s; principal=%s, domain=%s, upn=%s",
        norm_user,
        bound_principal,
        domain or "<none>",
        upn,
    )
    groups = _fetch_groups(norm_user, upn)
    roles = _roles_from_groups(groups)
    if not roles:
        logger.warning("User %s has no allowed roles; groups=%s", norm_user, groups)
        raise HTTPException(status_code=403, detail="Нет разрешенных ролей")

    return UserContext(
        username=norm_user,
        domain=domain,
        remote_user=user_part,
        gss_name=gss_name,
        groups=groups,
        roles=roles,
    )


async def get_current_user(
    request: Request,
    remote_user: str | None = Header(default=None, alias="X-Remote-User"),
    gss_name: str | None = Header(default=None, alias="X-GSS-Name"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> UserContext:
    """Resolve the current user from Apache headers and AD groups."""

    # Manual basic auth path (used by the UI login modal)
    if authorization and authorization.lower().startswith("basic "):
        try:
            payload = authorization.split(" ", 1)[1]
            decoded = base64.b64decode(payload).decode("utf-8")
            user_part, password = decoded.split(":", 1)
        except Exception as exc:  # pragma: no cover - defensive decoding
            logger.error("Invalid Basic auth header: %s", exc)
            raise HTTPException(status_code=401, detail="Некорректные учетные данные")

        logger.info("Basic auth header received for user=%s", user_part)
        return authenticate_basic(user_part, password, gss_name=gss_name)

    # Allow anonymous access when Apache/GSS headers are missing so the
    # dashboard keeps working in environments without SSO configured yet.
    if not remote_user:
        logger.warning("Kerberos headers are missing; falling back to anonymous access")
        return UserContext(
            username="anonymous",
            domain=None,
            remote_user="anonymous",
            gss_name=None,
            groups=[],
            roles=["Read"],
        )

    username, domain = _normalize_remote_user(remote_user)
    logger.info(
        "Resolving user from headers: remote_user=%s, gss_name=%s, domain=%s",
        remote_user,
        gss_name or "<none>",
        domain or "<none>",
    )
    upn = f"{username}@{domain}" if domain else f"{username}@{LDAP_DEFAULT_DOMAIN}"

    groups = _fetch_groups(username, upn)
    roles = _roles_from_groups(groups)

    if not roles:
        logger.warning(
            "User %s has no allowed roles (header flow); groups=%s", username, groups
        )
        raise HTTPException(status_code=403, detail="Нет разрешенных ролей")

    return UserContext(
        username=username,
        domain=domain,
        remote_user=remote_user,
        gss_name=gss_name,
        groups=groups,
        roles=roles,
    )


def require_roles(*allowed_roles: str):
    """FastAPI dependency to enforce role intersection."""

    async def _dependency(user: UserContext = Depends(get_current_user)) -> UserContext:
        if not allowed_roles:
            return user
        if not set(user.roles) & set(allowed_roles):
            raise HTTPException(status_code=403, detail="Недостаточно прав")
        return user

    return _dependency
