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

BASE_DIR = Path(__file__).resolve().parent
GROUP_CONFIG_PATH = BASE_DIR / "auth_groups.json"
LDAP_CONFIG_PATH = BASE_DIR / "ldap_config.json"

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


def _default_ldap_config() -> dict:
    return {
        "server": "fd.local",
        "port": 389,
        "bind_dn": "",
        "base_dn": "DC=fd,DC=local",
        "password_b64": None,
    }


def _load_ldap_config() -> dict:
    config = _default_ldap_config()
    if not LDAP_CONFIG_PATH.exists():
        return config

    try:
        with LDAP_CONFIG_PATH.open("r", encoding="utf-8") as fh:
            stored = json.load(fh)
        config["server"] = stored.get("server", config["server"]) or ""
        config["port"] = int(stored.get("port", config["port"]))
        config["bind_dn"] = stored.get("bind_dn", "") or ""
        config["base_dn"] = stored.get("base_dn", config["base_dn"]) or ""
        password_b64 = stored.get("password_b64")
        if password_b64:
            config["password_b64"] = password_b64
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to load ldap config: %s", exc)
    return config


def _save_ldap_config(server: str, port: int, bind_dn: str, base_dn: str, password: str | None):
    data = {
        "server": server,
        "port": port,
        "bind_dn": bind_dn,
        "base_dn": base_dn,
    }
    if password:
        data["password_b64"] = base64.b64encode(password.encode("utf-8")).decode("utf-8")
    else:
        existing = _load_ldap_config()
        if existing.get("password_b64"):
            data["password_b64"] = existing["password_b64"]

    LDAP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LDAP_CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    _server.cache_clear()


def get_ldap_config() -> dict:
    cfg = _load_ldap_config()
    return {
        "server": cfg.get("server", ""),
        "port": cfg.get("port", 389),
        "bind_dn": cfg.get("bind_dn", ""),
        "base_dn": cfg.get("base_dn", ""),
        "password_set": bool(cfg.get("password_b64")),
    }


def update_ldap_config(server: str, port: int, bind_dn: str, base_dn: str, password: str | None) -> dict:
    if not server:
        raise HTTPException(status_code=400, detail="Сервер LDAP обязателен")
    if not base_dn:
        raise HTTPException(status_code=400, detail="Base DN обязателен")
    if not bind_dn:
        raise HTTPException(status_code=400, detail="Учетная запись обязателена")
    _save_ldap_config(server, port, bind_dn, base_dn, password)
    return get_ldap_config()


def _ldap_settings() -> dict:
    cfg = _load_ldap_config()
    base_dn = cfg.get("base_dn", "")
    default_domain = base_dn.replace("DC=", "").replace(",", ".") if base_dn else None
    netbios = default_domain.split(".")[0].upper() if default_domain else None
    password = None
    pwd_b64 = cfg.get("password_b64")
    if pwd_b64:
        try:
            password = base64.b64decode(pwd_b64).decode("utf-8")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to decode LDAP password: %s", exc)

    return {
        "server": cfg.get("server", ""),
        "port": int(cfg.get("port", 389)),
        "bind_dn": cfg.get("bind_dn", ""),
        "password": password,
        "base_dn": base_dn,
        "default_domain": default_domain,
        "netbios_domain": netbios,
    }


def _default_custom() -> dict:
    return {
        "Admin": {"groups": [], "users": []},
        "Support": {"groups": [], "users": []},
        "Read": {"groups": [], "users": []},
    }


def _load_custom_groups() -> dict:
    """Load mutable group/user configuration from disk (lower-cased)."""

    default = _default_custom()
    if not GROUP_CONFIG_PATH.exists():
        return default
    try:
        with GROUP_CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        # Backward compatibility: old schema stored list of groups per role.
        parsed: dict[str, dict[str, list[str]]] = _default_custom()
        for role in ("Admin", "Support", "Read"):
            value = data.get(role, {})
            if isinstance(value, list):
                parsed[role]["groups"] = [g.lower() for g in value]
                parsed[role]["users"] = []
            else:
                parsed[role]["groups"] = [
                    g.lower() for g in value.get("groups", []) if g
                ]
                parsed[role]["users"] = [
                    u.lower() for u in value.get("users", []) if u
                ]
        return parsed
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to load auth group config: %s", exc)
        return default


def _save_custom_groups(config: dict) -> None:
    """Persist custom groups/users configuration to disk."""

    GROUP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with GROUP_CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)


def get_group_config() -> dict:
    """Return current group/user configuration (builtin, custom, effective)."""

    custom = _load_custom_groups()
    effective = {
        "Admin": {
            "groups": sorted({*ADMIN_GROUPS, *custom.get("Admin", {}).get("groups", [])}),
            "users": sorted(set(custom.get("Admin", {}).get("users", []))),
        },
        "Support": {
            "groups": sorted({*SUPPORT_GROUPS, *custom.get("Support", {}).get("groups", [])}),
            "users": sorted(set(custom.get("Support", {}).get("users", []))),
        },
        "Read": {
            "groups": sorted({*READ_GROUPS, *custom.get("Read", {}).get("groups", [])}),
            "users": sorted(set(custom.get("Read", {}).get("users", []))),
        },
    }
    return {
        "builtin": {
            "Admin": {"groups": sorted(ADMIN_GROUPS), "users": []},
            "Support": {"groups": sorted(SUPPORT_GROUPS), "users": []},
            "Read": {"groups": sorted(READ_GROUPS), "users": []},
        },
        "custom": custom,
        "effective": effective,
    }


def update_group_config(role: str, groups: list[str] | None, users: list[str] | None) -> dict:
    """Update custom groups/users for a given role and persist."""

    role_key = role.capitalize()
    if role_key not in {"Admin", "Support", "Read"}:
        raise HTTPException(status_code=400, detail="Неизвестная роль")

    custom = _load_custom_groups()
    role_cfg = custom.get(role_key, _default_custom()[role_key])
    if groups is not None:
        role_cfg["groups"] = [g.lower() for g in groups if g]
    if users is not None:
        role_cfg["users"] = [u.lower() for u in users if u]
    custom[role_key] = role_cfg
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


def _bind_candidates(
    username: str, domain: str | None, default_domain: str | None, netbios_domain: str | None
) -> List[str]:
    """Return possible LDAP principals for binding the user."""

    if "@" in username or "\\" in username:
        return [username]

    candidates: list[str] = []
    if default_domain:
        candidates.append(f"{username}@{default_domain}")
    if domain:
        candidates.append(f"{username}@{domain}")
    if netbios_domain:
        candidates.append(f"{netbios_domain}\\{username}")

    seen: Set[str] = set()
    unique: List[str] = []
    for cand in candidates:
        if cand and cand not in seen:
            unique.append(cand)
            seen.add(cand)
    return unique or [username]


@lru_cache(maxsize=1)
def _server(server: str, port: int) -> Server:
    return Server(server, port=port, get_info=ALL)


def _get_server(cfg: dict) -> Server:
    if not cfg.get("server"):
        raise HTTPException(status_code=503, detail="LDAP сервер не настроен")
    return _server(cfg["server"], cfg.get("port", 389))


def _fetch_groups(username: str, upn: str | None = None, cfg: dict | None = None) -> List[str]:
    """Fetch AD groups (CN) for the given user via LDAP bind using service account."""

    cfg = cfg or _ldap_settings()
    if not cfg.get("bind_dn") or not cfg.get("password"):
        raise HTTPException(status_code=503, detail="Сервисная учетная запись LDAP не настроена")
    if not cfg.get("base_dn"):
        raise HTTPException(status_code=503, detail="Base DN LDAP не настроен")

    server = _get_server(cfg)
    try:
        conn = Connection(
            server,
            user=cfg["bind_dn"],
            password=cfg["password"],
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
            search_base=cfg["base_dn"],
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

    cfg = _ldap_settings()
    result: dict[str, object] = {
        "reachable": False,
        "base_dn": cfg.get("base_dn"),
        "default_domain": cfg.get("default_domain"),
        "netbios_domain": cfg.get("netbios_domain"),
        "probe_user": probe_user,
        "entries": 0,
        "user_found": None,
        "message": "",
    }

    if not cfg.get("bind_dn") or not cfg.get("password"):
        result["message"] = "Сервисная учетная запись LDAP не задана"
        return result

    try:
        server = _get_server(cfg)
    except HTTPException as exc:
        result["message"] = exc.detail
        return result

    if not cfg.get("base_dn"):
        result["message"] = "Base DN LDAP не настроен"
        return result

    try:
        conn = Connection(
            server,
            user=cfg["bind_dn"],
            password=cfg["password"],
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
            search_base=cfg["base_dn"],
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
        "Admin": {
            "groups": {"domain admins", "1c-ras-admins", *cfg.get("Admin", {}).get("groups", [])},
            "users": set(cfg.get("Admin", {}).get("users", [])),
        },
        "Support": {
            "groups": {"1c-ras-support", *cfg.get("Support", {}).get("groups", [])},
            "users": set(cfg.get("Support", {}).get("users", [])),
        },
        "Read": {
            "groups": {"1c-ras-readonly", *cfg.get("Read", {}).get("groups", [])},
            "users": set(cfg.get("Read", {}).get("users", [])),
        },
    }


def _roles_from_members(username: str, groups: Iterable[str]) -> List[str]:
    username_l = username.lower()
    group_set: Set[str] = {g.lower() for g in groups}
    roles: Set[str] = set()
    effective = _effective_role_sets()

    for role, mapped in effective.items():
        if username_l in mapped["users"]:
            roles.add(role)
        if mapped["groups"] & group_set:
            roles.add(role)

    if "domain admins" in group_set:
        roles.add("Admin")

    return sorted(roles)


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

    cfg = _ldap_settings()
    server = _get_server(cfg)
    user_part = username
    norm_user, domain = _normalize_remote_user(user_part)
    candidates = _bind_candidates(norm_user, domain, cfg.get("default_domain"), cfg.get("netbios_domain"))
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

    upn = f"{norm_user}@{domain or cfg.get('default_domain', '')}" if cfg.get("default_domain") or domain else norm_user
    logger.info(
        "LDAP bind succeeded for %s; principal=%s, domain=%s, upn=%s",
        norm_user,
        bound_principal,
        domain or "<none>",
        upn,
    )
    groups = _fetch_groups(norm_user, upn, cfg)
    roles = _roles_from_members(norm_user, groups)
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
    cfg = _ldap_settings()
    upn = f"{username}@{domain}" if domain else (
        f"{username}@{cfg.get('default_domain')}" if cfg.get("default_domain") else username
    )

    groups = _fetch_groups(username, upn, cfg)
    roles = _roles_from_members(username, groups)

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
