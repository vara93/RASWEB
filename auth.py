"""Authentication and authorization helpers for Kerberos + AD roles."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, List, Set

from fastapi import Depends, Header, HTTPException, Request
from ldap3 import ALL, Connection, Server

logger = logging.getLogger(__name__)

# AD / LDAP configuration
LDAP_SERVER = "fd.local"
LDAP_PORT = 389
LDAP_BIND_DN = "svc_http1cv8@fd.local"
LDAP_BIND_PASSWORD = "hg43f%Rfvc6FT%#7"
LDAP_BASE_DN = "DC=fd,DC=local"

# Role-to-group mapping (case-insensitive comparison)
ADMIN_GROUPS = {"domain admins", "1c-ras-admins"}
SUPPORT_GROUPS = {"1c-ras-support"}
READ_GROUPS = {"1c-ras-readonly"}


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

    if not conn.entries:
        logger.warning("User %s not found in LDAP", username)
        return []

    entry = conn.entries[0]
    groups: List[str] = []
    for dn in entry.memberOf or []:
        match = re.search(r"CN=([^,]+)", str(dn))
        if match:
            groups.append(match.group(1))
    return groups


def _roles_from_groups(groups: Iterable[str]) -> List[str]:
    group_set: Set[str] = {g.lower() for g in groups}
    roles: Set[str] = set()

    if ADMIN_GROUPS & group_set:
        roles.add("Admin")
    if SUPPORT_GROUPS & group_set:
        roles.add("Support")
    if READ_GROUPS & group_set:
        roles.add("Read")

    if "domain admins" in group_set:
        roles.add("Admin")

    return list(roles)


async def get_current_user(
    request: Request,
    remote_user: str | None = Header(default=None, alias="X-Remote-User"),
    gss_name: str | None = Header(default=None, alias="X-GSS-Name"),
) -> UserContext:
    """Resolve the current user from Apache headers and AD groups."""

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
            roles=["Admin", "Support", "Read"],
        )

    username, domain = _normalize_remote_user(remote_user)
    upn = f"{username}@{domain}" if domain else f"{username}@fd.local"

    groups = _fetch_groups(username, upn)
    roles = _roles_from_groups(groups)

    if not roles:
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

    return Depends(_dependency)
