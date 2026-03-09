"""
Auth0 FGA (Fine-Grained Authorization) client for ShieldClaw.

Wraps the OpenFGA SDK (v0.1.x low-level API) to provide simple helpers:
  - check_permission(user, relation, object_type, object_id)
  - grant_permission(user, relation, object_type, object_id)
  - revoke_permission(user, relation, object_type, object_id)
  - list_relations(user, object_type, object_id)

All credentials come from environment variables (FGA_*).
Fails open or closed per caller's choice — see check_permission(fail_open=...).
"""

import logging
import os
from typing import Optional

from openfga_sdk import (
    OpenFgaApi,
    ApiClient,
    Configuration,
    CheckRequest,
    TupleKey,
    TupleKeyWithoutCondition,
    WriteRequest,
    WriteRequestWrites,
    WriteRequestDeletes,
)
from openfga_sdk.credentials import CredentialConfiguration, Credentials

logger = logging.getLogger("shieldclaw.fga_client")

# ---------------------------------------------------------------------------
# Configuration — all from env vars
# ---------------------------------------------------------------------------

FGA_API_URL = os.getenv("FGA_API_URL", "")
FGA_STORE_ID = os.getenv("FGA_STORE_ID", "")
FGA_MODEL_ID = os.getenv("FGA_MODEL_ID", "")
FGA_CLIENT_ID = os.getenv("FGA_CLIENT_ID", "")
FGA_CLIENT_SECRET = os.getenv("FGA_CLIENT_SECRET", "")
FGA_API_TOKEN_ISSUER = os.getenv("FGA_API_TOKEN_ISSUER", "")
FGA_API_AUDIENCE = os.getenv("FGA_API_AUDIENCE", "")

_fga_available = bool(FGA_API_URL and FGA_STORE_ID and FGA_CLIENT_ID and FGA_CLIENT_SECRET)

if not _fga_available:
    logger.warning(
        "[fga_client] FGA env vars incomplete — OpenFGA checks will be skipped. "
        "Set FGA_API_URL, FGA_STORE_ID, FGA_CLIENT_ID, FGA_CLIENT_SECRET."
    )


def _build_config() -> Configuration:
    """Build the OpenFGA client configuration from env vars."""
    url = FGA_API_URL.rstrip("/")
    if url.startswith("https://"):
        scheme, host = "https", url[len("https://"):]
    elif url.startswith("http://"):
        scheme, host = "http", url[len("http://"):]
    else:
        scheme, host = "https", url

    credentials = Credentials(
        method="client_credentials",
        configuration=CredentialConfiguration(
            api_issuer=FGA_API_TOKEN_ISSUER,
            api_audience=FGA_API_AUDIENCE,
            client_id=FGA_CLIENT_ID,
            client_secret=FGA_CLIENT_SECRET,
        ),
    )

    return Configuration(
        api_scheme=scheme,
        api_host=host,
        store_id=FGA_STORE_ID,
        credentials=credentials,
    )


def _get_api() -> OpenFgaApi:
    """Create an OpenFGA API instance."""
    return OpenFgaApi(ApiClient(_build_config()))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_permission(
    user: str,
    relation: str,
    object_type: str,
    object_id: str,
    fail_open: bool = False,
) -> bool:
    """
    Check if `user` has `relation` on `object_type:object_id`.

    Returns True if allowed, False if denied.
    If FGA is unavailable or errors, returns `fail_open` value.
    """
    if not _fga_available:
        logger.debug("[fga_client] FGA not configured, returning fail_open=%s", fail_open)
        return fail_open

    fga_object = f"{object_type}:{object_id}"
    try:
        api = _get_api()
        body = CheckRequest(
            tuple_key=TupleKey(user=user, relation=relation, object=fga_object),
        )
        if FGA_MODEL_ID:
            body.authorization_model_id = FGA_MODEL_ID

        response = await api.check(body)
        allowed = response.allowed
        logger.info(
            "[fga_client] CHECK user=%s relation=%s object=%s -> %s",
            user, relation, fga_object, "ALLOW" if allowed else "DENY",
        )
        return allowed
    except Exception as e:
        logger.error("[fga_client] CHECK failed: %s (fail_open=%s)", e, fail_open)
        return fail_open


async def grant_permission(
    user: str,
    relation: str,
    object_type: str,
    object_id: str,
) -> bool:
    """
    Write a tuple: (user, relation, object_type:object_id).
    Returns True on success, False on error.
    """
    if not _fga_available:
        logger.warning("[fga_client] FGA not configured — cannot grant permission")
        return False

    fga_object = f"{object_type}:{object_id}"
    try:
        api = _get_api()
        body = WriteRequest(
            writes=WriteRequestWrites(
                tuple_keys=[TupleKey(user=user, relation=relation, object=fga_object)]
            ),
        )
        if FGA_MODEL_ID:
            body.authorization_model_id = FGA_MODEL_ID

        await api.write(body)
        logger.info(
            "[fga_client] GRANT user=%s relation=%s object=%s",
            user, relation, fga_object,
        )
        return True
    except Exception as e:
        logger.error("[fga_client] GRANT failed: %s", e)
        return False


async def revoke_permission(
    user: str,
    relation: str,
    object_type: str,
    object_id: str,
) -> bool:
    """
    Delete a tuple: (user, relation, object_type:object_id).
    Returns True on success, False on error.
    """
    if not _fga_available:
        logger.warning("[fga_client] FGA not configured — cannot revoke permission")
        return False

    fga_object = f"{object_type}:{object_id}"
    try:
        api = _get_api()
        body = WriteRequest(
            deletes=WriteRequestDeletes(
                tuple_keys=[TupleKeyWithoutCondition(user=user, relation=relation, object=fga_object)]
            ),
        )
        if FGA_MODEL_ID:
            body.authorization_model_id = FGA_MODEL_ID

        await api.write(body)
        logger.info(
            "[fga_client] REVOKE user=%s relation=%s object=%s",
            user, relation, fga_object,
        )
        return True
    except Exception as e:
        logger.error("[fga_client] REVOKE failed: %s", e)
        return False


async def list_relations(
    user: str,
    object_type: str,
    object_id: str,
    relations: Optional[list] = None,
) -> list:
    """
    Check which relations `user` has on `object_type:object_id`.
    Tests each relation via individual check calls.
    Returns list of relation strings the user holds.
    """
    if not _fga_available:
        return []

    check_relations = relations or [
        "owner", "admin", "member", "viewer", "can_execute", "can_delete",
        "operator", "participant", "editor", "can_revoke", "can_rotate",
        "requester", "resolver",
    ]

    found = []
    for rel in check_relations:
        try:
            allowed = await check_permission(user, rel, object_type, object_id, fail_open=False)
            if allowed:
                found.append(rel)
        except Exception:
            continue

    return found


async def batch_grant(tuples: list) -> bool:
    """
    Write multiple tuples at once.
    Each tuple: {"user": ..., "relation": ..., "object_type": ..., "object_id": ...}
    """
    if not _fga_available:
        return False

    try:
        api = _get_api()
        writes = [
            TupleKey(
                user=t["user"],
                relation=t["relation"],
                object=f"{t['object_type']}:{t['object_id']}",
            )
            for t in tuples
        ]
        body = WriteRequest(writes=WriteRequestWrites(tuple_keys=writes))
        if FGA_MODEL_ID:
            body.authorization_model_id = FGA_MODEL_ID

        await api.write(body)
        logger.info("[fga_client] BATCH_GRANT wrote %d tuples", len(writes))
        return True
    except Exception as e:
        logger.error("[fga_client] BATCH_GRANT failed: %s", e)
        return False
