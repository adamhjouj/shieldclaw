"""
ShieldClaw Vault — Secret Abstraction Layer.

Provides a single `vault.get(key)` interface for all secret access.
Currently backed by environment variables / .env file.

To swap to a real secrets backend (AWS Secrets Manager, GCP Secret Manager,
HashiCorp Vault), replace the backend in _load_secret() — no other code changes needed.

Usage:
    from vault import vault

    api_key = vault.get("ANTHROPIC_API_KEY")
    mgmt_secret = vault.get("AUTH0_MGMT_CLIENT_SECRET")

Collaboration model:
    - Developers never share raw secret values
    - Each dev has their own .env (gitignored) or their own IAM/vault access
    - Rotate a secret in one place — all services pick it up on next restart
    - To revoke a dev's access: remove their vault/IAM permission, not the secret itself
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("shieldclaw.vault")


class _SecretNotFound(Exception):
    pass


class Vault:
    """
    Secret store abstraction. Currently reads from environment variables.

    Future backends (swap _load_secret to enable):
    - AWS Secrets Manager: boto3.client('secretsmanager').get_secret_value(...)
    - GCP Secret Manager: secretmanager.SecretManagerServiceClient().access_secret_version(...)
    - HashiCorp Vault: hvac.Client().secrets.kv.read_secret_version(...)
    - Auth0 Token Vault: Auth0 Management API token vault (for third-party OAuth tokens)
    """

    def __init__(self):
        self._cache: dict[str, str] = {}

    def _load_secret(self, key: str) -> Optional[str]:
        """
        Load a secret by key. Override this method to change the backend.

        Current backend: environment variables (loaded from .env by dotenv).
        """
        return os.getenv(key)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret by key. Returns default if not found.

        Cached in-process for performance. Call invalidate() to force refresh.
        """
        if key not in self._cache:
            value = self._load_secret(key)
            if value is not None:
                self._cache[key] = value
            else:
                if default is not None:
                    return default
                logger.warning(f"Secret '{key}' not found in vault")
                return None
        return self._cache[key]

    def require(self, key: str) -> str:
        """
        Get a secret by key. Raises if not found — use for required secrets.
        """
        value = self.get(key)
        if value is None:
            raise _SecretNotFound(
                f"Required secret '{key}' is not set. "
                f"Add it to your .env file or secrets backend."
            )
        return value

    def invalidate(self, key: Optional[str] = None):
        """
        Clear cached secrets. Pass a key to invalidate one, or None to clear all.
        Useful after secret rotation.
        """
        if key:
            self._cache.pop(key, None)
        else:
            self._cache.clear()
        logger.info(f"Vault cache invalidated: {key or 'all'}")

    def status(self) -> dict:
        """
        Return which secrets are present vs missing (values redacted).
        Useful for health checks and the debug dashboard.
        """
        known_secrets = [
            "AUTH0_DOMAIN",
            "AUTH0_CLIENT_ID",
            "AUTH0_CLIENT_SECRET",
            "AUTH0_AUDIENCE",
            "AUTH0_MGMT_CLIENT_ID",
            "AUTH0_MGMT_CLIENT_SECRET",
            "ANTHROPIC_API_KEY",
            "DISCORD_BOT_TOKEN",
            "OPENCLAW_UPSTREAM",
            "SHIELDCLAW_PORT",
        ]
        result = {}
        for key in known_secrets:
            val = self._load_secret(key)
            result[key] = "set" if val else "MISSING"
        return result


# Global singleton — import and use directly
vault = Vault()
