#!/usr/bin/env python3
"""
Setup script for Auth0 FGA — writes the authorization model to the FGA store.

Usage:
    python scripts/setup_fga.py

Reads FGA credentials from .env (via dotenv) and the model from fga-model.fga.
Prints the model ID so you can set FGA_MODEL_ID in your .env.
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is on the path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

load_dotenv(project_root / ".env")

from openfga_sdk import (
    OpenFgaApi,
    ApiClient,
    Configuration,
    WriteAuthorizationModelRequest,
    TypeDefinition,
    Userset,
    Usersets,
    Metadata,
    RelationMetadata,
    RelationReference,
    WriteRequest,
    WriteRequestWrites,
    TupleKey,
)
from openfga_sdk.credentials import CredentialConfiguration, Credentials

MODEL_PATH = project_root / "fga-model.fga"


def parse_fga_model(path: Path) -> list:
    """
    Parse the fga-model.fga DSL into OpenFGA TypeDefinition objects.
    Supports: type, relations, define with [direct], or (union).
    """
    text = path.read_text()
    lines = text.strip().splitlines()

    types = []
    current_type = None
    current_relations = {}
    current_metadata = {}

    def _flush_type():
        nonlocal current_type, current_relations, current_metadata
        if current_type:
            metadata_map = {}
            for rel_name, rel_meta in current_metadata.items():
                metadata_map[rel_name] = RelationMetadata(
                    directly_related_user_types=rel_meta
                )

            td = TypeDefinition(
                type=current_type,
                relations=current_relations if current_relations else None,
                metadata=Metadata(relations=metadata_map) if metadata_map else None,
            )
            types.append(td)

        current_type = None
        current_relations = {}
        current_metadata = {}

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#") or stripped.startswith("model") or stripped.startswith("schema"):
            continue

        if stripped.startswith("type "):
            _flush_type()
            current_type = stripped.split()[1]
            continue

        if stripped == "relations":
            continue

        if stripped.startswith("define "):
            rest = stripped[len("define "):]
            colon_idx = rest.index(":")
            rel_name = rest[:colon_idx].strip()
            rel_body = rest[colon_idx + 1:].strip()

            direct_types = []
            computed_parts = []

            parts = rel_body.split(" or ")

            for part in parts:
                part = part.strip()
                if part.startswith("["):
                    inner = part[1:part.index("]")]
                    for t in inner.split(","):
                        t = t.strip()
                        direct_types.append(RelationReference(type=t))
                else:
                    computed_parts.append(part)

            all_usersets = []
            if direct_types:
                all_usersets.append(Userset(this={}))
            for comp in computed_parts:
                all_usersets.append(Userset(computed_userset={"relation": comp}))

            if len(all_usersets) == 0:
                userset = Userset(this={})
            elif len(all_usersets) == 1:
                userset = all_usersets[0]
            else:
                userset = Userset(union=Usersets(child=all_usersets))

            current_relations[rel_name] = userset
            if direct_types:
                current_metadata[rel_name] = direct_types

    _flush_type()
    return types


async def main():
    api_url = os.getenv("FGA_API_URL")
    store_id = os.getenv("FGA_STORE_ID")
    client_id = os.getenv("FGA_CLIENT_ID")
    client_secret = os.getenv("FGA_CLIENT_SECRET")
    token_issuer = os.getenv("FGA_API_TOKEN_ISSUER", "fga.us.auth0.com")
    api_audience = os.getenv("FGA_API_AUDIENCE", "https://api.us1.fga.dev/")

    missing = [v for v, val in [("FGA_API_URL", api_url), ("FGA_STORE_ID", store_id),
               ("FGA_CLIENT_ID", client_id), ("FGA_CLIENT_SECRET", client_secret)] if not val]
    if missing:
        print(f"ERROR: Missing env vars: {', '.join(missing)}")
        sys.exit(1)

    if not MODEL_PATH.exists():
        print(f"ERROR: Model file not found at {MODEL_PATH}")
        sys.exit(1)

    print(f"[setup_fga] Parsing model from {MODEL_PATH}...")
    type_defs = parse_fga_model(MODEL_PATH)
    print(f"[setup_fga] Found {len(type_defs)} type definitions:")
    for td in type_defs:
        rels = list(td.relations.keys()) if td.relations else []
        print(f"  - {td.type}: {', '.join(rels) if rels else '(no relations)'}")

    # Parse URL
    url = api_url.rstrip("/")
    if url.startswith("https://"):
        scheme, host = "https", url[len("https://"):]
    elif url.startswith("http://"):
        scheme, host = "http", url[len("http://"):]
    else:
        scheme, host = "https", url

    credentials = Credentials(
        method="client_credentials",
        configuration=CredentialConfiguration(
            api_issuer=token_issuer,
            api_audience=api_audience,
            client_id=client_id,
            client_secret=client_secret,
        ),
    )

    config = Configuration(
        api_scheme=scheme,
        api_host=host,
        store_id=store_id,
        credentials=credentials,
    )

    print(f"\n[setup_fga] Connecting to FGA store {store_id}...")

    api = OpenFgaApi(ApiClient(config))

    print("[setup_fga] Writing authorization model...")
    body = WriteAuthorizationModelRequest(
        schema_version="1.1",
        type_definitions=type_defs,
    )

    response = await api.write_authorization_model(body)
    model_id = response.authorization_model_id

    print(f"\n{'=' * 60}")
    print(f"  Authorization model written successfully!")
    print(f"  Model ID: {model_id}")
    print(f"{'=' * 60}")
    print(f"\n  Add this to your .env:")
    print(f"    FGA_MODEL_ID={model_id}")
    print()

    # Write bootstrap tuple
    test_user = os.getenv("AUTH0_TEST_USER_ID")
    if test_user:
        print("[setup_fga] Writing bootstrap tuples...")
        try:
            bootstrap = WriteRequest(
                writes=WriteRequestWrites(
                    tuple_keys=[
                        TupleKey(
                            user=f"user:{test_user}",
                            relation="admin",
                            object="gateway:main",
                        )
                    ]
                ),
            )
            bootstrap.authorization_model_id = model_id
            await api.write(bootstrap)
            print(f"  Granted gateway:admin to user:{test_user}")
        except Exception as e:
            print(f"  (bootstrap tuple may already exist: {e})")

    print("\n[setup_fga] Done!")


if __name__ == "__main__":
    asyncio.run(main())
