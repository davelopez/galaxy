"""Crypt4GH transparent staging helper for compute nodes.

This module provides file I/O operations that run on the compute node to:
1. Decrypt/re-header encrypted inputs via the remote re-encryptor service.
2. Encrypt plaintext outputs via the remote re-encryptor service.

The manifest describes file locations and user ownership; the helper reads
it and makes minimal HTTP calls to the re-encryptor service (only headers,
never encrypted payloads or private keys).
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import shutil
from pathlib import Path
from typing import Any
from urllib import (
    error,
    request,
)

import crypt4gh.header
import crypt4gh.lib
import nacl.public


def _load_manifest(manifest_path: str) -> dict[str, Any]:
    """Load the manifest JSON from the compute node."""
    with open(manifest_path) as f:
        return json.load(f)


def _parse_header_length(stream: io.BufferedReader | io.BytesIO) -> int:
    """Determine header byte length by parsing and re-serializing packets."""
    parsed = crypt4gh.header.parse(stream)
    if isinstance(parsed, tuple):
        _magic, _version, packets = parsed
    else:
        packets = list(parsed)
    return len(crypt4gh.header.serialize(packets))


def _http_get_json(url: str, timeout: int = 30) -> dict[str, Any]:
    """Make a GET request to the re-encryptor service."""
    req = request.Request(url=url, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GET {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"GET {url} failed: {exc.reason}") from exc
    return json.loads(body)


def _http_post_json(url: str, payload: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    """Make a POST request to the re-encryptor service."""
    req = request.Request(
        url=url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"POST {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"POST {url} failed: {exc.reason}") from exc
    return json.loads(body)


def _rewrap_header(service_url: str, endpoint: str, header_bytes: bytes, user_email: str) -> bytes:
    """Call the re-encryptor to rewrap a header (base64 in/out)."""
    url = service_url.rstrip("/") + "/" + endpoint.lstrip("/")
    payload = {
        "crypt4gh_header": base64.b64encode(header_bytes).decode("ascii"),
        "user_email": user_email,
    }
    response = _http_post_json(url, payload)
    encoded = response.get("crypt4gh_header")
    if not isinstance(encoded, str):
        raise RuntimeError(f"POST {url} returned invalid payload")
    try:
        return base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise RuntimeError(f"POST {url} returned invalid base64 header") from exc


def stage_inputs(manifest_path: str, service_url: str) -> None:
    """Stage encrypted inputs by rewrapping headers for the compute key.

    For each input:
    1. Read the original crypt4gh header from the encrypted file.
    2. POST it to /rewrap_for_compute to get a header encrypted for compute.
    3. Write the new header + original body to the staged path.
    """
    manifest = _load_manifest(manifest_path)
    staging_dir = manifest.get("staging_directory", "")
    os.makedirs(staging_dir, exist_ok=True)

    for entry in manifest.get("inputs", []):
        encrypted_path = entry["encrypted_path"]
        staged_path = entry["staged_path"]
        user_email = entry.get("owner_email", "")

        os.makedirs(Path(staged_path).parent, exist_ok=True)
        with open(encrypted_path, "rb") as src:
            header_length = _parse_header_length(src)
            src.seek(0)
            original_header = src.read(header_length)
            src.seek(header_length)
            new_header = _rewrap_header(service_url, "/rewrap_for_compute", original_header, user_email)

            with open(staged_path, "wb") as dst:
                dst.write(new_header)
                shutil.copyfileobj(src, dst)


def _encrypt_for_compute(plaintext_path: str, compute_public_key: bytes) -> bytes:
    """Encrypt a plaintext file with the compute public key in-memory."""
    ephemeral_sk = bytes(nacl.public.PrivateKey.generate())
    encrypted = io.BytesIO()
    with open(plaintext_path, "rb") as infile:
        crypt4gh.lib.encrypt(
            keys=[(0, ephemeral_sk, compute_public_key)],
            infile=infile,
            outfile=encrypted,
        )
    return encrypted.getvalue()


def stage_outputs(manifest_path: str, service_url: str) -> None:
    """Stage plaintext outputs by encrypting and rewrapping headers.

    For each output marked should_encrypt:
    1. Fetch the compute public key (once, shared across outputs).
    2. Encrypt the plaintext with the compute public key.
    3. Extract the header from the encrypted result.
    4. POST the header to /rewrap_for_user to re-key it for the user.
    5. Write the new header + ciphertext body to the final path.
    """
    manifest = _load_manifest(manifest_path)

    key_payload = _http_get_json(service_url.rstrip("/") + "/compute-public-key")
    public_key_hex = key_payload.get("public_key_hex")
    if not isinstance(public_key_hex, str):
        raise RuntimeError("compute-public-key response missing public_key_hex")
    try:
        compute_public_key = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise RuntimeError("compute-public-key response contains invalid hex") from exc

    for entry in manifest.get("outputs", []):
        if not entry.get("should_encrypt", True):
            continue

        staged_path = entry["staged_path"]
        final_path = entry["final_path"]
        user_email = entry.get("owner_email", "")

        encrypted_bytes = _encrypt_for_compute(staged_path, compute_public_key)
        stream = io.BytesIO(encrypted_bytes)
        header_length = _parse_header_length(stream)
        original_header = encrypted_bytes[:header_length]
        encrypted_body = encrypted_bytes[header_length:]

        new_header = _rewrap_header(service_url, "/rewrap_for_user", original_header, user_email)

        os.makedirs(Path(final_path).parent, exist_ok=True)
        with open(final_path, "wb") as out:
            out.write(new_header)
            out.write(encrypted_body)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crypt4GH transparent staging helper")
    parser.add_argument("operation", choices=["stage-inputs", "stage-outputs"])
    parser.add_argument("manifest_path", help="Path to crypt4gh_manifest.json")
    parser.add_argument("service_url", help="Base URL of the crypt4gh re-encryptor service")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.operation == "stage-inputs":
        stage_inputs(args.manifest_path, args.service_url)
    else:
        stage_outputs(args.manifest_path, args.service_url)


if __name__ == "__main__":
    main()
