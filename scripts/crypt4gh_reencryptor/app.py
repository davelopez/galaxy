"""FastAPI application for the crypt4gh re-encryption service.

Endpoints
---------
GET  /health
    Returns ``{"status": "ok"}`` — used by load-balancers and test probes.


POST /register-key
    Associates a user public key with a dataset UUID.  Used by Galaxy or
    test harnesses to pre-register keys before job submission.

POST /rewrap_for_compute
    Rewraps a base64 crypt4gh header from user key ownership to compute key
    ownership (user -> compute).

POST /rewrap_for_user
    Rewraps a base64 crypt4gh header from compute key ownership to user key
    ownership (compute -> user).

GET /compute-public-key
    Returns the compute public key in hex (non-secret) for compute-side
    encryption before output header rewrap.

Galaxy never learns private keys. Only public-key material and non-secret
manifest values are exchanged over HTTP.
"""

import base64
import logging
from typing import Optional

from fastapi import (
    FastAPI,
    HTTPException,
    status,
)
from pydantic import (
    BaseModel,
)

from .keys import get_registry
from .staging import reencrypt_header

log = logging.getLogger("crypt4gh_reencryptor")

app = FastAPI(title="Galaxy Crypt4GH Re-encryptor", version="1.0.0")


# ── Request / response schemas ───────────────────────────────────────────────


class RegisterKeyRequest(BaseModel):
    user_email: str  # Galaxy user email address (vault identity)
    # Raw Curve25519 public key encoded as hex (32 bytes → 64 hex chars)
    public_key_hex: str
    # Optional private key hex — required for re-encryption (mock service only)
    private_key_hex: Optional[str] = None


class StatusResponse(BaseModel):
    status: str


class RewrapRequest(BaseModel):
    crypt4gh_header: str
    user_email: str


class RewrapResponse(BaseModel):
    crypt4gh_header: str


class ComputePublicKeyResponse(BaseModel):
    public_key_hex: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@app.get("/health", response_model=StatusResponse, tags=["ops"])
def health() -> StatusResponse:
    """Liveness probe — always returns 200 when the service is running."""
    return StatusResponse(status="ok")


def _decode_header_b64(crypt4gh_header_b64: str) -> bytes:
    try:
        return base64.b64decode(crypt4gh_header_b64, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="crypt4gh_header must be valid base64",
        ) from exc


@app.post("/rewrap_for_compute", response_model=RewrapResponse, tags=["staging"])
def api_rewrap_for_compute(req: RewrapRequest) -> RewrapResponse:
    """Rewrap a crypt4gh header from user key ownership to compute key ownership."""
    registry = get_registry()
    original_header = _decode_header_b64(req.crypt4gh_header)
    try:
        sender_private_key = registry.get_user_private_key(req.user_email)
        compute_public_key = registry.compute_public_key
        if compute_public_key is None:
            raise RuntimeError("Compute public key not loaded")
        new_header = reencrypt_header(original_header, sender_private_key, compute_public_key)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except Exception as exc:
        log.exception("rewrap_for_compute failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"rewrap_for_compute failed: {exc}",
        )

    return RewrapResponse(crypt4gh_header=base64.b64encode(new_header).decode("ascii"))


@app.post("/rewrap_for_user", response_model=RewrapResponse, tags=["staging"])
def api_rewrap_for_user(req: RewrapRequest) -> RewrapResponse:
    """Rewrap a crypt4gh header from compute key ownership to user key ownership."""
    registry = get_registry()
    original_header = _decode_header_b64(req.crypt4gh_header)
    try:
        sender_private_key = registry.compute_private_key
        recipient_public_key = registry.get_user_public_key(req.user_email)
        new_header = reencrypt_header(original_header, sender_private_key, recipient_public_key)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except Exception as exc:
        log.exception("rewrap_for_user failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"rewrap_for_user failed: {exc}",
        )

    return RewrapResponse(crypt4gh_header=base64.b64encode(new_header).decode("ascii"))


@app.get("/compute-public-key", response_model=ComputePublicKeyResponse, tags=["keys"])
def compute_public_key() -> ComputePublicKeyResponse:
    """Return the compute public key as hex for compute-side encryption."""
    registry = get_registry()
    public_key = registry.compute_public_key
    if public_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Compute public key not loaded",
        )
    return ComputePublicKeyResponse(public_key_hex=public_key.hex())


@app.get("/info", tags=["ops"])
def info() -> dict:
    """Service metadata — name and version."""
    return {"name": "galaxy-crypt4gh-reencryptor", "version": "mock"}


@app.post("/register-key", response_model=StatusResponse, tags=["keys"])
def api_register_key(req: RegisterKeyRequest) -> StatusResponse:
    """Register a Galaxy user's keypair (or just their public key) by email.

    Keys must be 64-character hex strings (32-byte Curve25519).
    Providing the private key enables header re-encryption at stage-inputs time
    (the service decrypts with user privkey, re-encrypts with compute pubkey).
    Without the private key, the service falls back to the compute key (for
    self-encrypted test fixtures only).  This endpoint is for demo/testing only.
    """
    try:
        pk_bytes = bytes.fromhex(req.public_key_hex)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="public_key_hex must be a valid hex string.",
        )
    if len(pk_bytes) != 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Expected 32-byte Curve25519 public key; got {len(pk_bytes)} bytes.",
        )
    registry = get_registry()
    if req.private_key_hex is not None:
        try:
            sk_bytes = bytes.fromhex(req.private_key_hex)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="private_key_hex must be a valid hex string.",
            )
        if len(sk_bytes) != 32:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Expected 32-byte Curve25519 private key; got {len(sk_bytes)} bytes.",
            )
        registry.register_user_keypair(req.user_email, sk_bytes, pk_bytes)
        log.info("Registered keypair for user %s", req.user_email)
    else:
        registry.register_user_key(req.user_email, pk_bytes)
        log.info("Registered public key for user %s", req.user_email)
    return StatusResponse(status="ok")
