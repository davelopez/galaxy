"""Key management for the mock crypt4gh re-encryption service.

Manages:
  - The service's own compute keypair (used to re-encrypt staged inputs
    so the compute node can read them).
  - A registry of user keypairs: the private key is needed to decrypt the
    incoming header (re-encryption), and the public key is needed to
    encrypt outputs back to the user.

Note: storing user private keys here is intentional for this mock service.
A production deployment would use a secure key vault.
"""

import threading
from pathlib import Path
from typing import Optional

import crypt4gh.keys


class KeyRegistry:
    """Thread-safe store for user public keys and the compute keypair.

    In a production deployment this would be backed by a secure key vault.
    For demo/testing purposes keys are kept in-process memory and may be
    seeded from disk at startup.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # user_email → raw 32-byte Curve25519 public key
        self._user_public_keys: dict[str, bytes] = {}
        # user_email → raw 32-byte Curve25519 private key (mock only)
        self._user_private_keys: dict[str, bytes] = {}
        self._compute_private_key: Optional[bytes] = None
        self._compute_public_key: Optional[bytes] = None

    # ── Compute keypair ──────────────────────────────────────────────────────

    def load_compute_keypair(self, private_key_path: str) -> None:
        """Load the compute private key from a crypt4gh key file.

        The passphrase is expected to be empty (suitable for automated
        service accounts).  Override via subclass for vault integration.
        """
        sk = crypt4gh.keys.get_private_key(private_key_path, lambda: b"")
        pk_path = str(private_key_path).replace(".sec", ".pub")
        pk = crypt4gh.keys.get_public_key(pk_path) if Path(pk_path).exists() else None
        with self._lock:
            self._compute_private_key = sk
            self._compute_public_key = pk

    def load_user_keys_from_dir(self, keys_dir: Path) -> list[str]:
        """Auto-discover and load user keypairs from a directory.

        Looks for files matching ``user_*.sec`` alongside ``user_*.pub``.
        The filename prefix is converted back to an email by reversing
        the ``_at_`` → ``@`` and ``_`` → ``.`` substitutions.

        Returns the list of emails that were loaded.
        """
        loaded: list[str] = []
        for sec_path in sorted(keys_dir.glob("user_*.sec")):
            pub_path = sec_path.with_suffix(".pub")
            if not pub_path.exists():
                continue
            # Reverse _user_key_prefix: user_<safe_name> → email
            safe_name = sec_path.stem[len("user_") :]
            # The prefix replacement order is: @ → _at_, . → _
            # Reverse: _at_ → @, then remaining _ → .
            email = safe_name.replace("_at_", "@").replace("_", ".")
            sk = crypt4gh.keys.get_private_key(str(sec_path), lambda: b"")
            pk = crypt4gh.keys.get_public_key(str(pub_path))
            self.register_user_keypair(email, sk, pk)
            loaded.append(email)
        return loaded

    @property
    def compute_private_key(self) -> bytes:
        with self._lock:
            if self._compute_private_key is None:
                raise RuntimeError("Compute private key not loaded.  Call load_compute_keypair() first.")
            return self._compute_private_key

    @property
    def compute_public_key(self) -> Optional[bytes]:
        with self._lock:
            return self._compute_public_key

    # ── User public key registry ─────────────────────────────────────────────

    def register_user_key(self, user_email: str, public_key: bytes) -> None:
        """Register a raw Curve25519 public key for a Galaxy user email."""
        with self._lock:
            self._user_public_keys[user_email] = public_key

    def register_user_private_key(self, user_email: str, private_key: bytes) -> None:
        """Register a raw Curve25519 private key for a Galaxy user email (mock only)."""
        with self._lock:
            self._user_private_keys[user_email] = private_key

    def register_user_keypair(self, user_email: str, private_key: bytes, public_key: bytes) -> None:
        """Register both keys for a Galaxy user email at once."""
        with self._lock:
            self._user_private_keys[user_email] = private_key
            self._user_public_keys[user_email] = public_key

    def register_user_key_from_file(self, user_email: str, public_key_path: str) -> None:
        """Load a public key from a crypt4gh key file and register it."""
        pk = crypt4gh.keys.get_public_key(public_key_path)
        self.register_user_key(user_email, pk)

    def get_user_public_key(self, user_email: str) -> bytes:
        """Return the registered public key for *user_email*, or raise KeyError."""
        with self._lock:
            key = self._user_public_keys.get(user_email)
        if key is None:
            raise KeyError(f"No public key registered for user {user_email!r}")
        return key

    def get_user_private_key(self, user_email: str) -> bytes:
        """Return the registered private key for *user_email*, or raise KeyError."""
        with self._lock:
            key = self._user_private_keys.get(user_email)
        if key is None:
            raise KeyError(f"No private key registered for user {user_email!r}")
        return key

    def has_user_key(self, user_email: str) -> bool:
        """Return True if a public key is registered for *user_email*."""
        with self._lock:
            return user_email in self._user_public_keys

    def has_user_private_key(self, user_email: str) -> bool:
        """Return True if a private key is registered for *user_email*."""
        with self._lock:
            return user_email in self._user_private_keys

    def list_user_emails(self) -> list[str]:
        """Return a sorted list of registered user emails."""
        with self._lock:
            return sorted(self._user_public_keys.keys())


# Singleton registry shared by the FastAPI app
_registry = KeyRegistry()


def get_registry() -> KeyRegistry:
    """Return the process-level key registry."""
    return _registry
