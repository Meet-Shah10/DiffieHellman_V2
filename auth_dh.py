"""auth_dh.py: key management and transport-level secure handshake for DHC1.

Wraps dhc1_core (pure state machines) with:
  - RSA key generation, PEM load/save (PKCS8 private, SubjectPublicKeyInfo public)
  - secure_handshake_server / secure_handshake_client: read/write JSON lines over
    a network.Connection, add timeouts, return a Record
  - Re-exports HandshakeError so callers only import from auth_dh

Usage in run.py:
    from auth_dh import (generate_keypair, load_private_key, load_public_key,
                         secure_handshake_server, secure_handshake_client,
                         HandshakeError, fingerprint_hex)
"""

import json
import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dhc1_core import (
    HandshakeError,   # re-export
    Server, Client,
    fingerprint,
)

__all__ = [
    "HandshakeError",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "save_private_key",
    "save_public_key",
    "fingerprint_hex",
    "secure_handshake_server",
    "secure_handshake_client",
]

HANDSHAKE_TIMEOUT = 5.0   # seconds per recv (D: timeouts)


# ---------------------------------------------------------------------------
# Key generation and PEM I/O
# ---------------------------------------------------------------------------

def generate_keypair():
    """Return (private_key, public_key) — RSA 2048 with public exponent 65537."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def save_private_key(priv, path: str) -> None:
    """Save a private key as PKCS8 PEM.
    Creates the file with mode 0o600 using O_CREAT|O_EXCL so it never
    silently overwrites an existing key (D15 / F18).
    Raises FileExistsError if the file already exists.
    """
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Atomic create-exclusive: safer than open() + write (race-condition free)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    # Enforce 0600 even if umask was permissive
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def save_public_key(pub, path: str) -> None:
    """Save a public key as SubjectPublicKeyInfo PEM.
    Same O_EXCL creation policy as save_private_key.
    """
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)


def load_private_key(path: str):
    """Load a PKCS8 PEM private key from disk.
    Raises FileNotFoundError if the file does not exist.
    Raises HandshakeError if the file is malformed.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=None)
    except FileNotFoundError:
        raise
    except Exception as e:
        raise HandshakeError(f"Failed to load private key from {path!r}: {e}") from e


def load_public_key(path: str):
    """Load a SubjectPublicKeyInfo PEM public key from disk.
    Raises FileNotFoundError if the file does not exist.
    Raises HandshakeError if the file is malformed.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_public_key(data)
    except FileNotFoundError:
        raise
    except Exception as e:
        raise HandshakeError(f"Failed to load public key from {path!r}: {e}") from e


def fingerprint_hex(pub) -> str:
    """Return the SHA-256 fingerprint of pub as a 64-char hex string."""
    return fingerprint(pub).hex()


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

def _send_json(conn, obj: dict) -> None:
    """Serialise obj as a single JSON line and send."""
    conn.send(json.dumps(obj))


def _recv_json(conn, timeout: float = HANDSHAKE_TIMEOUT) -> dict:
    """Receive one JSON line; raise HandshakeError on timeout or bad JSON.
    Sets a socket timeout before the read and restores it afterwards.
    """
    # Save old timeout
    old_timeout = None
    try:
        old_timeout = conn._sock.gettimeout()
        conn._sock.settimeout(timeout)
    except AttributeError:
        pass   # conn may not expose _sock in tests; proceed without timeout

    try:
        line = conn.recv()
    except Exception as e:
        raise HandshakeError(f"Handshake read error: {e}") from e
    finally:
        # Restore timeout
        try:
            conn._sock.settimeout(old_timeout)
        except AttributeError:
            pass

    if line is None:
        raise HandshakeError("Connection closed during handshake")

    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        raise HandshakeError(f"Malformed JSON in handshake: {e}") from e

    if not isinstance(obj, dict):
        raise HandshakeError("Handshake message must be a JSON object")

    return obj


# ---------------------------------------------------------------------------
# Secure handshake entry points
# ---------------------------------------------------------------------------

def secure_handshake_server(conn, priv, pub_s, pub_c_pinned) -> "Record":
    """Run the DHC1 server-side handshake over *conn*.

    Steps:
      1. Build and send M1 (server hello + signature).
      2. Receive M2 (client auth); verify; derive session keys.
      3. Send M3 (server auth over transcript including client's fresh value).
      4. Return a Record (session established).

    Raises HandshakeError on any failure (bad JSON, bad sig, bad DH value,
    timeout, wrong message type).

    Args:
        conn          : network.Connection
        priv          : server's RSA private key
        pub_s         : server's RSA public key (for fingerprint computation)
        pub_c_pinned  : pinned client public key
    """
    srv = Server(priv, pub_s, pub_c_pinned)
    _send_json(conn, srv.m1())
    m2 = _recv_json(conn)
    m3, record = srv.on_m2(m2)
    _send_json(conn, m3)
    return record


def secure_handshake_client(conn, priv, pub_c, pub_s_pinned) -> "Record":
    """Run the DHC1 client-side handshake over *conn*.

    Steps:
      1. Receive M1 (server hello); verify server signature.
      2. Send M2 (client auth).
      3. Receive M3 (server auth over transcript); verify; derive session keys.
      4. Return a Record (session established).

    Raises HandshakeError on any failure.

    Args:
        conn          : network.Connection
        priv          : client's RSA private key
        pub_c         : client's RSA public key (for fingerprint computation)
        pub_s_pinned  : pinned server public key
    """
    cli = Client(priv, pub_c, pub_s_pinned)
    m1 = _recv_json(conn)
    m2 = cli.on_m1(m1)
    _send_json(conn, m2)
    m3 = _recv_json(conn)
    return cli.on_m3(m3)
