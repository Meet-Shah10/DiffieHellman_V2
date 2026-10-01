"""tests/test_auth_dh.py — Phase 3 transport-level tests for auth_dh.py.

Tests key I/O, gen_keys refuse-to-overwrite, fingerprint stability,
and end-to-end secure handshake in threads using in-process sockets.
"""

import os
import stat
import threading
import socket
import json
import pytest
import tempfile

from cryptography.hazmat.primitives.asymmetric import rsa
from auth_dh import (
    generate_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    fingerprint_hex,
    secure_handshake_server,
    secure_handshake_client,
    HandshakeError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kp():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k, k.public_key()


class _PipeConn:
    """Minimal in-process connection backed by a socket pair."""

    def __init__(self, sock):
        self._sock = sock
        self._buf = b""

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        import base64
        line = base64.b64encode(data) + b"\n"
        self._sock.sendall(line)

    def recv(self):
        import base64
        try:
            while b"\n" not in self._buf:
                chunk = self._sock.recv(4096)
                if not chunk:
                    return None
                self._buf += chunk
            line, self._buf = self._buf.split(b"\n", 1)
            return base64.b64decode(line).decode()
        except Exception:
            return None

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def _connected_pair():
    """Return two _PipeConn objects connected to each other."""
    a, b = socket.socketpair()
    return _PipeConn(a), _PipeConn(b)


# ---------------------------------------------------------------------------
# Key I/O tests
# ---------------------------------------------------------------------------

def test_save_and_load_private_key(tmp_path):
    priv, _ = _kp()
    path = str(tmp_path / "test_priv.pem")
    save_private_key(priv, path)

    assert os.path.exists(path)
    mode = oct(stat.S_IMODE(os.stat(path).st_mode))
    import platform
    if platform.system() != "Windows":   # NTFS doesn't enforce Unix rwx bits
        assert "600" in mode, f"Expected 0o600 permissions, got {mode}"

    loaded = load_private_key(path)
    # Verify the loaded key has the same public key
    assert (loaded.public_key().public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        __import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == priv.public_key().public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        __import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def test_save_private_key_refuses_overwrite(tmp_path):
    priv, _ = _kp()
    path = str(tmp_path / "test_priv.pem")
    save_private_key(priv, path)
    with pytest.raises(FileExistsError):
        save_private_key(priv, path)


def test_save_and_load_public_key(tmp_path):
    _, pub = _kp()
    path = str(tmp_path / "test_pub.pem")
    save_public_key(pub, path)
    loaded = load_public_key(path)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    assert (
        pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        == loaded.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )


def test_load_missing_private_key_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_private_key(str(tmp_path / "nonexistent_priv.pem"))


def test_load_missing_public_key_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_public_key(str(tmp_path / "nonexistent_pub.pem"))


def test_load_malformed_private_key_raises(tmp_path):
    path = str(tmp_path / "bad_priv.pem")
    with open(path, "wb") as f:
        f.write(b"not a pem file")
    os.chmod(path, 0o600)
    with pytest.raises(HandshakeError):
        load_private_key(path)


# ---------------------------------------------------------------------------
# Fingerprint tests
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable():
    _, pub = _kp()
    assert fingerprint_hex(pub) == fingerprint_hex(pub)


def test_fingerprint_differs_for_different_keys():
    _, pub1 = _kp()
    _, pub2 = _kp()
    assert fingerprint_hex(pub1) != fingerprint_hex(pub2)


def test_fingerprint_is_64_hex_chars():
    _, pub = _kp()
    fp = fingerprint_hex(pub)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# gen_keys.py integration
# ---------------------------------------------------------------------------

def test_gen_keys_creates_files_and_refuses_overwrite(tmp_path):
    """gen_keys.gen_keys_for creates key files and refuses to overwrite them."""
    import sys
    sys.path.insert(0, str(tmp_path))
    from gen_keys import gen_keys_for
    gen_keys_for("testpeer", base_dir=str(tmp_path))
    priv_path = str(tmp_path / "testpeer" / "testpeer_priv.pem")
    pub_path  = str(tmp_path / "testpeer" / "testpeer_pub.pem")
    assert os.path.exists(priv_path)
    assert os.path.exists(pub_path)
    # Second call should skip silently (no overwrite)
    gen_keys_for("testpeer", base_dir=str(tmp_path))   # must not raise


# ---------------------------------------------------------------------------
# End-to-end secure handshake
# ---------------------------------------------------------------------------

def test_secure_handshake_end_to_end():
    """Full DHC1 handshake in two threads: both sides must get a working Record."""
    S_priv, S_pub = _kp()
    C_priv, C_pub = _kp()

    s_conn, c_conn = _connected_pair()

    errors = []
    srv_record = [None]
    cli_record = [None]

    def run_server():
        try:
            srv_record[0] = secure_handshake_server(s_conn, S_priv, S_pub, C_pub)
        except Exception as e:
            errors.append(("server", e))

    def run_client():
        try:
            cli_record[0] = secure_handshake_client(c_conn, C_priv, C_pub, S_pub)
        except Exception as e:
            errors.append(("client", e))

    ts = threading.Thread(target=run_server, daemon=True)
    tc = threading.Thread(target=run_client, daemon=True)
    ts.start(); tc.start()
    ts.join(timeout=10); tc.join(timeout=10)

    assert not errors, f"Handshake errors: {errors}"
    assert srv_record[0] is not None
    assert cli_record[0] is not None

    # Exchange messages through the derived records
    plaintext = b"hello from client"
    wire = cli_record[0].seal(plaintext)
    assert srv_record[0].open(wire) == plaintext

    plaintext2 = b"hello from server"
    wire2 = srv_record[0].seal(plaintext2)
    assert cli_record[0].open(wire2) == plaintext2


def test_secure_handshake_wrong_pinned_key():
    """If the client pins the wrong server key, the handshake must abort."""
    S_priv, S_pub = _kp()
    C_priv, C_pub = _kp()
    _, wrong_pub = _kp()   # a key the server doesn't own

    s_conn, c_conn = _connected_pair()
    errors = []

    def run_server():
        try:
            secure_handshake_server(s_conn, S_priv, S_pub, C_pub)
        except Exception as e:
            errors.append(("server", e))

    def run_client():
        try:
            # Client pins 'wrong_pub' instead of S_pub
            secure_handshake_client(c_conn, C_priv, C_pub, wrong_pub)
        except HandshakeError:
            errors.append(("client_handshake_error", None))
        except Exception as e:
            errors.append(("client_other", e))

    ts = threading.Thread(target=run_server, daemon=True)
    tc = threading.Thread(target=run_client, daemon=True)
    ts.start(); tc.start()
    ts.join(timeout=10); tc.join(timeout=10)

    client_errs = [e for e in errors if e[0] == "client_handshake_error"]
    assert client_errs, "Client should have raised HandshakeError for wrong pinned key"
