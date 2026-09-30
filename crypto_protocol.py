#!/usr/bin/env python
"""crypto_protocol.py — record-layer and key-derivation for DH Chat.

Phase 0: Python 3 port (print, bytes/str, pycryptodome AES-CBC)
Phase 2: Replace hand-rolled AES-128-CBC with AES-256-GCM (AESGCM from
         `cryptography`); replace SHA-256(str(secret)) KDF with HKDF-SHA-256.
Phase 3: Re-implemented on top of dhc1_core.Record so the legacy and secure
         paths share the same authenticated record layer.

Security rationale:
  AES-128-CBC (Phase 0):
    - No authentication tag  → bit-flip attacks undetected
    - Fixed IV per session   → repeated-prefix leakage
    - Hand-rolled CBC        → fragile; broke on the Py3 port
  AES-256-GCM + HKDF (Phase 2 onward):
    - Authenticated encryption → any tamper raises InvalidTag
    - Fresh 12-byte counter nonce per message (directional, Phase 3)
    - 256-bit key → full AES-256 security margin
    - HKDF-SHA-256 (RFC 5869) → cryptographically uniform key material

Phase 3 additions (D8 / F04):
  - Two directional keys derived by dhc1_core.derive_keys (HKDF with
    transcript hash as salt).
  - Counter nonces (4-byte zero pad + 8-byte counter) instead of random
    nonces, so replay / reorder / drop / reflection are all rejected.
  - Direction label as GCM AAD: cross-direction decryption fails auth.
"""

from dhc1_core import Record, derive_keys, enc, make_records

# Re-export InvalidTag so callers (run.py) don't need to import cryptography
from cryptography.exceptions import InvalidTag  # noqa: F401


# ---------------------------------------------------------------------------
# CryptoProtocol — legacy (vulnerable) mode record layer
# ---------------------------------------------------------------------------

class CryptoProtocol:
    """Symmetric record layer for the *vulnerable* (unsigned DH) mode.

    Derives two directional AES-256-GCM keys from the DH shared secret using
    HKDF-SHA-256.  Uses counter nonces and direction labels so replay and
    reflection are rejected even in the unauthenticated mode.

    Note: the *handshake* is still unauthenticated in this mode (Mallory can
    substitute DH values freely); only the record layer is authenticated.
    The MITM attack is still possible because Mallory runs two separate
    exchanges and two CryptoProtocol instances.

    Args:
        shared_secret : DH shared secret integer
        is_server     : True if this side is the server (Bob)
    """

    def __init__(self, shared_secret: int, is_server: bool = True):
        raw = enc(shared_secret)
        # Use empty fingerprints and empty DH values as a stand-in for the
        # transcript hash in vulnerable mode (Part 3.3): "Vulnerable mode
        # uses the same record layer, with empty fingerprints in the
        # transcript hash."
        k_c2s, k_s2c = derive_keys(
            shared_secret,
            fp_s=b"\x00" * 32,
            fp_c=b"\x00" * 32,
            gs=raw,
            gc=raw,
        )
        self._record: Record = make_records(k_c2s, k_s2c, is_server)

    def encrypt(self, data: str) -> str:
        """Encrypt a UTF-8 string; return a hex wire string."""
        return self._record.seal(data.encode("utf-8"))

    def decrypt(self, data: str) -> str:
        """Decrypt a hex wire string; return UTF-8 string.
        Raises cryptography.exceptions.InvalidTag on any tampering.
        """
        return self._record.open(data).decode("utf-8")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    text = "abcdefghijklmnopqrstuvwxyz!"
    shared_secret = 123456789012345678901234567890

    # Server and client must have mirrored is_server flags
    srv = CryptoProtocol(shared_secret, is_server=True)
    cli = CryptoProtocol(shared_secret, is_server=False)

    ct = cli.encrypt(text)
    assert srv.decrypt(ct) == text
    print("[+] AES-256-GCM round-trip (client→server)  PASSED")

    ct2 = srv.encrypt(text)
    assert cli.decrypt(ct2) == text
    print("[+] AES-256-GCM round-trip (server→client)  PASSED")

    # Replay rejection
    from cryptography.exceptions import InvalidTag
    ct3 = cli.encrypt("first")
    srv.decrypt(ct3)   # consume
    try:
        srv.decrypt(ct3)   # replay
        assert False, "Should have raised"
    except InvalidTag:
        print("[+] Replay rejected by counter nonce    PASSED")

    # Reflection rejection
    srv2 = CryptoProtocol(shared_secret, is_server=True)
    cli2 = CryptoProtocol(shared_secret, is_server=False)
    sent = cli2.encrypt("hello")
    try:
        cli2.decrypt(sent)   # reflected back to sender
        assert False, "Should have raised"
    except InvalidTag:
        print("[+] Reflection rejected by directional keys  PASSED")

    print("\n[+] crypto_protocol.py self-test passed")
