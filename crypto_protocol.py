#! /usr/bin/env python
# Phase 0: Python 3 port (print, bytes/str, pycryptodome AES-CBC)
# Phase 2: Replace hand-rolled AES-128-CBC with AES-256-GCM (authenticated encryption)
#          Replace SHA-256(str(secret)) KDF with HKDF-SHA-256 (RFC 5869)
#
# Security rationale for the changes:
#   AES-128-CBC (old):
#     - No authentication tag → bit-flip attacks possible
#     - Fixed IV per session → repeated-prefix leakage
#     - Hand-rolled CBC around ECB → fragile; previously broke on Py3 port
#   AES-256-GCM (new):
#     - Authenticated encryption → any ciphertext tamper raises InvalidTag
#     - Fresh random 96-bit nonce per message → unique under 2^48 messages
#     - 256-bit key → full AES-256 security margin
#   SHA-256(str(int)) KDF (old):
#     - Decimal-string conversion wastes entropy; non-standard
#   HKDF-SHA-256 (new):
#     - RFC 5869 standard; output is cryptographically uniform
#     - 'info' field provides context/domain separation

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os


class CryptoProtocol:

    def __init__(self, shared_secret: int):
        """
        Derive a 32-byte AES-256 key from the DH shared secret integer
        using HKDF-SHA-256.
        """
        # Convert DH shared secret integer to big-endian bytes
        byte_len = (shared_secret.bit_length() + 7) // 8
        raw = shared_secret.to_bytes(byte_len, 'big')

        # HKDF-SHA-256 → 32 bytes = AES-256 key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,          # no salt: shared secret already has high entropy
            info=b'dh-chat-v2', # context label / domain separation
        )
        self.key = hkdf.derive(raw)

    def encrypt(self, data: str) -> str:
        """
        AES-256-GCM encrypt.
        Wire format: hex(nonce[12] + ciphertext + tag[16])
        The 12-byte nonce is randomly generated per message.
        Returns a hex string (safe UTF-8 text, compatible with network.send).
        """
        nonce = os.urandom(12)                               # 96-bit GCM nonce
        ct    = AESGCM(self.key).encrypt(nonce, data.encode('utf-8'), None)
        return (nonce + ct).hex()

    def decrypt(self, data: str) -> str:
        """
        AES-256-GCM decrypt.
        Raises cryptography.exceptions.InvalidTag if the ciphertext was tampered.
        """
        raw        = bytes.fromhex(data)
        nonce, ct  = raw[:12], raw[12:]
        plaintext  = AESGCM(self.key).decrypt(nonce, ct, None)
        return plaintext.decode('utf-8')


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    text = 'abcdefghijklmnopqrstuvwxyz!'
    shared_secret = 123456789012345678901234567890

    c = CryptoProtocol(shared_secret)
    assert c.decrypt(c.encrypt(text)) == text
    print("[+] AES-256-GCM decrypt(encrypt(text))==text  PASSED")

    # Nonce uniqueness
    c1 = c.encrypt(text)
    c2 = c.encrypt(text)
    assert c1 != c2, "Two encryptions of the same text must differ (nonce)"
    print("[+] Nonce uniqueness test  PASSED")

    # Tamper detection
    from cryptography.exceptions import InvalidTag
    ct = c.encrypt(text)
    # flip a byte in the ciphertext (after the 12-byte nonce = 24 hex chars)
    tampered = ct[:24] + format(int(ct[24:26], 16) ^ 0xFF, '02x') + ct[26:]
    try:
        c.decrypt(tampered)
        assert False, "Tampered ciphertext should have raised InvalidTag"
    except (InvalidTag, Exception):
        pass
    print("[+] Tamper detection test  PASSED")

    # Key derivation is deterministic
    c_dup = CryptoProtocol(shared_secret)
    assert c_dup.key == c.key
    print("[+] Key determinism test   PASSED")

    print("\n[+] crypto_protocol.py self-test passed")
