"""
tests/test_crypto_v2.py — Phase 2/3 unit tests.

Covers:
  A. AES-256-GCM: round-trip, tamper detection, nonce uniqueness
  B. RFC 3526 group: bit-length, generator, DH uses it, bad params rejected
  C. Public value range: validate_public_value edge cases (incl. subgroup check F02)
  D. DH shared secret: matching secrets, get_shared_secret validates input
  E. Integration: headless_test and headless_mitm_test still pass
     (MITM still works in vulnerable mode — go/no-go for Phase 3)
"""

import sys
import unittest

from cryptography.exceptions import InvalidTag

from crypto_protocol import CryptoProtocol
from diffie_hellman import DiffieHellman, RFC3526_P, RFC3526_G


# ---------------------------------------------------------------------------
# A. AES-256-GCM
# ---------------------------------------------------------------------------

class TestAESGCM(unittest.TestCase):

    def setUp(self):
        # Use mirrored is_server flags (server=True, client=False)
        secret = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0
        self.srv = CryptoProtocol(secret, is_server=True)
        self.cli = CryptoProtocol(secret, is_server=False)

    def test_roundtrip_client_to_server(self):
        text = "Hello, Phase 2!"
        self.assertEqual(self.srv.decrypt(self.cli.encrypt(text)), text)

    def test_roundtrip_server_to_client(self):
        text = "Reply from server!"
        self.assertEqual(self.cli.decrypt(self.srv.encrypt(text)), text)

    def test_roundtrip_unicode(self):
        text = "Ñoño 日本語 emoji 🔐"
        self.assertEqual(self.srv.decrypt(self.cli.encrypt(text)), text)

    def test_roundtrip_empty(self):
        text = ""
        self.assertEqual(self.srv.decrypt(self.cli.encrypt(text)), text)

    def test_tamper_detection_ciphertext(self):
        """Flip a byte in the ciphertext body; AES-GCM must raise."""
        ct = self.cli.encrypt("secret message")
        # nonce = first 4-byte pad + 8-byte counter = 12 bytes = 24 hex chars
        tampered = ct[:24] + format(int(ct[24:26], 16) ^ 0xFF, '02x') + ct[26:]
        with self.assertRaises(Exception):
            self.srv.decrypt(tampered)

    def test_tamper_detection_tag(self):
        """Flip a byte in the GCM authentication tag (last 16 bytes)."""
        ct = self.cli.encrypt("secret message")
        tampered = ct[:-32] + format(int(ct[-32:-30], 16) ^ 0x01, '02x') + ct[-30:]
        with self.assertRaises(Exception):
            self.srv.decrypt(tampered)

    def test_nonce_uniqueness(self):
        """Same plaintext encrypted twice must produce different ciphertext."""
        text = "identical plaintext"
        self.assertNotEqual(self.cli.encrypt(text), self.cli.encrypt(text))

    def test_replay_rejected(self):
        """Replaying a ciphertext must raise (counter nonce)."""
        ct = self.cli.encrypt("first")
        self.srv.decrypt(ct)   # consume
        with self.assertRaises(Exception):
            self.srv.decrypt(ct)

    def test_reflection_rejected(self):
        """Client's ciphertext reflected back to itself must raise."""
        ct = self.cli.encrypt("hello")
        with self.assertRaises(Exception):
            self.cli.decrypt(ct)

    def test_different_secrets_different_ciphertext(self):
        srv2 = CryptoProtocol(0x1111111111111111, is_server=True)
        cli2 = CryptoProtocol(0x1111111111111111, is_server=False)
        ct1 = self.cli.encrypt("same text")
        ct2 = cli2.encrypt("same text")
        self.assertNotEqual(ct1, ct2)


# ---------------------------------------------------------------------------
# B. RFC 3526 Group
# ---------------------------------------------------------------------------

class TestRFC3526Group(unittest.TestCase):

    def test_prime_bit_length(self):
        self.assertEqual(RFC3526_P.bit_length(), 2048)

    def test_generator_value(self):
        self.assertEqual(RFC3526_G, 2)

    def test_g_in_subgroup(self):
        """g^((p-1)/2) ≡ 1 (mod p) — g generates the prime-order subgroup."""
        q = (RFC3526_P - 1) // 2
        self.assertEqual(pow(RFC3526_G, q, RFC3526_P), 1)

    def test_dh_server_uses_rfc3526(self):
        dh = DiffieHellman()
        self.assertEqual(dh.p, RFC3526_P)
        self.assertEqual(dh.g, RFC3526_G)

    def test_dh_client_accepts_rfc3526(self):
        # Must NOT raise
        dh = DiffieHellman(RFC3526_P, RFC3526_G)
        self.assertEqual(dh.p, RFC3526_P)
        self.assertEqual(dh.g, RFC3526_G)

    def test_wrong_p_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            DiffieHellman(RFC3526_P - 1, RFC3526_G)
        self.assertIn("RFC 3526", str(ctx.exception))

    def test_wrong_g_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman(RFC3526_P, 5)

    def test_both_wrong_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman(1234, 5)

    def test_private_exponent_in_range(self):
        from diffie_hellman import RFC3526_Q
        dh = DiffieHellman()
        self.assertGreater(dh.private_exponent, 1)
        self.assertLess(dh.private_exponent, RFC3526_Q)   # in [2, q-1] (F23)

    def test_fresh_exponent_per_instance(self):
        """Two DH instances must (with overwhelming probability) have different exponents."""
        dh1 = DiffieHellman()
        dh2 = DiffieHellman()
        self.assertNotEqual(dh1.private_exponent, dh2.private_exponent)

    def test_public_value_in_group(self):
        """g^priv mod p must be in (1, p-1)."""
        dh = DiffieHellman()
        _, _, pub = dh.generate_public_broadcast()
        self.assertGreater(pub, 1)
        self.assertLess(pub, RFC3526_P - 1)


# ---------------------------------------------------------------------------
# C. Public value range validation
# ---------------------------------------------------------------------------

class TestPublicValueRange(unittest.TestCase):

    def test_valid_values_accepted(self):
        # Use actual subgroup members: g^2 and g^3 mod p are always in the subgroup
        v1 = pow(RFC3526_G, 2, RFC3526_P)
        v2 = pow(RFC3526_G, 3, RFC3526_P)
        DiffieHellman.validate_public_value(v1, RFC3526_P)   # must not raise
        DiffieHellman.validate_public_value(v2, RFC3526_P)   # must not raise

    def test_zero_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(0, RFC3526_P)

    def test_one_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(1, RFC3526_P)

    def test_p_minus_one_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(RFC3526_P - 1, RFC3526_P)

    def test_p_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(RFC3526_P, RFC3526_P)

    def test_value_11_rejected_subgroup_check(self):
        """11 passes the range check but fails pow(v,q,p)==1 (F02)."""
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(11, RFC3526_P)

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            DiffieHellman.validate_public_value(-1, RFC3526_P)

    def test_get_shared_secret_validates(self):
        """get_shared_secret(1) must raise ValueError, not compute a trivial secret."""
        dh = DiffieHellman()
        with self.assertRaises(ValueError):
            dh.get_shared_secret(1)


# ---------------------------------------------------------------------------
# D. DH shared secret correctness
# ---------------------------------------------------------------------------

class TestDHSharedSecret(unittest.TestCase):

    def test_shared_secrets_match(self):
        """A and B compute the same shared secret."""
        dhA = DiffieHellman()
        _, _, A = dhA.generate_public_broadcast()

        dhB = DiffieHellman(RFC3526_P, RFC3526_G)
        _, _, B = dhB.generate_public_broadcast()

        sA = dhA.get_shared_secret(B)
        sB = dhB.get_shared_secret(A)
        self.assertEqual(sA, sB)

    def test_different_sessions_different_secrets(self):
        """Two independent DH exchanges produce different shared secrets."""
        def handshake():
            a = DiffieHellman()
            b = DiffieHellman()
            _, _, A = a.generate_public_broadcast()
            _, _, B = b.generate_public_broadcast()
            return a.get_shared_secret(B)

        self.assertNotEqual(handshake(), handshake())

    def test_crypto_protocol_from_shared_secret(self):
        """End-to-end: DH shared secret feeds CryptoProtocol; messages round-trip."""
        dhA = DiffieHellman()
        _, _, A = dhA.generate_public_broadcast()
        dhB = DiffieHellman(RFC3526_P, RFC3526_G)
        _, _, B = dhB.generate_public_broadcast()

        # Server is dhB (is_server=True), client is dhA (is_server=False)
        cpB = CryptoProtocol(dhB.get_shared_secret(A), is_server=True)
        cpA = CryptoProtocol(dhA.get_shared_secret(B), is_server=False)

        plaintext = "DH + AES-GCM works!"
        self.assertEqual(cpB.decrypt(cpA.encrypt(plaintext)), plaintext)
        self.assertEqual(cpA.decrypt(cpB.encrypt("Reply!")), "Reply!")


# ---------------------------------------------------------------------------
# E. Integration regression: headless tests still pass
#    (verifies MITM still works in vulnerable mode — go/no-go for Phase 3)
# ---------------------------------------------------------------------------

class TestHeadlessRegression(unittest.TestCase):
    """
    Re-runs the logic of headless_test.py and headless_mitm_test.py
    inline (no subprocess, no GUI) so Phase 2 changes don't break baseline.
    """

    def _run_normal_chat(self):
        """Run the normal-chat scenario in threads, return (server_received, client_received)."""
        import threading, time, network

        PORT = 19882
        MESSAGES = ["Hello Phase 2!", "GCM works", "RFC3526 rocks"]
        server_got = []
        client_got = []
        errors = []

        def _server():
            try:
                c = network.Connection()
                c.listen(PORT)
                dh = DiffieHellman()
                p, g, A = dh.generate_public_broadcast()
                c.send(str(p)); c.send(str(g)); c.send(str(A))
                B = int(c.recv())
                cp = CryptoProtocol(dh.get_shared_secret(B), is_server=True)
                for _ in MESSAGES:
                    server_got.append(cp.decrypt(c.recv()))
                    c.send(cp.encrypt("ECHO:" + server_got[-1]))
                c._sock.close()
            except Exception as e:
                errors.append(f"SERVER: {e}")

        def _client():
            try:
                time.sleep(0.2)
                c = network.Connection()
                c.connect("127.0.0.1", PORT)
                p = int(c.recv()); g = int(c.recv()); A = int(c.recv())
                dh = DiffieHellman(p, g)
                _, _, B = dh.generate_public_broadcast()
                c.send(str(B))
                cp = CryptoProtocol(dh.get_shared_secret(A), is_server=False)
                for m in MESSAGES:
                    c.send(cp.encrypt(m))
                    client_got.append(cp.decrypt(c.recv()))
                c._sock.close()
            except Exception as e:
                errors.append(f"CLIENT: {e}")

        st = threading.Thread(target=_server, daemon=True)
        ct = threading.Thread(target=_client, daemon=True)
        st.start(); ct.start()
        ct.join(timeout=10); st.join(timeout=5)
        return server_got, client_got, errors, MESSAGES

    def test_normal_chat_roundtrip(self):
        server_got, client_got, errors, MESSAGES = self._run_normal_chat()
        self.assertEqual(errors, [], f"Errors: {errors}")
        self.assertEqual(server_got, MESSAGES)
        self.assertEqual(client_got, [f"ECHO:{m}" for m in MESSAGES])

    def test_mitm_still_works_vulnerable_mode(self):
        """
        GO/NO-GO for Phase 3:
        Mallory must still be able to intercept in vulnerable (unsigned) mode.
        If this fails, the Phase 2 changes broke the MITM relay — stop and fix first.
        """
        import threading, time, network

        PORT_S = 19883
        PORT_M = 19884
        MESSAGES = ["intercept me", "mallory reads this", "no signature yet"]
        captured = []
        server_got = []
        errors = []

        def _server():
            try:
                c = network.Connection()
                c.listen(PORT_S)
                dh = DiffieHellman()
                p, g, A = dh.generate_public_broadcast()
                c.send(str(p)); c.send(str(g)); c.send(str(A))
                B = int(c.recv())
                cp = CryptoProtocol(dh.get_shared_secret(B), is_server=True)
                for _ in MESSAGES:
                    server_got.append(cp.decrypt(c.recv()))
                c._sock.close()
            except Exception as e:
                errors.append(f"SERVER: {e}")

        def _mitm():
            try:
                cs = network.Connection()
                cc = network.Connection()
                cc.listen(PORT_M)
                cs.connect("127.0.0.1", PORT_S)

                p = int(cs.recv()); g = int(cs.recv()); A_s = int(cs.recv())
                dh_s = DiffieHellman(p, g)
                _, _, B_s = dh_s.generate_public_broadcast()
                cs.send(str(B_s))
                cp_s = CryptoProtocol(dh_s.get_shared_secret(A_s), is_server=False)  # Mallory as client toward server

                dh_c = DiffieHellman(p, g)
                _, _, A_c = dh_c.generate_public_broadcast()
                cc.send(str(p)); cc.send(str(g)); cc.send(str(A_c))
                B_c = int(cc.recv())
                cp_c = CryptoProtocol(dh_c.get_shared_secret(B_c), is_server=True)  # Mallory as server toward client

                for _ in MESSAGES:
                    raw = cc.recv()
                    pt = cp_c.decrypt(raw)
                    captured.append(pt)
                    cs.send(cp_s.encrypt(pt))
                cs._sock.close(); cc._sock.close()
            except Exception as e:
                errors.append(f"MITM: {e}")

        def _client():
            try:
                time.sleep(0.3)
                c = network.Connection()
                c.connect("127.0.0.1", PORT_M)
                p = int(c.recv()); g = int(c.recv()); A = int(c.recv())
                dh = DiffieHellman(p, g)
                _, _, B = dh.generate_public_broadcast()
                c.send(str(B))
                cp = CryptoProtocol(dh.get_shared_secret(A), is_server=False)
                for m in MESSAGES:
                    c.send(cp.encrypt(m))
                    import time as t; t.sleep(0.05)
                c._sock.close()
            except Exception as e:
                errors.append(f"CLIENT: {e}")

        st = threading.Thread(target=_server, daemon=True)
        mt = threading.Thread(target=_mitm,   daemon=True)
        ct = threading.Thread(target=_client, daemon=True)
        st.start(); time.sleep(0.1); mt.start(); ct.start()
        ct.join(timeout=15); mt.join(timeout=5); st.join(timeout=5)

        self.assertEqual(errors, [], f"Errors: {errors}")
        self.assertEqual(captured, MESSAGES,
                         "MITM FAILED to intercept — STOP before Phase 3")
        self.assertEqual(server_got, MESSAGES)


if __name__ == '__main__':
    unittest.main(verbosity=2)
