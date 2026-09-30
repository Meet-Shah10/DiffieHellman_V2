#! /usr/bin/env python
# Phase 0: Python 3 port (print, bytes/str, pycryptodome)
# Phase 2: RFC 3526 2048-bit MODP group; secrets.randbelow; validate_public_value;
#          reject any p/g that isn't the RFC 3526 constant.

import secrets
from Crypto.PublicKey import RSA   # still used in __main__ self-test only


# ---------------------------------------------------------------------------
# RFC 3526 Group 14 — 2048-bit MODP (https://www.rfc-editor.org/rfc/rfc3526#section-3)
#
# Why use a fixed standard group instead of generating one?
#   1. Avoids the non-primitive-root generator bug in the original code
#      (randint(p//2, p-1) gives a random element, not a primitive root).
#   2. Parameters are pre-vetted by IETF; no runtime primality test needed.
#   3. Every party can verify the group instantly by comparing to the RFC constant.
#   4. Eliminates ~20 s startup delay from RSA.generate(2048) on every run.
#
# p is a *safe prime*: (p-1)/2 is also prime.
# g = 2 generates the prime-order subgroup of size (p-1)/2.
# ---------------------------------------------------------------------------

RFC3526_P = int(
    "FFFFFFFFFFFFFFFF" "C90FDAA22168C234" "C4C6628B80DC1CD1"
    "29024E088A67CC74" "020BBEA63B139B22" "514A08798E3404DD"
    "EF9519B3CD3A431B" "302B0A6DF25F1437" "4FE1356D6D51C245"
    "E485B576625E7EC6" "F44C42E9A637ED6B" "0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5" "AE9F24117C4B1FE6" "49286651ECE45B3D"
    "C2007CB8A163BF05" "98DA48361C55D39A" "69163FA8FD24CF5F"
    "83655D23DCA3AD96" "1C62F356208552BB" "9ED529077096966D"
    "670C354E4ABC9804" "F1746C08CA18217C" "32905E462E36CE3B"
    "E39E772C180E8603" "9B2783A2EC07A28F" "B5C55DF06F4C52C9"
    "DE2BCBF695581718" "3995497CEA956AE5" "15D2261898FA0510"
    "15728E5A8AACAA68" "FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_G = 2


def _verify_rfc3526_group() -> None:
    """
    Sanity-check the RFC 3526 constants at import time.
    Checks:
      1. p is exactly 2048 bits.
      2. g^q ≡ 1 (mod p) where q = (p-1)/2  →  g is in the prime-order subgroup.
    This does NOT run a full Miller-Rabin primality test (the RFC value is trusted),
    but it catches accidental edits or copy-paste errors.
    """
    assert RFC3526_P.bit_length() == 2048, \
        f"RFC3526_P must be 2048 bits, got {RFC3526_P.bit_length()}"
    q = (RFC3526_P - 1) // 2
    assert pow(RFC3526_G, q, RFC3526_P) == 1, \
        "RFC3526_G must satisfy g^((p-1)/2) ≡ 1 (mod p)"


_verify_rfc3526_group()   # runs once at import time


# ---------------------------------------------------------------------------
# DiffieHellman class
# ---------------------------------------------------------------------------

class DiffieHellman:

    def __init__(self, p: int = None, g: int = None):
        """
        Server path (no args):  use RFC 3526 constants.
        Client path (p, g provided):  MUST match RFC 3526 constants exactly.
        Raises ValueError if p/g are wrong — rejects parameter injection.
        Private exponent: fresh secrets.randbelow() per instance.
        """
        if p is not None or g is not None:
            if p != RFC3526_P or g != RFC3526_G:
                raise ValueError(
                    "Rejected: received p/g do not match RFC 3526 2048-bit MODP group. "
                    "Possible parameter injection attack."
                )
        self.p = RFC3526_P
        self.g = RFC3526_G
        # secrets.randbelow uses OS CSPRNG; safer than random.randint
        self.private_exponent = secrets.randbelow(RFC3526_P - 3) + 2   # in [2, p-2]

    def generate_public_broadcast(self) -> tuple:
        """Return (p, g, public_value) where public_value = g^priv mod p."""
        return self.p, self.g, pow(self.g, self.private_exponent, self.p)

    @staticmethod
    def validate_public_value(value: int, p: int) -> None:
        """
        Raise ValueError if value ∉ (1, p-1).
        Prevents small-subgroup attacks: values 0, 1, or p-1 allow an attacker
        to enumerate the private exponent bit-by-bit.
        """
        if not (1 < value < p - 1):
            raise ValueError(
                f"Received DH public value is out of safe range (1, p-1). "
                f"Possible small-subgroup attack."
            )

    def get_shared_secret(self, public_share: int) -> int:
        """Compute g^(priv·peer) mod p. Validates public_share range first."""
        self.validate_public_value(public_share, self.p)
        return pow(public_share, self.private_exponent, self.p)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print(f"[*] Using RFC 3526 Group 14  (p = {RFC3526_P.bit_length()} bits, g = {RFC3526_G})")

    personA = DiffieHellman()
    pA, gA, A = personA.generate_public_broadcast()
    print(f"A  = {A:x}"[:80] + "...")

    personB = DiffieHellman(pA, gA)
    pB, gB, B = personB.generate_public_broadcast()
    print(f"B  = {B:x}"[:80] + "...")

    assert pA == pB == RFC3526_P
    assert gA == gB == RFC3526_G

    sA = personA.get_shared_secret(B)
    sB = personB.get_shared_secret(A)
    assert sA == sB
    print("[+] DH shared secrets match")

    # Verify parameter rejection
    try:
        DiffieHellman(p=1234, g=5)
        assert False, "Should have raised"
    except ValueError:
        print("[+] Non-RFC-3526 parameters correctly rejected")

    # Verify range check
    try:
        DiffieHellman.validate_public_value(1, RFC3526_P)
        assert False, "Should have raised"
    except ValueError:
        print("[+] Out-of-range public value correctly rejected")

    print("[+] DH self-test passed")
