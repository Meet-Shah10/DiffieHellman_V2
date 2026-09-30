"""dhc1_core.py: reference core for the signed-DH chat (protocol DHC1).
Pure functions, no sockets, so every rule below is unit-testable.

Security ideas (explain these in the viva):
  * fixed-width encodings: signed transcripts cannot be re-parsed differently
  * subgroup check v^q == 1: peer value must lie in the prime-order subgroup
  * domain labels + both fingerprints + both DH values inside every signature
  * 3 messages: the server signs a transcript containing the client's fresh value
  * directional keys + sequence numbers: no reflection, replay, reorder or drop

Protocol DHC1 (Part 3.2 of IMPLEMENTATION_PLAN_v2.md):
  M1  S -> C : {t:"hello",   v:1, gs, sig_S}     sig_S = Sign_S("DHC1|server-hello|modp2048|" || Gs)
  M2  C -> S : {t:"auth",    gc, sig_C}           sig_C = Sign_C("DHC1|client-auth|" || FPs || FPc || Gs || Gc)
  M3  S -> C : {t:"confirm", sig_S2}              sig_S2 = Sign_S("DHC1|server-auth|" || FPs || FPc || Gs || Gc)
"""
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: F401 (re-exported)

# ---------------------------------------------------------------------------
# RFC 3526 Group 14 (2048-bit MODP).  Safe prime: q = (p-1)/2 is prime.
# g = 2 generates the prime-order subgroup of size q.
# ---------------------------------------------------------------------------
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
Q = (P - 1) // 2              # prime-order subgroup size
WIDTH = 256                    # bytes for a 2048-bit field element (fixed width)
GROUP_ID = b"modp2048"

# RSA-PSS with SHA-512, salt = 64 bytes (digest size).  D5 / F23.
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA512()),
    salt_length=64,            # fixed = digest size; avoids MAX_LENGTH non-portability (F23)
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HandshakeError(Exception):
    """Any handshake failure.
    Library code (dhc1_core, auth_dh, crypto_protocol) raises this.
    run.py and mitm.py catch it, print the abort banner, close the transport,
    and exit.  Library code never calls sys.exit (D14).
    """


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def new_exponent() -> int:
    """Fresh private exponent, uniform in [2, q-1] (F23: was [2, p-2])."""
    return secrets.randbelow(Q - 2) + 2


def enc(n: int) -> bytes:
    """Encode an integer as a fixed-width (256-byte) big-endian byte string.
    Fixed width prevents re-parsing ambiguity in signed transcripts (F05).
    """
    return n.to_bytes(WIDTH, "big")


def dec(b: bytes) -> int:
    """Decode and VALIDATE a peer DH public value.

    Raises HandshakeError if:
    - b is not bytes or not exactly WIDTH bytes
    - value is outside the prime-order subgroup (range AND pow(v,q,p)==1)

    The subgroup check rejects non-residues such as 11 that pass a plain
    range check but are order-2q elements leaking one bit of the exponent (F02).
    """
    if not isinstance(b, (bytes, bytearray)) or len(b) != WIDTH:
        raise HandshakeError(f"DH value has wrong length (expected {WIDTH}, got {len(b) if isinstance(b, (bytes, bytearray)) else 'non-bytes'})")
    v = int.from_bytes(b, "big")
    if not (1 < v < P - 1) or pow(v, Q, P) != 1:
        raise HandshakeError("DH value outside the prime-order subgroup (range or pow(v,q,p)!=1)")
    return v


def unhex(s, n=None) -> bytes:
    """Decode a hex string; raise HandshakeError on malformed input."""
    try:
        b = bytes.fromhex(s)
    except (ValueError, TypeError, AttributeError):
        raise HandshakeError("malformed hex field")
    if n is not None and len(b) != n:
        raise HandshakeError(f"field has wrong length (expected {n}, got {len(b)})")
    return b


# ---------------------------------------------------------------------------
# RSA-PSS helpers
# ---------------------------------------------------------------------------

def sign(priv, data: bytes) -> bytes:
    """Sign data with RSA-PSS / SHA-512."""
    return priv.sign(data, PSS, hashes.SHA512())


def verify(pub, sig: bytes, data: bytes) -> None:
    """Verify an RSA-PSS / SHA-512 signature.
    Raises HandshakeError (not bool) so the caller cannot forget to check (D: verify raises).
    """
    try:
        pub.verify(sig, data, PSS, hashes.SHA512())
    except InvalidSignature:
        raise HandshakeError("signature verification failed")


def fingerprint(pub) -> bytes:
    """SHA-256 of the DER SubjectPublicKeyInfo (32 bytes).
    Used in signed transcripts so a signature cannot be reused under another
    key pair (unknown-key-share defence).
    """
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).digest()


# ---------------------------------------------------------------------------
# Signed transcript constructors (Part 3.2)
# Labels + fixed-width fields = no re-parsing ambiguity, no cross-role replay
# ---------------------------------------------------------------------------

def t_server_hello(gs: bytes) -> bytes:
    """M1 signed data: label || group-id || Gs."""
    return b"DHC1|server-hello|" + GROUP_ID + b"|" + gs


def t_client_auth(fp_s: bytes, fp_c: bytes, gs: bytes, gc: bytes) -> bytes:
    """M2 signed data: label || FPs || FPc || Gs || Gc (all fixed width)."""
    return b"DHC1|client-auth|" + fp_s + fp_c + gs + gc


def t_server_auth(fp_s: bytes, fp_c: bytes, gs: bytes, gc: bytes) -> bytes:
    """M3 signed data: label || FPs || FPc || Gs || Gc (same fields, different label)."""
    return b"DHC1|server-auth|" + fp_s + fp_c + gs + gc


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_keys(shared: int, fp_s: bytes, fp_c: bytes, gs: bytes, gc: bytes):
    """HKDF-SHA-256 bound to the full handshake transcript.

    The salt is the transcript hash (FPs || FPc || Gs || Gc), tying the keys
    to exactly this handshake and both identities (D9).
    Returns (k_c2s, k_s2c) — two 32-byte AES-256 keys, one per direction (D8).
    """
    th = hashlib.sha256(fp_s + fp_c + gs + gc).digest()
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=th,
        info=b"DHC1 record keys",
    ).derive(enc(shared))
    return okm[:32], okm[32:]


# ---------------------------------------------------------------------------
# Record layer (D8)
# ---------------------------------------------------------------------------

class Record:
    """AES-256-GCM record layer.

    Design decisions (D8):
    - One key per direction: directional keys stop reflection attacks.
    - Counter nonces (4-byte zero pad + 8-byte big-endian counter): reject
      replay, reorder and drop.  Random nonces have no ordering (F04).
    - Direction label as AAD: any cross-direction attempt fails GCM auth.
    """

    def __init__(self, k_send: bytes, k_recv: bytes,
                 label_send: bytes, label_recv: bytes):
        self._ks = AESGCM(k_send)
        self._kr = AESGCM(k_recv)
        self._ls = label_send
        self._lr = label_recv
        self._ns = 0   # send counter
        self._nr = 0   # recv counter

    @staticmethod
    def _nonce(n: int) -> bytes:
        """12-byte nonce: 4-byte zero pad + 8-byte big-endian counter."""
        return b"\x00\x00\x00\x00" + n.to_bytes(8, "big")

    def seal(self, pt: bytes) -> str:
        """Encrypt and authenticate plaintext; return hex wire string."""
        ct = self._ks.encrypt(self._nonce(self._ns), pt, self._ls)
        self._ns += 1
        return ct.hex()

    def open(self, wire: str) -> bytes:
        """Decode hex, authenticate and decrypt.
        Raises cryptography.exceptions.InvalidTag on any deviation (tamper,
        replay, reorder, drop, reflection).
        """
        ct = bytes.fromhex(wire)
        pt = self._kr.decrypt(self._nonce(self._nr), ct, self._lr)
        self._nr += 1
        return pt


def make_records(k_c2s: bytes, k_s2c: bytes, is_server: bool) -> "Record":
    """Build a Record with the correct key and label assignment for each role."""
    if is_server:
        # server sends s2c, receives c2s
        return Record(k_s2c, k_c2s, b"s2c", b"c2s")
    # client sends c2s, receives s2c
    return Record(k_c2s, k_s2c, b"c2s", b"s2c")


# ---------------------------------------------------------------------------
# Handshake state machines (pure: dict in, dict out)
# ---------------------------------------------------------------------------

class Server:
    """Server-side (Bob) handshake state machine.

    Usage:
        srv = Server(priv_s, pub_s, pub_c_pinned)
        m1 = srv.m1()                    # send to client
        m3, record = srv.on_m2(m2_dict)  # receive client auth; send m3
    """

    def __init__(self, priv, pub_s, pub_c_pinned):
        self.priv = priv
        self.fp_s = fingerprint(pub_s)
        self.pub_c = pub_c_pinned
        self.fp_c = fingerprint(pub_c_pinned)
        self.s = new_exponent()
        self.gs = enc(pow(G, self.s, P))

    def m1(self) -> dict:
        """Build M1 (server hello): {t, v, gs, sig}."""
        return {
            "t": "hello",
            "v": 1,
            "gs": self.gs.hex(),
            "sig": sign(self.priv, t_server_hello(self.gs)).hex(),
        }

    def on_m2(self, m: dict):
        """Process M2 from client; return (m3_dict, Record).
        Raises HandshakeError on any verification failure.
        """
        if m.get("t") != "auth":
            raise HandshakeError(f"expected 'auth', got {m.get('t')!r}")
        gc_bytes = unhex(m.get("gc", ""), WIDTH)
        sig_bytes = unhex(m.get("sig", ""))
        gcv = dec(gc_bytes)
        verify(self.pub_c, sig_bytes, t_client_auth(self.fp_s, self.fp_c, self.gs, gc_bytes))
        shared = pow(gcv, self.s, P)
        k = derive_keys(shared, self.fp_s, self.fp_c, self.gs, gc_bytes)
        m3 = {
            "t": "confirm",
            "sig": sign(self.priv, t_server_auth(self.fp_s, self.fp_c, self.gs, gc_bytes)).hex(),
        }
        return m3, make_records(*k, is_server=True)


class Client:
    """Client-side (Alice) handshake state machine.

    Usage:
        cli = Client(priv_c, pub_c, pub_s_pinned)
        m2 = cli.on_m1(m1_dict)    # receive server hello; send m2
        record = cli.on_m3(m3_dict) # receive server confirm; session ready
    """

    def __init__(self, priv, pub_c, pub_s_pinned):
        self.priv = priv
        self.fp_c = fingerprint(pub_c)
        self.pub_s = pub_s_pinned
        self.fp_s = fingerprint(pub_s_pinned)
        self.c = new_exponent()
        self.gc = enc(pow(G, self.c, P))
        self.gs = None
        self.gsv = None

    def on_m1(self, m: dict) -> dict:
        """Process M1 from server; return M2.
        Raises HandshakeError on any verification failure.
        """
        if m.get("t") != "hello" or m.get("v") != 1:
            raise HandshakeError(f"unexpected M1: t={m.get('t')!r}, v={m.get('v')!r}")
        self.gs = unhex(m.get("gs", ""), WIDTH)
        sig_bytes = unhex(m.get("sig", ""))
        self.gsv = dec(self.gs)
        verify(self.pub_s, sig_bytes, t_server_hello(self.gs))
        return {
            "t": "auth",
            "gc": self.gc.hex(),
            "sig": sign(self.priv, t_client_auth(self.fp_s, self.fp_c, self.gs, self.gc)).hex(),
        }

    def on_m3(self, m: dict) -> "Record":
        """Process M3 from server; return Record (session established).
        Raises HandshakeError on any verification failure.
        """
        if m.get("t") != "confirm":
            raise HandshakeError(f"expected 'confirm', got {m.get('t')!r}")
        verify(
            self.pub_s,
            unhex(m.get("sig", "")),
            t_server_auth(self.fp_s, self.fp_c, self.gs, self.gc),
        )
        shared = pow(self.gsv, self.c, P)
        k = derive_keys(shared, self.fp_s, self.fp_c, self.gs, self.gc)
        return make_records(*k, is_server=False)
