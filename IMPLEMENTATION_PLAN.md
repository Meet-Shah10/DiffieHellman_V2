# IMPLEMENTATION PLAN — IS FA2: "Secure Chat: Break It, Then Fix It"

> **Reading guide:**
> - `VERIFIED` = read directly from repo source.
> - `ASSUMED` = reasonable inference; must be confirmed by the team.
> - ✅ **DONE** = completed and tested (see Appendix audit trail).
> - 🔲 **TODO** = not yet started.
> - ⚠️ = needs team decision or confirmation.
>
> Original repo: `jaybosamiya/DiffieHellman-ManInTheMiddle` (MIT, archived 2018).  
> Our fork: Python 3.13, Windows + Linux compatible.  
> Git tag `phase-0` = commit `63b402d`.

---

## PART 1 — FINDINGS SUMMARY

### 1.1 Python Version and Breaking Constructs

**VERIFIED:** Every original file was Python 2. System Python is 3.13.7.

| File | Line(s) | Python 2 construct | Python 3 impact |
|---|---|---|---|
| `run.py` | 12-14, 34, 47, 57 | `print "..."` | `SyntaxError` |
| `diffie_hellman.py` | 33-35, 47-48 | `print '...'` | `SyntaxError` |
| `diffie_hellman.py` | 18, 22 | `randint(p/2, p-1)` | `TypeError`: `randint` needs `int` |
| `diffie_hellman.py` | 4, 9 | `from Crypto…; RSAKey.key.p` | PyCrypto dead; pycryptodome uses `RSAKey.p` |
| `crypto_protocol.py` | 14, 57, 73 | `len(data) / 16` | Wrong block count; `range(float)` crashes |
| `crypto_protocol.py` | 9, 25, 31, 52 | `chr()`/`ord()` on str used as bytes | `TypeError` in Python 3 bytes context |
| `crypto_protocol.py` | 58, 64, 74, 79 | `str += str` for binary concat | Must be `bytes += bytes` |
| `crypto_protocol.py` | 90 | `h.update(str(key))` | `update()` needs `bytes` |
| `crypto_protocol.py` | 91 | `a2b_hex(h.hexdigest())` | `h.hexdigest()` is `str`; use `bytes.fromhex()` |
| `crypto_protocol.py` | 71 | `print "..."` | `SyntaxError` |
| `gui.py` | 3 | `import Tkinter` | `ModuleNotFoundError`; Py 3 = `tkinter` |
| `gui.py` | 18 | `print "..."` | `SyntaxError` |
| `mitm.py` | 15-16, 43, 49 | `print "..."` | `SyntaxError` |
| `network.py` | 3 | `import pwn` | Unreliable on Windows |
| `network.py` | 22, 27-28 | `.decode('base64')` / `.encode('base64')` | `LookupError`: codec removed in Py 3 |

### 1.2 Third-Party Dependencies (VERIFIED)

| Import | Library | Status |
|---|---|---|
| `from Crypto.PublicKey import RSA` | `pycryptodome` | ✅ 3.23.0 installed |
| `from Crypto.Cipher import AES` | `pycryptodome` | ✅ installed |
| `from Crypto.Hash import SHA256` | `pycryptodome` | ✅ installed |
| `import pwn` (ORIGINAL only) | `pwntools` | ✅ REMOVED — stdlib `socket` used instead |
| `import tkinter` | stdlib | ✅ |

**Not yet installed (future phases):**
- `cryptography` — AES-GCM, RSA-PSS/SHA-512, HKDF (Phases 2–3)
- `pyotp`, `qrcode`, `Pillow` — TOTP MFA (Phase 6)

### 1.3 Launch Commands (VERIFIED vs README)

| Role | Correct command | README note |
|---|---|---|
| Server | `python run.py <port>` | ✅ matches |
| Client | `python run.py <ip> <port>` | ✅ matches |
| MITM | `python mitm.py <server_ip> <port_1> <port_2>` | README omits the script name `mitm.py` — confirmed from `mitm.py:15-17` |

**VERIFIED startup order:** Server → MITM → Client (MITM connects to server at startup).

### 1.4 DH Parameters (VERIFIED from `diffie_hellman.py`)

| Item | How | Weakness |
|---|---|---|
| Prime `p` | `RSA.generate(2048).p` → ≈1024-bit factor | Weak by 2024 NIST standards |
| Generator `g` | `randint(p//2, p-1)` | **Not a primitive root** — may generate a small subgroup |
| Private exponent | `randint(p//2, p-1)` | Should use `secrets.randbelow` |
| Public value | `pow(g, priv, p)` | Correct formula |

**Receiver validation: NONE.** `int(get_line())` with no checks. This is the parameter injection vulnerability.

### 1.5 Cipher, Key Derivation, and Weaknesses (VERIFIED)

| Item | Original | Weakness |
|---|---|---|
| KDF | `SHA256(str(shared_secret))` → first 16 bytes = key, last 16 = IV | IV is fixed per session; decimal-string conversion is non-standard |
| Cipher | **AES-128-CBC** (hand-rolled from ECB) | No authentication tag; bit-flip attacks possible; fixed IV leaks repeated-prefix patterns |
| Padding | Custom PKCS#7 | Specific exception type could enable padding-oracle in network scenario |

### 1.6 Wire Protocol (VERIFIED)

```
Every message:  base64_encode(utf8(payload)) + b'\n'

Handshake payloads: decimal strings of large integers (p, g, A, B)
Chat payloads:      hex string of AES-CBC ciphertext bytes
```

### 1.7 What `mitm.py` Does (VERIFIED, line by line)

```
Step 1  conn_client.listen(client_port)           — wait for Alice
Step 2  conn_server.connect(server_ip, server_port)— connect to Bob
Step 3  recv p, g, A from Bob
Step 4  dh_server = DiffieHellman(p, g)
        compute B_server (Mallory's DH value toward Bob)
        send B_server to Bob   ← Bob now shares K1 with Mallory
Step 5  dh_client = DiffieHellman(p, g)
        compute A_client (Mallory's DH value toward Alice)
        send p, g, A_client to Alice  ← Alice gets FORGED public value
Step 6  recv B_client from Alice   ← Alice shares K2 with Mallory
Relay:  recv from client → decrypt K2 → print plaintext → re-encrypt K1 → send to server
        recv from server → decrypt K1 → print plaintext → re-encrypt K2 → send to client
```

### 1.8 GUI Needed?

**VERIFIED:** Both `run.py` and `mitm.py` unconditionally start a GUI thread. The
`--no-gui` flag added in Phase 1 switches to a stdin reader thread (subprocess-driveable)
for automated testing. Keep GUI for the live demo.

---

## PART 2 — DECISIONS AND ASSUMPTIONS

| # | Decision | Default | Rationale |
|---|---|---|---|
| D1 | Python target | **3.13** | System version; venv active |
| D2 | GUI | **Keep + `--no-gui`** | Demo impact; tests use `--no-gui` |
| D3 | DH group | **RFC 3526 2048-bit MODP in all modes** | No `--toy-params`; group is pre-computed constant |
| D4 | `--toy-params`? | **Dropped** | Jupyter notebook from reference repo is sufficient for the math explanation; adds complexity without benefit |
| D5 | Signature scheme | **RSA-PSS / SHA-512** | Matches IS syllabus Unit IV; `cryptography` library |
| D6 | Key size | **RSA-2048** | NIST recommended minimum |
| D7 | Public key distribution | **Files on disk, generated by `gen_keys.py` before demo; NO PEM committed** | Local lab; see PEM policy below |
| D8 | Symmetric cipher (Phase 2+) | **AES-256-GCM** | Authenticated encryption; eliminates CBC weaknesses |
| D9 | KDF (Phase 2+) | **HKDF-SHA-256** | RFC 5869 standard |
| D10 | MFA scope | **TOTP (RFC 6238), inside AES-GCM channel** | After DH handshake; channel protects OTP transit |
| D11 | MFA storage | **`users.json`, never committed** | Local demo |
| D12 | Lockout | **3 failures → 30-second cooldown** | Demonstrable |
| D13 | AVISPA | **Try local install (WSL); web interface fallback** | Phase 5 |
| D14 | HandshakeError | **Raised by library, caught by `run.py`** | Library code never calls `sys.exit` |
| D15 | PEM policy | **`*.pem` in `.gitignore`; no PEM committed, including public keys; `gen_keys.py` refuses to overwrite** | Security hygiene; key distribution discussed in viva |

**Phase ordering:** 0 → 1 → 2 → 3 → 4 → **5 (AVISPA)** → **6 (MFA)** → 7

**Open questions for the team:**
1. ⚠️ Exact deadline and deliverable format (confirm with faculty).
2. ⚠️ Group size (plan assumes 4; adjust roles accordingly).
3. ⚠️ Demo on same machine or two lab PCs?
4. ⚠️ Is AVISPA installed on lab machines?
5. ⚠️ Report length — context says 6–10 pages; confirm.

---

## PART 3 — PHASED PLAN

---

### ✅ PHASE 0: Python 3 Port + Baseline

**Status: COMPLETE. Git tag: `phase-0` (commit `63b402d`).**

#### What Was Changed

| File | Change |
|---|---|
| `network.py` | Removed `pwntools`; stdlib `socket` + `base64` |
| `diffie_hellman.py` | `print()`, `//`, `RSAKey.p` |
| `crypto_protocol.py` | Full bytes/str fix; `//`; `bytes.fromhex`; `encrypt()` → hex string; `decrypt()` ← hex string |
| `gui.py` | `tkinter` (lowercase); `print()` |
| `run.py` | `print()` only |
| `mitm.py` | `print()` only |

#### New Files

| File | Purpose |
|---|---|
| `requirements.txt` | `pycryptodome==3.23.0` |
| `headless_test.py` | Integration: DH + AES round-trip, no GUI |
| `headless_mitm_test.py` | Integration: MITM parameter injection, no GUI |
| `IMPLEMENTATION_PLAN.md` | This document |

#### Verified Test Output

```
$ venv\Scripts\python diffie_hellman.py
[+] DH self-test passed

$ venv\Scripts\python crypto_protocol.py
[+] CBC decrypt(encrypt(text))==text test passed

$ venv\Scripts\python headless_test.py
[PASS] All messages round-tripped correctly.

$ venv\Scripts\python headless_mitm_test.py
[MITM] Intercepted: Attack at dawn
[MITM] Intercepted: Bank PIN is 1234
[MITM] Intercepted: Top secret data
[PASS] MITM attack succeeded — unauthenticated DH is broken.
```

#### ⚠️ GUI Check (run manually before marking done)

```powershell
# Terminal 1:  venv\Scripts\activate && python run.py 9000
# Terminal 2:  venv\Scripts\activate && python run.py 127.0.0.1 9000
# Send messages; confirm both Tkinter windows show text.
```

---

### ✅ PHASE 1: `--secure` Flag Plumbing + Mode Banner + stdin Chat

**Status: COMPLETE. Git tag: `phase-1`.**

#### Goal

Add `--secure` and `--no-gui` to both `run.py` and `mitm.py`. `--secure` is a no-op
in this phase (banner only). `--no-gui` replaces the GUI thread with a stdin reader
thread that subprocess-based tests can drive by writing lines to stdin.

#### Files Modified

| File | Changes |
|---|---|
| `run.py` | `argparse`; `parse_args()`; `print_banner()`; `StdinReaderThread`; `--no-gui` guards |
| `mitm.py` | `argparse`; `parse_args()`; `print_banner()`; `log_intercept()`; `--no-gui` guards |

#### Files Created

| File | Purpose |
|---|---|
| `tests/__init__.py` | Makes `tests/` a package |
| `tests/test_args.py` | Unit tests for `parse_args()` and `print_banner()` |

#### Design Notes

**stdin reader thread (run.py, `--no-gui` path):**
```python
class StdinReaderThread(threading.Thread):
    daemon = True
    def run(self):
        for line in sys.stdin:
            text = line.rstrip('\n')
            if text:
                send_message(text)
                print(f"[Me] {text}", flush=True)
```
A subprocess test writes UTF-8 lines to the client's `stdin`; the thread picks them
up and calls `send_message`. The server prints `[Other] <text>` to stdout which the
test reads from the server's stdout pipe.

**`--secure` banner (Phase 1 only — no crypto change):**
```
[*] DH Chat | Role: Server | Mode: SECURE (signed DH — Phase 3 not yet active)
```
In Phase 3, this banner changes to `SECURE (signed DH — ACTIVE)` and the flag wires
into the handshake functions.

**mitm.py `--secure` meaning:**  
In Phase 1 it prints a banner only. In Phase 4 it will: (a) read the signed wire
format from server and client, (b) strip the real signature, (c) substitute its own
DH value with a garbage/replayed signature, and (d) forward to the other side. The
endpoints will reject the forged signature and abort.

---

### 🔲 PHASE 2: Crypto Modernization

**Goal:** AES-256-GCM, HKDF-SHA-256, RFC 3526 2048-bit MODP group everywhere.
Protocol remains MITM-vulnerable (no signatures yet). `--toy-params` is dropped.

**Branch:** `feat/modern-crypto`

#### Files to Modify

| File | Change |
|---|---|
| `diffie_hellman.py` | Replace random prime + random g with RFC 3526 constants; verify prime; `secrets.randbelow` |
| `crypto_protocol.py` | Replace AES-128-CBC + SHA-256 KDF with AES-256-GCM + HKDF; drop PKCS#7 helpers |
| `requirements.txt` | Add `cryptography>=42.0.0` |
| `README.md` | Fix any wording that still says "AES-CBC" |
| `DEMO.md` | Fix talk track (line "Wireshark shows only ciphertext" is fine; remove any CBC-specific claim) |

#### `diffie_hellman.py` — Function Changes

```python
import secrets
from Crypto.PublicKey import RSA  # kept for generate_prime() in __main__ self-test only

# RFC 3526 group 14 — 2048-bit MODP (https://www.rfc-editor.org/rfc/rfc3526#section-3)
RFC3526_P = int(
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
RFC3526_G = 2

def _verify_rfc3526_group() -> None:
    """Assert p is 2048-bit and (p-1)/2 is prime. Called once at import."""
    assert RFC3526_P.bit_length() == 2048, "p must be 2048 bits"
    q = (RFC3526_P - 1) // 2
    # Miller-Rabin is not imported here; we trust the RFC constant but at least
    # check bit length and that g^q ≡ 1 (mod p) [order-q subgroup].
    assert pow(RFC3526_G, q, RFC3526_P) == 1, "g must be in the order-q subgroup"

_verify_rfc3526_group()   # runs at import time

class DiffieHellman:
    def __init__(self, p=None, g=None):
        """
        If p/g provided (client path): MUST equal RFC 3526 constants or raise ValueError.
        If not provided (server path): use RFC 3526 constants.
        Private exponent: fresh secrets.randbelow(RFC3526_P) per instance.
        """
        if p is not None:
            if p != RFC3526_P or g != RFC3526_G:
                raise ValueError(
                    "Rejected: p/g do not match RFC 3526 2048-bit MODP group. "
                    "Possible parameter injection attack.")
        self.p = RFC3526_P
        self.g = RFC3526_G
        self.private_exponent = secrets.randbelow(RFC3526_P - 2) + 2  # in [2, p-2]

    def generate_public_broadcast(self) -> tuple:
        return self.p, self.g, pow(self.g, self.private_exponent, self.p)

    @staticmethod
    def validate_public_value(value: int, p: int) -> None:
        """Raise ValueError if value is outside (1, p-1) — prevents small-subgroup attack."""
        if not (1 < value < p - 1):
            raise ValueError(f"Received DH public value {value!r} is out of range (1, p-1).")

    def get_shared_secret(self, public_share: int) -> int:
        self.validate_public_value(public_share, self.p)
        return pow(public_share, self.private_exponent, self.p)
```

**`run.py` client path change:** after `A = int(get_line())`, call
`DiffieHellman.validate_public_value(A, RFC3526_P)` before accepting the value.

#### `crypto_protocol.py` — Class Rewrite

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os, secrets

class CryptoProtocol:
    def __init__(self, shared_secret: int):
        raw = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        # HKDF-SHA-256 → 32 bytes → AES-256 key
        # Why HKDF: standard KDF (RFC 5869); stretches non-uniform DH secret to uniform key
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'dh-chat-v2')
        self.key = hkdf.derive(raw)

    def encrypt(self, data: str) -> str:
        nonce = os.urandom(12)                     # 96-bit GCM nonce; unique per message
        ct = AESGCM(self.key).encrypt(nonce, data.encode('utf-8'), None)
        return (nonce + ct).hex()

    def decrypt(self, data: str) -> str:
        raw = bytes.fromhex(data)
        nonce, ct = raw[:12], raw[12:]
        pt = AESGCM(self.key).decrypt(nonce, ct, None)  # raises InvalidTag if tampered
        return pt.decode('utf-8')
```

Keep the old `AES_128_CBC_*` and PKCS#7 functions **only** if the `--main` self-test
in `crypto_protocol.py` still needs them; otherwise delete them.

#### Verifying MITM Vulnerability Is Still Present (Go/No-Go)

```bash
venv\Scripts\python headless_mitm_test.py
# Must still print: [PASS] MITM attack succeeded
```
If this fails, stop and investigate before Phase 3.

#### Automated Tests

```python
# tests/test_crypto_v2.py
# 1. test_roundtrip(): cp.decrypt(cp.encrypt("hello")) == "hello"
# 2. test_tamper_detection(): flip one byte in hex → decrypt raises InvalidTag
# 3. test_nonce_uniqueness(): same plaintext encrypted twice → different hex
# 4. test_key_deterministic(): same shared_secret → same key
# 5. test_rfc3526_group(): DiffieHellman() uses RFC3526_P and RFC3526_G
# 6. test_bad_params_rejected(): DiffieHellman(p=bad, g=2) raises ValueError
# 7. test_public_value_range(): validate_public_value(0, p) raises ValueError
#                               validate_public_value(p-1, p) raises ValueError
```

#### Commit

```
git commit -m "phase-2: AES-256-GCM, HKDF-SHA-256, RFC 3526 2048-bit MODP; reject bad params; MITM still works"
```

---

### 🔲 PHASE 3: Signature Layer (`--secure` Activates)

**Goal:** When `--secure` is passed, the handshake is authenticated with RSA-PSS/SHA-512
and domain-separated signed data. The protocol rejects any p/g that isn't the RFC 3526
group and validates received public values before trusting them.

**Why RSA-PSS/SHA-512:** Maps to IS Unit III (RSA) and Unit IV (SHA-512, digital signatures).
PSS is the provably-secure RSA padding scheme.

**Branch:** `feat/signed-dh`

#### Files to Create/Modify

| File | Action |
|---|---|
| `auth_dh.py` | **CREATE**: sign, verify, load/save keys, `HandshakeError` |
| `gen_keys.py` | **CREATE**: generate RSA-2048 key pairs; refuse to overwrite |
| `crypto_protocol.py` | **ADD**: `secure_handshake_server()`, `secure_handshake_client()` |
| `run.py` | **MODIFY**: call secure handshake in `--secure` mode; catch `HandshakeError` |
| `mitm.py` | **NO CHANGE** to handshake in Phase 3; Phase 4 adds forgery |
| `.gitignore` | **ADD**: `*.pem` (all PEM files, including public keys) |
| `requirements.txt` | Confirm `cryptography>=42.0.0` present |

#### `auth_dh.py` — Complete API

```python
"""
auth_dh.py: RSA-PSS/SHA-512 signing for DH authentication.
Why PSS: provably secure; PKCS#1-v1.5 has known weaknesses.
Why SHA-512: maps to IS Unit IV topic SHA-512.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class HandshakeError(Exception):
    """Raised when signature verification fails during DH handshake.
    Callers (run.py) must catch this, print an abort message, and close the socket.
    Library code (auth_dh, crypto_protocol) must NOT call sys.exit()."""

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                   salt_length=padding.PSS.MAX_LENGTH)

def generate_keypair(bits: int = 2048) -> tuple:
    """Generate RSA key pair. Returns (private_key, public_key)."""

def save_private_key(private_key, path: str) -> None:
    """Save unencrypted PKCS8 PEM. Demo only — real systems encrypt this."""

def save_public_key(public_key, path: str) -> None:
    """Save SubjectPublicKeyInfo PEM."""

def load_private_key(path: str):
    """Load private key from PEM file."""

def load_public_key(path: str):
    """Load public key from PEM file."""

def sign(private_key, data: bytes) -> bytes:
    """RSA-PSS/SHA-512 sign. Returns raw signature bytes."""

def verify(public_key, signature: bytes, data: bytes) -> None:
    """RSA-PSS/SHA-512 verify. Raises HandshakeError on failure.
    Does not return a bool — callers must use try/except HandshakeError."""
```

#### `gen_keys.py`

```python
"""
gen_keys.py — run ONCE before the demo:  python gen_keys.py
Generates alice_priv.pem, alice_pub.pem, bob_priv.pem, bob_pub.pem.
Refuses to overwrite any existing key file to prevent accidental key churn.
"""
import os
from auth_dh import generate_keypair, save_private_key, save_public_key

for name in ('alice', 'bob'):
    priv_path = f'{name}_priv.pem'
    pub_path  = f'{name}_pub.pem'
    if os.path.exists(priv_path) or os.path.exists(pub_path):
        print(f'[!] Keys for {name} already exist ({priv_path}, {pub_path}). '
              f'Delete them manually if you really want to regenerate.')
        continue
    priv, pub = generate_keypair()
    save_private_key(priv, priv_path)
    save_public_key(pub, pub_path)
    print(f'[+] Generated: {priv_path}, {pub_path}')

print('[!] Keys are NOT committed to git (*.pem is in .gitignore).')
print('[!] Distribute *_pub.pem to the peer out-of-band (USB, face-to-face).')
```

#### Signed Data Format and Domain Separation

```
Server signs:  b"server-hello" + A_bytes
  Why "server-hello" label: domain separation — a valid server signature cannot be
  replayed as a client signature, preventing cross-role replay.

Client signs:  b"client-hello" + B_bytes + A_bytes
  Why include A_bytes in client's signature: binds the client's reply to this specific
  server hello. Prevents Mallory from replaying Bob's (B, sig_B) in a future session
  with a different A.

Both use:      A_bytes = server's DH public value as big-endian bytes
               B_bytes = client's DH public value as big-endian bytes
               (integers converted with .to_bytes((n.bit_length()+7)//8, 'big'))
```

#### Wire Order (Secure Mode)

```
Server → Client:  A_hex        (str: big-endian bytes of A as hex)
Server → Client:  sig_A_hex    (str: signature bytes as hex)
Client verifies:  verify(bob_pub, sig_A, b"server-hello" + bytes.fromhex(A_hex))
                  → raises HandshakeError if wrong
Client → Server:  B_hex
Client → Server:  sig_B_hex    (signature over b"client-hello" + B_bytes + A_bytes)
Server verifies:  verify(alice_pub, sig_B, b"client-hello" + B_bytes + A_bytes)
                  → raises HandshakeError if wrong
Both compute:     K = get_shared_secret(peer_value)
                  → validate_public_value() called inside get_shared_secret
```

#### Handshake Functions in `crypto_protocol.py`

```python
def secure_handshake_server(conn, dh, own_priv_key, peer_pub_key) -> 'CryptoProtocol':
    """
    Perform the server side of the signed DH handshake.
    Uses RFC 3526 group (already set in dh).
    Signs b"server-hello" + A_bytes with own_priv_key (RSA-PSS/SHA-512).
    Receives B_hex + sig_B_hex; verifies sig over b"client-hello" + B_bytes + A_bytes.
    Raises HandshakeError on any verification failure (caller must catch).
    Returns: CryptoProtocol keyed to the shared secret.
    """

def secure_handshake_client(conn, dh, own_priv_key, peer_pub_key) -> 'CryptoProtocol':
    """
    Perform the client side of the signed DH handshake.
    Receives A_hex + sig_A_hex; verifies sig over b"server-hello" + A_bytes.
    Signs b"client-hello" + B_bytes + A_bytes with own_priv_key.
    Raises HandshakeError on any verification failure.
    Returns: CryptoProtocol keyed to the shared secret.
    """
```

#### `run.py` Integration (Secure Mode)

```python
from auth_dh import load_private_key, load_public_key, HandshakeError
from crypto_protocol import secure_handshake_server, secure_handshake_client

if len(args.positional) == 1:   # server = Bob
    ...
    if args.secure:
        try:
            own_priv = load_private_key('bob_priv.pem')
            peer_pub  = load_public_key('alice_pub.pem')
            crypto_protocol = secure_handshake_server(conn, dh, own_priv, peer_pub)
        except HandshakeError as e:
            print(f"[SECURE] Signature verification FAILED: {e}")
            print("[SECURE] Possible man-in-the-middle attack. Aborting connection.")
            conn._sock.close()
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"[ERROR] Key file not found: {e}")
            print("[ERROR] Run 'python gen_keys.py' first.")
            sys.exit(1)
    else:
        # unchanged vulnerable path
        ...
```

Same pattern for the client branch (loads `alice_priv.pem`, `bob_pub.pem`).

#### `.gitignore` Addition

```
# ALL PEM key files — never commit private OR public keys
# Distribute *_pub.pem out-of-band (USB / face-to-face)
*.pem
# MFA user database
users.json
```

#### Automated Tests

```python
# tests/test_auth_dh.py
# 1.  test_sign_verify_roundtrip()
# 2.  test_tampered_data_raises()
# 3.  test_wrong_key_raises()
# 4.  test_handshake_error_not_sys_exit(): verify raises HandshakeError not SystemExit
# 5.  test_domain_separation(): sig made with "server-hello" does NOT verify under "client-hello"
# 6.  test_client_sig_binds_A(): sig over (B + A1) does NOT verify under A2
# 7.  test_gen_keys_no_overwrite(): gen_keys.py refuses if files exist
# 8.  test_secure_handshake_e2e(): two threads, --secure, messages flow
```

#### Commit

```
git commit -m "phase-3: RSA-PSS/SHA-512 signed DH; domain labels; HandshakeError; gen_keys.py; *.pem ignored"
```

---

### 🔲 PHASE 4: Show the Attack Failing + Full MITM Forgery

**Goal:** `mitm.py --secure` actually implements the secure wire format (reads A_hex,
sig_A_hex from server; sends B_hex, forged_sig_hex to client). The forgery uses
Mallory's own signature (signed with a key Alice doesn't have) or a garbage byte string.
Both endpoints detect the mismatch and abort with the `HandshakeError` path.

**Branch:** `feat/attack-demo`

#### `mitm.py` — Secure Mode Handshake

In `--secure` mode, `mitm.py` must speak the full signed wire format:

```python
if args.secure:
    print("[MITM] Secure mode: reading signed wire format; attempting forgery...")

    # --- Mallory ↔ Server (Bob) side ---
    # Receive Bob's signed hello
    A_hex     = get_line(conn_server)
    sig_A_hex = get_line(conn_server)
    # Mallory cannot verify this (she doesn't have Alice's key to check Bob's claim)
    # but she READS it so the server doesn't hang.

    # Create Mallory's own DH toward Bob
    dh_s = DiffieHellman()
    _, _, B_mal = dh_s.generate_public_broadcast()
    B_mal_bytes = B_mal.to_bytes((B_mal.bit_length()+7)//8, 'big')

    # FORGERY: Mallory signs with her own key (which Bob's verify() will reject)
    # or sends a garbage signature — either way Bob's verify() raises HandshakeError.
    forged_sig = b'\x00' * 256   # 256 zero bytes — obviously not a valid RSA-PSS sig
    conn_server.send(B_mal_bytes.hex())
    conn_server.send(forged_sig.hex())
    print("[MITM] Sent forged B + garbage signature to server.")

    # --- Mallory ↔ Client (Alice) side ---
    # Alice's client will call verify(bob_pub, sig, b"server-hello" + A_bytes).
    # Mallory forwards Bob's real A_hex but with a forged (garbage) sig.
    # Or she substitutes her own A_mal with the same garbage sig.
    # Either way, Alice's verify() will raise HandshakeError and abort.
    A_mal = dh_s.generate_public_broadcast()[2]   # Mallory's A toward Alice
    A_mal_bytes = A_mal.to_bytes((A_mal.bit_length()+7)//8, 'big')
    conn_client.send(A_mal_bytes.hex())
    conn_client.send(forged_sig.hex())
    print("[MITM] Sent forged A + garbage signature to client.")
    print("[MITM] Endpoints should now abort with HandshakeError.")
    # No relay possible — both sides will disconnect
```

#### Automated Tests (`tests/test_secure_vs_mitm.py`)

```python
# 1. test_vulnerable_chat_works()       — no MITM, --no-gui, 3 messages received
# 2. test_mitm_breaks_vulnerable()      — MITM reads plaintext in vulnerable mode
# 3. test_secure_chat_works()           — no MITM, --secure, messages flow
# 4. test_mitm_fails_secure()           — MITM, --secure → HandshakeError abort msg in stdout
# 5. test_tampered_sig_rejected()       — manually corrupt one sig byte → HandshakeError
# 6. test_replayed_sig_rejected()       — use sig(B+A1) for session with A2 → HandshakeError
# 7. test_wrong_peer_key_rejected()     — verify with wrong public key → HandshakeError
# 8. test_domain_label_enforced()       — "server-hello" sig won't pass "client-hello" check
```

#### Expected Abort Output (test 4)

```
[Server] [SECURE] Signature verification FAILED: ...
[Server] [SECURE] Possible man-in-the-middle attack. Aborting connection.
[Client] [SECURE] Signature verification FAILED: ...
[Client] [SECURE] Possible man-in-the-middle attack. Aborting connection.
[MITM]   Sent forged B + garbage signature to server.
[MITM]   Sent forged A + garbage signature to client.
[MITM]   Endpoints should now abort with HandshakeError.
```

#### Commit

```
git commit -m "phase-4: mitm.py speaks secure wire format and attempts forgery; 8 scenario tests"
```

---

### 🔲 PHASE 5: AVISPA Formal Verification

**Goal:** Model both protocol variants in valid HLPSL. Run OFMC (and CL-AtSe) to get
UNSAFE + SAFE results. Screenshot outputs for slides and report.

> ⚠️ **The HLPSL skeletons below were NOT run through AVISPA** (no AVISPA installation
> was available during plan creation). They must be verified and debugged against a real
> AVISPA binary or the web interface before submission. Do not include unrun results.

**Branch:** `feat/avispa`

#### Files to Create

| File | Purpose |
|---|---|
| `avispa/dh_unauth.hlpsl` | Unauthenticated DH — expected UNSAFE |
| `avispa/dh_auth.hlpsl` | Signed DH — expected SAFE |
| `avispa/README_avispa.md` | Install, run, interpret instructions |
| `docs/avispa_unsafe.png` | OFMC screenshot (from actual run) |
| `docs/avispa_safe.png` | OFMC screenshot (from actual run) |

#### `dh_unauth.hlpsl` — Valid HLPSL (UNRUN — must be tested)

```hlpsl
%%% dh_unauth.hlpsl
%%% Protocol: Unauthenticated Diffie-Hellman key exchange.
%%% Intruder model: Dolev-Yao.
%%% Expected result: UNSAFE (MITM attack trace found).
%%%
%%% Abstraction: g^a is modelled as a fresh value Ga (nonce).
%%% The shared secret is modelled as the peer's public value (Gb or Ga)
%%% because under Dolev-Yao the intruder can substitute it.

role alice(A, B : agent,
           SND, RCV : channel(dy))
played_by A def=

  local  State   : nat,
         Ga, Gb  : text

  init   State := 0

  transition

    1. State  = 0 /\ RCV(start) =|>
       State' := 1
       /\ Ga'  := new()
       /\ SND(Ga')                          %% Alice sends A = g^a unauthenticated

    2. State  = 1 /\ RCV(Gb?) =|>           %% Receive any value claiming to be g^b
       State' := 2
       /\ witness(A, B, alice_bob_a, Ga)
       /\ secret(Gb, sec_k_alice, {A, B})   %% Alice believes Gb is secret with Bob

end role


role bob(A, B : agent,
         SND, RCV : channel(dy))
played_by B def=

  local  State   : nat,
         Ga, Gb  : text

  init   State := 0

  transition

    1. State  = 0 /\ RCV(Ga?) =|>           %% Receive any value claiming to be g^a
       State' := 1
       /\ Gb'  := new()
       /\ SND(Gb')                          %% Bob sends B = g^b unauthenticated
       /\ request(B, A, alice_bob_a, Ga)
       /\ secret(Ga, sec_k_bob, {A, B})     %% Bob believes Ga is secret with Alice

end role


role session(A, B : agent) def=
  local SA, RA, SB, RB : channel(dy)
  composition
       alice(A, B, SA, RA)
    /\ bob(A, B, SB, RB)
end role


role environment() def=
  const alice, bob             : agent,
        sec_k_alice, sec_k_bob : protocol_id,
        alice_bob_a            : protocol_id,
        start                  : protocol_id

  intruder_knowledge = {alice, bob}

  composition
       session(alice, bob)
    /\ session(alice, i)
    /\ session(i, bob)

end role


goal
  secrecy_of sec_k_alice, sec_k_bob
  authentication_on alice_bob_a
end goal

environment()
```

#### `dh_auth.hlpsl` — Valid HLPSL (UNRUN — must be tested)

```hlpsl
%%% dh_auth.hlpsl
%%% Protocol: Signed Diffie-Hellman (our Phase 3 design).
%%% Signed data:
%%%   Server (Bob) signs: b"server-hello" || A
%%%   Client (Alice) signs: b"client-hello" || B || A
%%% Modelled with HLPSL public-key signing: {data}_inv(K) = signed with K.
%%% Expected result: SAFE.

role alice(A, B        : agent,
           Ka, Kb      : public_key,
           SND, RCV    : channel(dy))
played_by A def=

  local  State            : nat,
         Ga, Gb           : text,
         Server_label     : text,
         Client_label     : text

  init   State        := 0

  transition

    %%% Step 1: receive Bob's signed hello
    1. State  = 0 /\ RCV(start) =|>
       State' := 1
       /\ Ga' := new()

    %%% Alice waits for (Gb, sig_B) where sig_B = sign_Bob("server-hello" . Gb)
    2. State  = 1 /\ RCV({xserver_label.Gb?}_inv(Kb)) =|>
       State' := 2
       /\ witness(A, B, alice_bob_ga, Ga)
       /\ SND({xclient_label.Ga.Gb?}_inv(Ka))   %% Alice signs "client-hello" || Ga || Gb
       /\ secret(Gb, sec_key, {A, B})

end role


role bob(A, B       : agent,
         Ka, Kb     : public_key,
         SND, RCV   : channel(dy))
played_by B def=

  local  State           : nat,
         Ga, Gb          : text,
         Server_label    : text,
         Client_label    : text

  init   State       := 0

  transition

    %%% Step 1: Bob sends his DH value signed with "server-hello" label
    1. State  = 0 /\ RCV(start) =|>
       State' := 1
       /\ Gb' := new()
       /\ SND({xserver_label.Gb'}_inv(Kb))      %% Bob signs "server-hello" || Gb

    %%% Step 2: receive Alice's signed reply
    2. State  = 1 /\ RCV({xclient_label.Ga?.Gb}_inv(Ka)) =|>
       State' := 2
       /\ request(B, A, alice_bob_ga, Ga)
       /\ secret(Ga, sec_key, {A, B})

end role


role session(A, B : agent, Ka, Kb : public_key) def=
  local SA, RA, SB, RB : channel(dy)
  composition
       alice(A, B, Ka, Kb, SA, RA)
    /\ bob(A, B, Ka, Kb, SB, RB)
end role


role environment() def=
  const alice, bob             : agent,
        ka, kb                 : public_key,
        sec_key                : protocol_id,
        alice_bob_ga           : protocol_id,
        start                  : protocol_id,
        xserver_label          : text,
        xclient_label          : text

  intruder_knowledge = {alice, bob, ka, kb, xserver_label, xclient_label}

  composition
       session(alice, bob, ka, kb)
    /\ session(alice, i, ka, ki)
    /\ session(i, bob, ki, kb)

end role


goal
  secrecy_of sec_key
  authentication_on alice_bob_ga
end goal

environment()
```

#### Notes on the HLPSL Models

1. **Not run** — these skeletons model the exact signed data per our Phase 3 design.
   Syntax may need adjustment for the AVISPA version you install. Common issues:
   `xserver_label` as a `text` constant vs a built-in; use of `?` pattern matching;
   `ki` for the intruder's key needing a different declaration.
2. **What the models do verify (if AVISPA accepts them):**
   - `dh_unauth.hlpsl`: The intruder can substitute Ga/Gb freely → `sec_key` is not
     secret → UNSAFE → attack trace shows parameter injection.
   - `dh_auth.hlpsl`: The intruder cannot forge the public-key signature → cannot
     produce `{xserver_label.forged_Gb}_inv(Kb)` without Kb's private key → SAFE.
3. **What the models do NOT verify:** Implementation bugs, side channels, key loading
   errors, the HKDF step, or any attacks outside the Dolev-Yao model.

#### How to Run

```bash
# Option A — local install (Linux or WSL):
./avispa --ofmc avispa/dh_unauth.hlpsl
./avispa --ofmc avispa/dh_auth.hlpsl
./avispa --cl-atse avispa/dh_auth.hlpsl   # second back-end

# Option B — web interface:
# https://avispa-project.org/ → paste HLPSL → select OFMC → Verify
# Screenshot the SUMMARY and DETAILS lines.
```

#### Commit

```
git commit -m "phase-5: AVISPA HLPSL models (unauth/auth); run and screenshot before submitting"
```

---

### 🔲 PHASE 6: MFA — TOTP Login (Inside the AES-GCM Channel)

**Goal:** After the DH handshake completes (and the AES-GCM session key is established),
run a TOTP + password login **inside the encrypted channel**. This means the OTP code
is never transmitted in plaintext — the AES-GCM channel protects it in transit.

**Why inside the channel:** MFA credentials are sensitive. Sending them before
encryption is set up would expose them to eavesdroppers. The DH handshake (possibly
signed in `--secure` mode) establishes the session key first; then the login challenge
rides inside that encrypted channel.

**Branch:** `feat/mfa`

#### Files to Create/Modify

| File | Action |
|---|---|
| `mfa.py` | **CREATE**: enrollment, verification, lockout |
| `enroll.py` | **CREATE**: one-shot enrollment CLI |
| `run.py` | **MODIFY**: if `--mfa`, call `mfa_login_server/client` after `CryptoProtocol` is ready |
| `requirements.txt` | Add `pyotp>=2.9.0`, `qrcode>=7.4`, `Pillow>=10.0` |

#### MFA Protocol (inside AES-GCM channel)

```
Client → Server:  Enc_K("MFA_USERNAME:" + username)
Server → Client:  Enc_K("MFA_CHALLENGE")
Client → Server:  Enc_K("MFA_CREDS:" + password + ":" + totp_code)
Server verifies; sends:
  on success: Enc_K("MFA_OK")
  on failure: Enc_K("MFA_FAIL:" + reason)
If MFA_FAIL: both sides close connection.
```

All messages go through `conn.send(crypto_protocol.encrypt(...))` and
`crypto_protocol.decrypt(conn.recv())` — the same channel used for chat.

#### `mfa.py` — API

```python
def enroll_user(username: str, password: str, users_file: str = 'users.json') -> str:
    """Create user record; return TOTP provisioning URI."""

def save_qr(uri: str, path: str) -> None:
    """Save QR PNG using qrcode + Pillow."""

def hash_password(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA512, 200 000 iterations. Returns 64-byte digest."""

def verify_login(username: str, password: str, totp_code: str,
                 users_file: str = 'users.json') -> tuple[bool, str]:
    """
    Returns (True, '') or (False, reason).
    Reasons: 'USER_NOT_FOUND', 'WRONG_PASSWORD', 'WRONG_OTP', 'LOCKED_OUT'.
    Enforces 3-attempt lockout with 30-second cooldown.
    Uses hmac.compare_digest for timing-safe password comparison.
    """

def mfa_server_side(conn, crypto_protocol) -> bool:
    """
    Read username/password/OTP from encrypted channel, verify, send MFA_OK or MFA_FAIL.
    Returns True on success. Caller closes conn on False.
    """

def mfa_client_side(conn, crypto_protocol, username: str, password: str, totp_code: str) -> bool:
    """
    Send credentials over encrypted channel, receive result.
    Returns True on MFA_OK, False on MFA_FAIL.
    Caller closes conn on False.
    """
```

#### `run.py` Integration

```python
# After CryptoProtocol is constructed (both server and client):
if args.mfa:
    from mfa import mfa_server_side, mfa_client_side
    if is_server:
        ok = mfa_server_side(conn, crypto_protocol)
    else:
        username = input("Username: ")
        password = input("Password: ")
        totp_code = input("OTP code: ")
        ok = mfa_client_side(conn, crypto_protocol, username, password, totp_code)
    if not ok:
        print("[MFA] Login failed. Closing connection.")
        conn._sock.close()
        sys.exit(1)
    print("[MFA] Login successful. Proceeding to chat.")
```

#### Automated Tests

```python
# tests/test_mfa.py
# 1. test_enroll_creates_record()
# 2. test_correct_login()
# 3. test_wrong_password()
# 4. test_wrong_otp()
# 5. test_lockout_after_3_failures()
# 6. test_lockout_expires_after_30s()  (mock time)
# 7. test_hash_deterministic()
# 8. test_timing_safe_compare()  (hmac.compare_digest used, not ==)
# 9. test_mfa_over_channel_e2e()  (two threads, MFA handshake completes)
```

#### Commit

```
git commit -m "phase-6: TOTP+PBKDF2-SHA512 MFA inside AES-GCM channel; mfa.py; enroll.py"
```

---

### 🔲 PHASE 7: Docs, Polish, and Final Cleanup

**Goal:** Professional README, DEMO.md, Mermaid sequence diagrams, docs/ folder,
original author credit, clean-environment test.

**Branch:** `feat/docs`

#### Files to Create/Modify

| File | Action |
|---|---|
| `README.md` | Rewrite with credit, all modes, install |
| `DEMO.md` | 10-min demo runbook (Part 5 of this document) |
| `docs/diagram_normal_dh.md` | Mermaid — normal DH chat |
| `docs/diagram_mitm_attack.md` | Mermaid — parameter injection |
| `docs/diagram_signed_dh.md` | Mermaid — signed DH, MITM fails |
| `docs/avispa_unsafe.png` | From actual AVISPA run |
| `docs/avispa_safe.png` | From actual AVISPA run |
| `.gitignore` | Verify `venv/`, `*.pem`, `users.json`, `__pycache__/` all present |

#### Clean-Environment Test

```powershell
python -m venv venv_test
venv_test\Scripts\pip install -r requirements.txt
venv_test\Scripts\python diffie_hellman.py
venv_test\Scripts\python crypto_protocol.py
venv_test\Scripts\python headless_test.py
venv_test\Scripts\python headless_mitm_test.py
venv_test\Scripts\python -m pytest tests/ -v
```
All must pass. Remove `venv_test/` after.

#### Commit

```
git commit -m "phase-7: README, DEMO.md, Mermaid diagrams, docs/, clean-env test passes"
```

---

## PART 4 — FINAL TARGET REPO TREE

```
DiffieHellman_V2/
│
├── run.py                    Server (1 arg) or client (2 args); --secure; --no-gui; --mfa
├── mitm.py                   MITM proxy; --secure speaks signed wire format + attempts forgery
├── network.py                Stdlib TCP; base64-framed newline-delimited messages
├── diffie_hellman.py         RFC 3526 2048-bit DH; validate_public_value; secrets.randbelow
├── crypto_protocol.py        AES-256-GCM + HKDF; secure_handshake_server/client
├── gui.py                    Tkinter chat GUI (skipped via --no-gui)
├── auth_dh.py                RSA-PSS/SHA-512 sign/verify; HandshakeError (Phase 3)
├── gen_keys.py               RSA-2048 keygen; refuses to overwrite (Phase 3)
├── enroll.py                 TOTP enrollment → users.json + QR PNG (Phase 6)
├── mfa.py                    PBKDF2+TOTP login; lockout; mfa_server/client_side (Phase 6)
│
├── headless_test.py          Integration: DH + AES round-trip, no GUI
├── headless_mitm_test.py     Integration: MITM parameter injection, no GUI
│
├── tests/
│   ├── __init__.py
│   ├── test_args.py          argparse correctness (Phase 1) ✅
│   ├── test_crypto_v2.py     AES-GCM + HKDF + RFC 3526 (Phase 2)
│   ├── test_auth_dh.py       RSA sign/verify + HandshakeError (Phase 3)
│   ├── test_secure_vs_mitm.py  All 8 scenarios (Phase 4)
│   └── test_mfa.py           TOTP + lockout (Phase 6)
│
├── avispa/
│   ├── dh_unauth.hlpsl       HLPSL: unauthenticated DH (expected UNSAFE)
│   ├── dh_auth.hlpsl         HLPSL: signed DH (expected SAFE)
│   └── README_avispa.md      Install, run, interpret
│
├── docs/
│   ├── diagram_normal_dh.md
│   ├── diagram_mitm_attack.md
│   ├── diagram_signed_dh.md
│   ├── avispa_unsafe.png     (from actual AVISPA run)
│   └── avispa_safe.png       (from actual AVISPA run)
│
├── report/                   Original authors' report — kept unchanged
├── requirements.txt          pycryptodome, cryptography, pyotp, qrcode, Pillow
├── README.md
├── DEMO.md
├── IS_FA2_Project_Context.md
├── IMPLEMENTATION_PLAN.md
└── .gitignore                *.pem; users.json; venv/; __pycache__/
```

---

## PART 5 — DEMO RUNBOOK

### Pre-Demo Setup (day before)

```powershell
cd c:\Users\ASUS\Desktop\Harsh\PROJECTS\IS_FA2\DiffieHellman_V2
venv\Scripts\activate
python gen_keys.py        # creates *.pem; refuses overwrite if already exist
python enroll.py alice    # creates users.json entry; saves alice_mfa_qr.png
                          # scan alice_mfa_qr.png with Google Authenticator
python -m pytest tests/ -v
python headless_test.py
python headless_mitm_test.py
```

---

### Scenario 1 — Normal Encrypted Chat

```powershell
# Terminal 1 (Bob/server):  venv\Scripts\activate && python run.py 9000
# Terminal 2 (Alice/client): venv\Scripts\activate && python run.py 127.0.0.1 9000
```
**Expected:** Tkinter windows open. Mode banner: `VULNERABLE`. Messages appear encrypted
on Wireshark (`tcp.port == 9000`), plaintext in both GUI windows.

---

### Scenario 2 — MITM Attack (Vulnerable Mode)

```powershell
# Terminal 1: python run.py 9000
# Terminal 2: python mitm.py 127.0.0.1 9000 9001    ← after server starts
# Terminal 3: python run.py 127.0.0.1 9001          ← connects to MITM, not server
```
**Expected:** Three windows. Alice types → Bob sees it. Mallory's terminal shows
`[MITM][client] INTERCEPTED: <plaintext>`.

---

### Scenario 3 — MITM Attack Fails (`--secure`)

```powershell
# Terminal 1: python run.py 9000 --secure
# Terminal 2: python mitm.py 127.0.0.1 9000 9001 --secure
# Terminal 3: python run.py 127.0.0.1 9001 --secure
```
**Expected:**
```
Alice:   [SECURE] Signature verification FAILED: ...
         [SECURE] Possible man-in-the-middle attack. Aborting connection.
Bob:     [SECURE] Signature verification FAILED: ...
Mallory: [MITM] Sent forged A + garbage signature to client.
         [MITM] Endpoints should now abort with HandshakeError.
```

---

### Scenario 4 — MFA Login

```powershell
# Terminal 1: python run.py 9000 --mfa --secure
# Terminal 2: python run.py 127.0.0.1 9000 --mfa --secure
# Prompts: Username: alice  Password: ****  OTP code: <from Authenticator>
```
**Expected (correct code):** `[MFA] Login successful. Proceeding to chat.`  
**Expected (wrong code):** `[MFA] Wrong OTP code. 2 attempts remaining.`  
**Expected (3 failures):** `[MFA] Account locked for 30 seconds.`

---

### 10-Minute Talk Track

| Min | Step | Say |
|---|---|---|
| 0:00 | Title slide | "We break DH, then fix it with signatures, MFA, and formal verification." |
| 1:00 | DH math | "Alice and Bob agree on a shared secret without sending it — eavesdropper must solve discrete log." |
| 2:30 | Scenario 1 | "Wireshark shows only ciphertext. Looks secure." |
| 4:00 | MITM slide | "DH has no authentication. Mallory intercepts before the key exchange." |
| 5:00 | Scenario 2 | "Same two parties, Mallory in the middle. She reads every message in plaintext." |
| 6:30 | Fix slide | "RSA-PSS/SHA-512 signature on the DH value. Labels prevent cross-role replay. Mallory cannot forge." |
| 7:00 | Scenario 3 | "Same attack code — connection aborted by both endpoints." |
| 8:00 | Scenario 4 | "MFA inside the encrypted channel. Stolen password alone is not enough." |
| 9:00 | AVISPA | "Formal verification: tool says UNSAFE without signatures, SAFE with." |
| 9:45 | Syllabus slide | "Units I (MITM), III (DH, AES, RSA), IV (signatures, SHA-512, MFA, AVISPA)." |

---

## PART 6 — SECURITY ANALYSIS

### What `--secure` Protects

| Threat | Protected? | Why |
|---|---|---|
| Passive eavesdropper | ✅ Both modes | AES-256-GCM; eavesdropper cannot compute DH secret |
| Active MITM substituting DH values | ✅ `--secure` | Cannot forge RSA-PSS/SHA-512 signature |
| Small-subgroup attack on DH | ✅ Phase 2+ | `validate_public_value` rejects out-of-range values |
| Parameter injection (bad p/g) | ✅ Phase 2+ | Client rejects non-RFC-3526 parameters |
| Ciphertext tampering | ✅ Phase 2+ | AES-GCM authentication tag |
| Password-only login | ✅ Phase 6 | TOTP required |
| Cross-role signature replay | ✅ Phase 3+ | Domain labels: "server-hello" vs "client-hello" |
| Session-binding replay | ✅ Phase 3+ | Client's sig covers B+A; old sig won't match new A |

### What `--secure` Does NOT Protect

| Threat | Not Protected | Smallest Fix |
|---|---|---|
| Long-term key compromise | ❌ | Ephemeral signing keys (SIGMA-style) |
| No forward secrecy | ❌ | Fresh ephemeral DH even for signing layer |
| No PKI | ❌ | X.509 certificates + CA — that's TLS |
| Trust-on-first-use | ❌ | Out-of-band fingerprint verification |
| Identity not bound in server sig | partial | Already fixed: domain label "server-hello" identifies role |
| MFA credentials in plaintext (pre-Phase 6 design) | ✅ Fixed in Phase 6 | MFA runs inside AES-GCM channel |

---

## PART 7 — RISK REGISTER

| # | Risk | Likelihood | Impact | Mitigation | Fallback |
|---|---|---|---|---|---|
| R1 | AVISPA install fails on Windows | High | Medium | Use WSL or AVISPA web tool | Show pre-run screenshots from teammate's Linux |
| R2 | Tkinter not working on demo machine | Low | High | Test GUI day before; have `--no-gui` ready | Use `--no-gui` + terminal printout |
| R3 | Demo is slow during key operations | Low | Low | RFC 3526 group constants eliminate RSA.generate; DH public value computation takes < 0.1 s on modern hardware | Pre-warm by running `python diffie_hellman.py` once |
| R4 | Private key accidentally committed | Medium | High | `*.pem` in `.gitignore`; check with `git status` before every push | `git filter-repo --path-glob '*.pem' --invert-paths` |
| R5 | GUI demo crashes during presentation | Medium | High | Rehearse 3×; record backup video | Play pre-recorded video |
| R6 | Team member unavailable on demo day | Low | High | All 4 members can run all scenarios | Any one member can do solo demo |
| R7 | `cryptography` pip install fails on lab network | Low | Medium | Download wheel files at home; use `pip install --find-links ./deps/` | Bundle wheels in `deps/` folder |
| R8 | HLPSL syntax errors prevent AVISPA run | Medium | Medium | Start AVISPA early (Day 6); use AVISPA examples as templates | Show manual attack trace diagram; cite tool |

---

## PART 8 — TIMELINE (10 Days, 4 Members)

| Day | Goal | Lead/Integrator | Crypto Engineer | Auth+Tools | Verification+Docs |
|---|---|---|---|---|---|
| 1 | Phase 0 done ✅. Git setup. Manual GUI test. | Merge tag; set up branches | Verify headless tests on second machine | Check Tkinter on demo PC | Read original `report/` |
| 2 | Phase 1 ✅ argparse, banner, stdin thread | Review + merge | Implement `run.py`/`mitm.py` changes | Write `tests/test_args.py` | README first draft |
| 3 | Phase 2: AES-GCM, HKDF, RFC 3526 | Review, merge | Rewrite `crypto_protocol.py`, `diffie_hellman.py` | Write `tests/test_crypto_v2.py` | Diagram: normal DH |
| 4 | Phase 3: auth_dh.py, signatures | Review, merge | Implement `auth_dh.py`, `secure_handshake_*` | Write `tests/test_auth_dh.py` | Diagram: signed DH |
| 5 | Phase 4: MITM forgery + all 8 tests | Review, merge | Patch `mitm.py` secure handshake | Write `tests/test_secure_vs_mitm.py` | Diagram: MITM attack |
| 6 | Phase 5: AVISPA HLPSL models | — | — | — | Write HLPSL; run on web tool; screenshot |
| 7 | Phase 6: MFA inside channel | Review, merge | — | `mfa.py`, `enroll.py`, `tests/test_mfa.py` | AVISPA debug and re-run |
| 8 | Phase 7: Docs, README, DEMO.md | Merge all PRs; write README | Code review | — | DEMO.md; finalize diagrams |
| 9 | Full rehearsal × 3 | Run demo as MC | Fix bugs | Fix MFA timing | Finalize slides + AVISPA section |
| 10 | Buffer / submission | Submit repo, report, slides | — | — | Proofread report |

---

## PART 9 — TESTING STRATEGY

### Unit Tests

| Phase | File | Covers |
|---|---|---|
| 0 | `diffie_hellman.py --main` | DH shared secret matches |
| 0 | `crypto_protocol.py --main` | CBC round-trip |
| 1 | `tests/test_args.py` | argparse all combinations; banner text |
| 2 | `tests/test_crypto_v2.py` | GCM; tamper; nonce; RFC 3526 rejection |
| 3 | `tests/test_auth_dh.py` | Sign/verify; HandshakeError; domain labels; gen_keys no-overwrite |
| 4 | `tests/test_secure_vs_mitm.py` | All 8 scenarios; replayed sig; wrong key |
| 6 | `tests/test_mfa.py` | Enroll; login; lockout; timing-safe |

### Integration Tests

| Script | Proves |
|---|---|
| `headless_test.py` | Full DH + AES handshake + 3-message echo |
| `headless_mitm_test.py` | MITM parameter injection + plaintext relay |

### Manual Pre-Demo Checklist

- [ ] `python gen_keys.py` — 4 PEM files created; re-running refuses overwrite
- [ ] `python enroll.py alice` — `users.json` + `alice_mfa_qr.png` created
- [ ] QR scans in Google Authenticator
- [ ] Scenario 1: both GUI windows open; messages flow
- [ ] Scenario 2: Mallory's `[MITM][client] INTERCEPTED:` lines appear
- [ ] Scenario 3: both endpoints print `Signature verification FAILED`
- [ ] Scenario 4: correct OTP → OK; wrong OTP → rejected; 3rd → locked
- [ ] `python -m pytest tests/ -v` — all green
- [ ] `git log --all --full-history -- "*.pem"` — **no output** (no PEM in history)

### Pre-Demo Checklist (30 minutes before)

- [ ] Machine charged, display connected
- [ ] 4 terminal windows pre-positioned; venv activated in each
- [ ] Authenticator app open on phone
- [ ] Wireshark open; filter `tcp.port == 9000`
- [ ] Slides at title slide
- [ ] Backup video ready

---

## PART 10 — VIVA PREPARATION

**Q1. In `diffie_hellman.py`, what prime `p` did the original code use, and what do we use now?**
A: Original: `RSA.generate(2048).p` — a ~1024-bit prime factor of a 2048-bit RSA key. Ours: the
RFC 3526 2048-bit MODP group 14, a pre-defined safe prime `p` where `(p-1)/2` is also prime.

**Q2. Why is `g = randint(p//2, p-1)` insecure as a generator?**
A: A generator must be a primitive root of `Z_p*` to guarantee the full-order subgroup is used.
A random element may only generate a small subgroup, making discrete-log much easier.
RFC 3526 specifies `g = 2`, which generates a prime-order subgroup of size `(p-1)/2`.

**Q3. What is the "parameter injection" attack and where does it happen in `mitm.py`?**
A: Lines 58–74: Mallory creates her own `DiffieHellman` instances, computes her own B toward
Bob and her own A toward Alice, and sends those instead of the real values. Both sides
compute shared secrets with Mallory, not with each other.

**Q4. Why do we validate the received DH public value with `validate_public_value`?**
A: Values outside `(1, p-1)` can enable small-subgroup attacks where the attacker learns
the private exponent bit-by-bit. We reject any value ≤1 or ≥p-1.

**Q5. What does AES-GCM add over AES-CBC?**
A: GCM provides authenticated encryption: any tampering with the ciphertext causes
`decrypt()` to raise `InvalidTag`. CBC provides confidentiality only; an attacker can
flip bits in ciphertext to cause predictable plaintext changes (bit-flip attack).

**Q6. Why is the IV fixed in our Phase 0 code, and why is that bad?**
A: The IV is derived once from the shared secret and reused for every message. In CBC,
two messages with the same prefix produce the same ciphertext prefix, leaking that the
prefixes match. GCM (Phase 2) uses a fresh random 12-byte nonce per message.

**Q7. What does domain separation (`b"server-hello"` / `b"client-hello"`) prevent?**
A: Without labels, a valid server signature `sign(A)` could be replayed as if it were
a client signature. The label makes the signed data distinct per role, so a server's
signature is cryptographically incompatible with a client's expected signature format.

**Q8. Why does the client's signature cover `B + A`, not just `B`?**
A: It binds Bob's reply to this specific session's A value. If Mallory records a valid
`(B, sig_B)` from a past session and replays it in a new session (with different A),
the signature will not verify because A changed.

**Q9. Why does `verify()` raise `HandshakeError` instead of returning `False`?**
A: Library code should not make control-flow decisions for the caller. Raising an
exception ensures the caller (run.py) cannot accidentally ignore the failure by
forgetting to check the return value. The caller catches it, prints the abort message,
and closes the socket — no `sys.exit()` inside library code.

**Q10. Why does MFA run inside the AES-GCM channel (Phase 6), not before it?**
A: If MFA credentials were sent before the session key is established, they would
travel in plaintext or under at best a weak transport. The DH handshake first
establishes the authenticated session key; the TOTP code then travels encrypted
inside that channel, invisible to an eavesdropper.

**Q11. What does `hmac.compare_digest` protect against in `mfa.py`?**
A: Timing attacks. A standard `==` short-circuits on the first mismatched byte, leaking
information about how many bytes matched. `hmac.compare_digest` always compares all
bytes in constant time, preventing byte-by-byte enumeration of the stored hash.

**Q12. What does AVISPA's Dolev-Yao model assume?**
A: The intruder has full control of the network: can intercept, replay, delay, modify,
and compose any message. A SAFE result under Dolev-Yao means no attack exists given
those capabilities.

**Q13. What does a SAFE AVISPA result NOT guarantee?**
A: It does not cover implementation bugs (e.g., wrong domain label in actual code),
side-channel attacks, compromised private keys, or threats outside the formal model.

**Q14. What would be needed to achieve forward secrecy?**
A: Use ephemeral DH keys: generate a fresh RSA (or better, ECDH) signing key for each
session, prove identity only through the long-term key signing the ephemeral key. If
the long-term key is later compromised, past sessions remain safe because the ephemeral
private keys are gone. This is how TLS 1.3 with ECDHE achieves forward secrecy.

**Q15. Can Mallory succeed by relaying messages unchanged in `--secure` mode?**
A: No. If she relays Bob's real A unmodified, she cannot compute the shared secret
(she doesn't know Bob's private exponent). She would be a transparent proxy, unable
to decrypt anything. To intercept, she must substitute her own DH value — and that
substitution is exactly what the signature check catches.

---

## PART 11 — SYLLABUS MAPPING

| Component | File(s) | IS Unit | Topic |
|---|---|---|---|
| Diffie-Hellman key exchange (demo) | `diffie_hellman.py`, `run.py` | Unit III | Diffie-Hellman key exchange |
| AES-128-CBC (baseline, Phase 0) | `crypto_protocol.py` | Unit II, III | Block ciphers, AES |
| AES-256-GCM (Phase 2+) | `crypto_protocol.py` | Unit III | AES; authenticated encryption |
| MITM attack demo | `mitm.py`, `headless_mitm_test.py` | Unit I | Man-in-the-middle attack |
| RSA-PSS/SHA-512 signatures | `auth_dh.py` | Units III, IV | RSA; digital signatures |
| SHA-512 in signatures | `auth_dh.py` | Unit IV | SHA-512, secure hash functions |
| HKDF key derivation | `crypto_protocol.py` | Unit IV | Key management |
| RFC 3526 MODP group | `diffie_hellman.py` | Unit III | DH parameter standards |
| TOTP-based MFA | `mfa.py`, `enroll.py` | Unit IV (self-learning) | Multi-factor authentication |
| PBKDF2-SHA512 password hashing | `mfa.py` | Unit IV | Cryptography for authentication |
| AVISPA formal verification | `avispa/dh_*.hlpsl` | Unit IV (case study) | MITM in public-key exchange, AVISPA |
| Public key distribution discussion | `gen_keys.py`, viva Q14 | Unit IV | Key management |
| Security policy / threat model | This plan, Part 6 | Unit I | Threats, NIST CSF |

---

## PART 12 — DEFINITION OF DONE

### Code
- [ ] `python -m pytest tests/ -v` — all green on clean `pip install -r requirements.txt`
- [ ] `python headless_test.py` — `[PASS]`
- [ ] `python headless_mitm_test.py` — `[PASS] MITM attack succeeded`
- [ ] `--secure` chat works (no MITM): both sides send/receive messages
- [ ] `--secure` with MITM: both endpoints print `Signature verification FAILED`
- [ ] `--mfa --secure`: correct OTP → chat; wrong OTP → rejected; 3 failures → locked

### Security hygiene
- [ ] `git log --all --full-history -- "*.pem"` — **no output** (no PEM files ever committed)
- [ ] `cat .gitignore | findstr pem` — `*.pem` present
- [ ] `requirements.txt` works on a clean venv on a second machine

### Documentation
- [ ] `README.md`: install, all modes, original author credit, MIT license notice
- [ ] `DEMO.md`: exact port numbers, process start order, expected outputs
- [ ] Three Mermaid diagrams committed to `docs/`
- [ ] AVISPA screenshots in `docs/` — **from actual AVISPA runs only**

### Demo readiness
- [ ] Full demo rehearsed × 3
- [ ] Pre-recorded backup video in `docs/`
- [ ] Every member can explain DH math and MITM without notes
- [ ] Every member reviewed all 15 viva questions

### Report
- [ ] Original authors credited (Jay Bosamiya & Rakholiya Jenish, MIT, 2015)
- [ ] All scenarios described with screenshots
- [ ] Security analysis: what works and what doesn't (Part 6 above)
- [ ] Syllabus mapping table included

---

## APPENDIX — PHASE COMPLETION AUDIT TRAIL

| Phase | Status | Date | Tester | Commit / Evidence |
|---|---|---|---|---|
| Phase 0: Python 3 port | ✅ DONE | 2026-09-30 | AI agent | tag `phase-0`, commit `63b402d`; headless tests PASS |
| Phase 0: GUI check | ⚠️ MANUAL | — | Team | Run Scenarios 1 & 2 in terminals; tick when done |
| Phase 1: `--secure`/`--no-gui` | ✅ DONE | 2026-09-30 | AI agent | tag `phase-1`; `test_args.py` all pass |
| Phase 2: AES-GCM + RFC 3526 | 🔲 TODO | — | — | — |
| Phase 3: Signatures | 🔲 TODO | — | — | — |
| Phase 4: Attack fails | 🔲 TODO | — | — | — |
| Phase 5: AVISPA | 🔲 TODO | — | — | — |
| Phase 6: MFA | 🔲 TODO | — | — | — |
| Phase 7: Docs | 🔲 TODO | — | — | — |
| Final rehearsal × 3 | 🔲 TODO | — | — | — |
| Clean-env test (second machine) | 🔲 TODO | — | — | — |
| Report submitted | 🔲 TODO | — | — | — |

> **Fill in Date, Tester, and Commit SHA after each phase is merged to `main`.**
