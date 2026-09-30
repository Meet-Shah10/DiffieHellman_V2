# IS FA2 — Project Progress Report

> **Project:** Diffie-Hellman Secure Chat — Break It, Then Fix It
> **Team:** T.Y. CSE AI&ML
> **Fork of:** `jaybosamiya/DiffieHellman-ManInTheMiddle` (MIT, archived 2018)
> **Last updated:** 2026-10-01

---

## Quick Status

| Phase | Name | Status | Git Tag | Commit |
|---|---|---|---|---|
| 0 | Python 3 Port + Baseline | ✅ **DONE** | `phase-0` | `63b402d` |
| 1 | `--secure`/`--no-gui` Argparse + Banner + Stdin Thread | ✅ **DONE** | `phase-1` | `c901a1b` |
| 2 | AES-256-GCM + HKDF + RFC 3526 MODP Group | ✅ **DONE** | `phase-2` | `5f083d7` |
| 3 | RSA-PSS/SHA-512 Signed DH (`auth_dh.py`) | 🔲 TODO | — | — |
| 4 | MITM Forgery Fails in `--secure` Mode | 🔲 TODO | — | — |
| 5 | AVISPA Formal Verification | 🔲 TODO | — | — |
| 6 | TOTP MFA Inside AES-GCM Channel | 🔲 TODO | — | — |
| 7 | Docs, README, Mermaid Diagrams, Final Polish | 🔲 TODO | — | — |

**3 of 8 phases done. 5 remaining.**

---

## What Is Done

### Phase 0 — Python 3 Port (tag: `phase-0`)

**Goal:** Make the 2015 Python 2 codebase run under Python 3.13 with minimal changes.

**Changes made:**

| File | What changed |
|---|---|
| `network.py` | Removed `pwntools`; replaced with stdlib `socket` + `base64` (Windows compatible) |
| `diffie_hellman.py` | `print()`, `//` integer division, `RSAKey.p` → `RSAKey.key.p` |
| `crypto_protocol.py` | Full bytes/str fix; `//`; `bytes.fromhex`; encrypt returns hex string |
| `gui.py` | `Tkinter` → `tkinter`; `print()` |
| `run.py` | `print()` syntax only |
| `mitm.py` | `print()` syntax only |

**New files added:**

| File | Purpose |
|---|---|
| `requirements.txt` | `pycryptodome==3.23.0` |
| `headless_test.py` | Integration test: DH + AES round-trip without GUI |
| `headless_mitm_test.py` | Integration test: MITM parameter injection without GUI |

**Verified output:**
```
$ python diffie_hellman.py        → [+] DH self-test passed
$ python crypto_protocol.py       → [+] CBC decrypt(encrypt(text))==text test passed
$ python headless_test.py         → [PASS] All messages round-tripped correctly.
$ python headless_mitm_test.py    → [PASS] MITM attack succeeded — unauthenticated DH is broken.
```

---

### Phase 1 — Argparse + Mode Banner + Stdin Thread (tag: `phase-1`)

**Goal:** Add `--secure` and `--no-gui` flags so automated tests can drive the chat processes via stdin/stdout pipes (no Tkinter needed).

**Changes made:**

| File | What changed |
|---|---|
| `run.py` | `argparse` parser; `parse_args()`; `print_banner(role, secure)`; `StdinReaderThread` (reads stdin, sends encrypted messages); `--no-gui` guards on GUI; `[Other] plaintext` printed to stdout |
| `mitm.py` | `argparse` parser; `parse_args()`; `print_banner(secure)`; `log_intercept(name, text)` helper; `--no-gui` guard on GUI thread |

**New files added:**

| File | Purpose |
|---|---|
| `tests/__init__.py` | Makes `tests/` a Python package |
| `tests/conftest.py` | `--run-slow` pytest flag for gating subprocess integration tests |
| `tests/test_args.py` | 23 unit tests: argparse correctness, banner text, stdin integration |

**Test results:**
```
pytest tests/test_args.py -v
22 passed, 1 skipped (slow subprocess test)   in 0.04s
```

**What `--secure` does in Phase 1:** Banner only — prints `SECURE (signed DH — Phase 3 not yet active)`. Crypto is unchanged. Flag is wired for Phase 3.

**What `--no-gui` does:** Replaces Tkinter GUI thread with a `StdinReaderThread`. Subprocess tests pipe lines to stdin; received messages print to stdout. Enables headless automated testing.

---

### Phase 2 — AES-256-GCM + HKDF + RFC 3526 (tag: `phase-2`)

**Goal:** Replace the broken/weak Phase 0 crypto with cryptographically sound primitives. Protocol remains MITM-vulnerable (no signatures yet) — this is intentional for the demo.

**Changes made:**

| File | What changed |
|---|---|
| `diffie_hellman.py` | RFC 3526 Group 14 (2048-bit safe prime, `g=2`) replaces `RSA.generate(2048).p`; `secrets.randbelow` replaces `random.randint`; rejects non-RFC-3526 `p`/`g`; `validate_public_value()` rejects values outside `(1, p-1)` |
| `crypto_protocol.py` | **AES-256-GCM** replaces hand-rolled AES-128-CBC; **HKDF-SHA-256** replaces `SHA256(str(secret))`; fresh 12-byte random nonce per message; `InvalidTag` on tamper |
| `run.py` | Client path catches `ValueError` from `DiffieHellman(p,g)` and `get_shared_secret()` → clean abort instead of crash |
| `requirements.txt` | Added `cryptography>=42.0.0` |

**New files added:**

| File | Purpose |
|---|---|
| `tests/test_crypto_v2.py` | 34 tests: AES-GCM round-trip, tamper detection, nonce uniqueness, key properties, RFC 3526 group, range validation, DH correctness, inline chat+MITM regression |

**Test results:**
```
pytest tests/test_crypto_v2.py tests/test_args.py -v
56 passed, 1 skipped   in 1.49s   ← was 40+s before (RFC 3526 = no key gen at startup)
```

**Go/No-Go confirmed:**
```
TestHeadlessRegression::test_mitm_still_works_vulnerable_mode   PASSED
```
MITM still intercepts plaintext → Phase 3 can proceed safely.

**Security improvements over Phase 0:**

| Attack vector | Phase 0 | Phase 2 |
|---|---|---|
| Ciphertext bit-flip | Undetected (CBC, no MAC) | `InvalidTag` raised (GCM) |
| Fixed IV per session | Leaks repeated-prefix patterns | Fresh 12-byte nonce per message |
| Weak DH group | Random ~1024-bit prime, random `g` (not primitive root) | RFC 3526 safe prime, `g=2` |
| Parameter injection (bad p/g) | Any values accepted | `ValueError` if `p≠RFC3526_P` or `g≠2` |
| Small-subgroup attack | No range check on received values | `validate_public_value()` enforced |

---

## What Is Remaining

### Phase 3 — RSA-PSS/SHA-512 Signed DH 🔲

**Goal:** When `--secure` is passed, the DH handshake is authenticated. Neither side accepts an unverified public value.

**Files to create:**
- `auth_dh.py` — `generate_keypair()`, `sign()`, `verify()`, `HandshakeError`, load/save PEM
- `gen_keys.py` — one-shot CLI to create `alice_priv.pem`, `bob_priv.pem`; refuses overwrite

**Files to modify:**
- `crypto_protocol.py` — add `secure_handshake_server()` / `secure_handshake_client()`
- `run.py` — call secure handshake when `--secure`; catch `HandshakeError`
- `.gitignore` — add `*.pem`, `users.json`

**Key design decisions:**
- Scheme: **RSA-PSS / SHA-512** (maps to IS Unit III+IV)
- Domain labels: server signs `b"server-hello" + A_bytes`; client signs `b"client-hello" + B_bytes + A_bytes`
- `verify()` raises `HandshakeError`, never returns bool; `run.py` catches it and closes socket
- No `sys.exit()` inside library code (`auth_dh.py`, `crypto_protocol.py`)
- All PEM files in `.gitignore` — never committed, even public keys

**Tests to write:** `tests/test_auth_dh.py` (8 tests: sign/verify, tamper, domain labels, session binding, no-overwrite)

---

### Phase 4 — MITM Forgery Fails in `--secure` Mode 🔲

**Goal:** `mitm.py --secure` speaks the full signed wire format, attempts forgery (garbage signature), and both endpoints abort with `HandshakeError`.

**Files to modify:**
- `mitm.py` — add `--secure` branch in the handshake that reads signed wire format, substitutes its own DH value with a garbage/forged signature, logs the forgery attempt

**Expected output when MITM attempts forgery:**
```
[Server] [SECURE] Signature verification FAILED: ...
[Server] [SECURE] Possible man-in-the-middle attack. Aborting.
[Client] [SECURE] Signature verification FAILED: ...
[MITM]   Sent forged A + garbage signature to client.
[MITM]   Endpoints should now abort with HandshakeError.
```

**Tests to write:** `tests/test_secure_vs_mitm.py` (8 scenarios: normal chat, MITM breaks vulnerable, secure chat works, MITM fails secure, tampered sig, replayed sig, wrong key, wrong domain label)

---

### Phase 5 — AVISPA Formal Verification 🔲

**Goal:** Model both protocol variants in HLPSL, run OFMC, screenshot UNSAFE (unauthenticated) and SAFE (signed) results for the report and slides.

**Files to create:**
- `avispa/dh_unauth.hlpsl` — unauthenticated DH; expected UNSAFE
- `avispa/dh_auth.hlpsl` — signed DH (Phase 3 design); expected SAFE
- `avispa/README_avispa.md` — how to install and run AVISPA
- `docs/avispa_unsafe.png` — screenshot from actual run (not placeholder)
- `docs/avispa_safe.png` — screenshot from actual run

**⚠️ Action needed:** HLPSL skeleton is written in `IMPLEMENTATION_PLAN.md` (Part 3, Phase 5). Must be tested against a real AVISPA binary or web interface before submission. Do not include unrun results in the report.

**How to run:**
```bash
# Local (Linux/WSL): ./avispa --ofmc avispa/dh_unauth.hlpsl
# Web: https://avispa-project.org/ → paste HLPSL → OFMC → Verify → screenshot
```

---

### Phase 6 — TOTP MFA Inside AES-GCM Channel 🔲

**Goal:** After the DH handshake establishes the session key, run TOTP + password login **inside the encrypted channel** (credentials never travel in plaintext).

**Files to create:**
- `mfa.py` — `enroll_user()`, `verify_login()`, `mfa_server_side()`, `mfa_client_side()`, PBKDF2-SHA512 password hashing, 3-attempt lockout
- `enroll.py` — one-shot enrollment CLI; saves QR PNG

**Files to modify:**
- `run.py` — if `--mfa`, call `mfa_server_side` / `mfa_client_side` after `CryptoProtocol` is ready
- `requirements.txt` — add `pyotp>=2.9.0`, `qrcode>=7.4`, `Pillow>=10.0`

**MFA wire protocol (inside AES-GCM channel):**
```
Client → Server:  Enc_K("MFA_USERNAME:" + username)
Server → Client:  Enc_K("MFA_CHALLENGE")
Client → Server:  Enc_K("MFA_CREDS:" + password + ":" + totp_code)
Server → Client:  Enc_K("MFA_OK") or Enc_K("MFA_FAIL:" + reason)
```

**Tests to write:** `tests/test_mfa.py` (9 tests: enroll, correct login, wrong password, wrong OTP, lockout, lockout expiry, hash determinism, timing-safe compare, MFA over channel e2e)

---

### Phase 7 — Docs, Diagrams, Final Polish 🔲

**Goal:** Professional README, DEMO.md runbook, Mermaid sequence diagrams, and verified clean-env test.

**Files to create/modify:**
- `README.md` — complete rewrite with install, all modes, original author credit, MIT license
- `DEMO.md` — 10-minute demo runbook with exact port numbers, process order, expected output
- `docs/diagram_normal_dh.md` — Mermaid: normal DH chat
- `docs/diagram_mitm_attack.md` — Mermaid: parameter injection attack
- `docs/diagram_signed_dh.md` — Mermaid: signed DH, MITM fails

**Clean-env test (must pass before submission):**
```powershell
python -m venv venv_test
venv_test\Scripts\pip install -r requirements.txt
venv_test\Scripts\python -m pytest tests/ -v
# All green → remove venv_test/
```

---

## Current Test Inventory

```
tests/
├── conftest.py            --run-slow gate for subprocess tests
├── test_args.py           23 tests  (Phase 1: argparse, banner, stdin integration)
└── test_crypto_v2.py      34 tests  (Phase 2: AES-GCM, RFC 3526, DH, regression)

Planned:
├── test_auth_dh.py        ~8 tests  (Phase 3)
├── test_secure_vs_mitm.py ~8 tests  (Phase 4)
└── test_mfa.py            ~9 tests  (Phase 6)
```

**Current run:** `56 passed, 1 skipped` in 1.5 s

---

## Manual Checks Still Needed

Before ticking Phase 0 complete in the audit table, run this manually:

```powershell
# Terminal 1 — vulnerable server:
venv\Scripts\activate && python run.py 9000

# Terminal 2 — vulnerable client:
venv\Scripts\activate && python run.py 127.0.0.1 9000
```

Expected: two Tkinter windows open; mode banner shows `VULNERABLE`; messages appear in both windows.

---

## Files in the Repo (current state)

```
DiffieHellman_V2/
├── run.py                  Server/client; --secure (banner); --no-gui (stdin thread)
├── mitm.py                 MITM proxy; --secure (banner); --no-gui
├── network.py              stdlib TCP; base64-framed newline-delimited messages
├── diffie_hellman.py       RFC 3526 2048-bit MODP; validate_public_value; secrets.randbelow
├── crypto_protocol.py      AES-256-GCM + HKDF-SHA-256
├── gui.py                  Tkinter chat GUI (skipped with --no-gui)
├── headless_test.py        Integration: DH + AES round-trip
├── headless_mitm_test.py   Integration: MITM parameter injection
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_args.py        Phase 1 tests (23)
│   └── test_crypto_v2.py   Phase 2 tests (34)
│
├── requirements.txt        pycryptodome, cryptography, pytest
├── IMPLEMENTATION_PLAN.md  Full design spec with all phases
├── PROGRESS_REPORT.md      This file
├── IS_FA2_Project_Context.md
├── README.md
└── report/                 Original authors' report (unchanged)
```

---

## Quick Commands

```powershell
# Activate venv
venv\Scripts\activate

# Run all tests (fast — skips slow subprocess test)
python -m pytest tests/ -v

# Run slow subprocess integration test (needs ~90s)
python -m pytest tests/ -v --run-slow

# Self-test individual modules
python diffie_hellman.py
python crypto_protocol.py

# See all git tags
git tag -l

# See phase commit history
git log --oneline
```

---

*Report generated automatically by the AI agent. Update after each phase merge.*
