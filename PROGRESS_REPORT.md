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
| 1.5 | Transport Hygiene, .gitignore, Exact Pins | ✅ **DONE** (partial) | — | `df3f628` |
| 2 | AES-256-GCM + HKDF + RFC 3526 MODP Group | ✅ **DONE** | `phase-2` | `5f083d7` |
| 2 fixes | Subgroup check (F02), exponent [2,q-1] (F23), drop pycryptodome | ✅ **DONE** | — | `df3f628` |
| 3 | RSA-PSS/SHA-512 Signed DH (`dhc1_core.py`, `auth_dh.py`) | ✅ **DONE** | — | `df3f628` |
| 4 | MITM Attack Modes (substitute/splice/relay) | ✅ **DONE** | — | `df3f628` |
| 5 | AVISPA Formal Verification | 🔲 HLPSL written (UNRUN) | — | — |
| 6 | TOTP MFA Inside AES-GCM Channel | 🔲 TODO | — | — |
| 7 | Docs, README, Mermaid Diagrams, Final Polish | 🔲 TODO | — | — |
| 8 | Report, Slides, Rehearsal | 🔲 TODO | — | — |

**6 of 8 phases done (core protocol complete). 2 remaining (MFA + docs).**

---

## What Is Done

### Phases 0–1 (previous sessions — unchanged)

See prior progress report entries.

---

### Phase 2 Fixes (commit: `df3f628`)

| Finding | Fix |
|---|---|
| F02: Range check `1<v<p-1` insufficient — non-residue `11` passes but leaks exponent bit | `validate_public_value` now also checks `pow(v,q,p)==1` |
| F23: Exponent was in `[2,p-2]` not `[2,q-1]` | Fixed to `secrets.randbelow(RFC3526_Q-2)+2` |
| F23: `assert` in group sanity → bypassed by `-O` | Replaced with explicit `raise RuntimeError` |
| F11: `from Crypto.PublicKey import RSA` at module top | Removed; pycryptodome fully dropped |
| requirements.txt: `>=` pins | Exact pins (`cryptography==46.0.3`) |

---

### Phase 1.5 — Hygiene (commit: `df3f628`)

| Item | Done |
|---|---|
| `.gitignore`: `*.pem`, `keys/**/*.pem`, `users.json`, `*_mfa_qr.png`, `venv*/`, `.pytest_cache/`, `deps/`, `*.mp4` | ✅ |
| `requirements.txt`: exact pin, pycryptodome removed, pyotp/qrcode/Pillow added for Phase 6 | ✅ |
| `requirements-dev.txt`: pinned `pytest==8.3.5` | ✅ |
| Transport API (send_line/recv_line with timeouts) | 🔲 Still using network.py baseline |
| CI `.github/workflows/ci.yml` | 🔲 TODO |
| `tests/helpers.py`: free_port, start, kill_all | 🔲 TODO |

---

### Phase 3 — RSA-PSS/SHA-512 Signed DH (commit: `df3f628`)

**Goal:** When `--secure` is passed, the DH handshake is authenticated via the DHC1 3-message protocol. Neither side accepts an unverified public value.

**New files:**

| File | Purpose |
|---|---|
| `dhc1_core.py` | Pure-function DHC1 protocol core: `Server`/`Client` state machines, `Record` (AES-256-GCM directional), `derive_keys` (HKDF + transcript hash), `enc`/`dec` (fixed-width), `sign`/`verify`/`fingerprint`, transcript constructors |
| `auth_dh.py` | PEM key management (O_EXCL creation, 0600 perms), `secure_handshake_server/client` (transport wrappers with socket timeouts), `fingerprint_hex` |
| `gen_keys.py` | CLI: `python gen_keys.py [alice bob mallory]`. Creates `keys/<name>/` with priv+pub PEM. Refuses to overwrite. Prints SHA-256 fingerprints. |

**Modified files:**

| File | What changed |
|---|---|
| `crypto_protocol.py` | Completely rewritten on `dhc1_core.Record`; two directional AES-256-GCM keys + counter nonces + direction AAD (F04 fix); `is_server` flag required |
| `run.py` | `--secure` now calls `secure_handshake_server/client`; `--key-dir`, `--peer-pub` flags; `HandshakeError` caught with abort banner; legacy path unchanged |
| `headless_test.py`, `headless_mitm_test.py` | Updated for `is_server` flag |

**Protocol (DHC1 — Part 3.2):**
```
M1  S -> C : {t:"hello", v:1, gs, sig_S}     sig_S = Sign_S("DHC1|server-hello|modp2048|" || Gs)
M2  C -> S : {t:"auth",  gc, sig_C}           sig_C = Sign_C("DHC1|client-auth|" || FPs || FPc || Gs || Gc)
M3  S -> C : {t:"confirm", sig_S2}            sig_S2 = Sign_S("DHC1|server-auth|" || FPs || FPc || Gs || Gc)
```

**Test results:**
```
tests/test_dhc1_core.py   16 tests  ✅ all passed
tests/test_auth_dh.py     12 tests  ✅ all passed
```

---

### Phase 4 — MITM Attack Modes (commit: `df3f628`)

**Goal:** `mitm.py --secure` speaks the full signed wire format and demonstrates three attack outcomes.

**Attack modes (--attack):**

| Mode | What Mallory does | Result |
|---|---|---|
| `substitute` (default) | Signs her own `Gs` with her own RSA key | Client: `Signature verification FAILED`. Server aborts. |
| `splice` | Keeps real sig, swaps in Mallory's `Gs` | Client: `Signature verification FAILED` (sig covers wrong value) |
| `relay` | Forwards all handshake messages unchanged | Chat works; Mallory sees only GCM ciphertext |

**Two independent DH exchanges** (F09 fix): `mitm.py` now holds separate `dh_server` and `dh_client` objects.

**Readiness signal:** `[*] listening` printed before blocking on `accept()` — test harness can sync on this.

---

## Test Inventory (current)

```
tests/
├── conftest.py            --run-slow gate
├── test_args.py           23 tests  (Phase 1)
├── test_crypto_v2.py      34 tests  (Phase 2/3: AES-GCM directional, RFC 3526, subgroup)
├── test_dhc1_core.py      16 tests  (Phase 3: protocol core, all attack scenarios)
└── test_auth_dh.py        12 tests  (Phase 3: key I/O, handshake, wrong-key abort)

Total: 85 tests (84 pass, 1 skipped slow subprocess test)
```

**Run:**
```bash
python -m pytest tests/ -v                      # 84 passed, 1 skipped in ~10s
python headless_test.py                         # [PASS] All messages round-tripped correctly.
python headless_mitm_test.py                    # [PASS] MITM attack succeeded — unauthenticated DH is broken.
```

---

## What Is Remaining

### Phase 5 — AVISPA Formal Verification 🔲

**HLPSL models are written (UNRUN):**

| File | Expected result |
|---|---|
| `avispa/dh_unauth.hlpsl` | UNSAFE — intruder learns session payload |
| `avispa/dh_auth.hlpsl` | SAFE — both directions authenticated |

**Action needed (Day 1 spike, 3 hours):**
```bash
# Option A: SPAN Linux binary in WSL
./span/bin/avispa avispa/dh_unauth.hlpsl --ofmc
./span/bin/avispa avispa/dh_auth.hlpsl   --ofmc
# Option B: OFMC from source
git clone https://github.com/ofmc/ofmc.git && cd ofmc && stack build
# Option C: Ask faculty for lab access
```

See `avispa/README_avispa.md` for full instructions.

> ⚠️ Do not include UNSAFE/SAFE screenshots in the report unless your own run produced them.

---

### Phase 6 — TOTP MFA Inside AES-GCM Channel 🔲

**Goal:** After the DH handshake, run TOTP + password login inside the encrypted channel.

**Files to create:**
- `mfa.py` — `enroll_user()`, `verify_login()`, `mfa_server_side()`, `mfa_client_side()`; PBKDF2-SHA-512 (210,000 iterations); 3-attempt lockout (persisted in `users.json`); TOTP replay protection (last accepted time-step stored); constant-time compare
- `enroll.py` — enrollment CLI; saves QR PNG (git-ignored); `--show-code` fallback

**Files to modify:**
- `run.py` — `--mfa` flag requires `--secure` (or `--allow-insecure-mfa` for the leak demo); calls `mfa_server_side`/`mfa_client_side` after handshake

**Wire protocol (inside AES-GCM channel, JSON objects):**
```
C -> S : Enc({"t":"mfa", "user":u, "pw":p, "otp":"123456"})
S -> C : Enc({"t":"mfa_ok"})  or  Enc({"t":"mfa_fail"})   [no reason to client]
```

**Tests to write:** `tests/test_mfa.py` (13 tests per plan v2 Part 6.3)

---

### Phase 7 — Docs, Diagrams, Final Polish 🔲

**Files to create/modify:**
- `README.md` — complete rewrite: install, all modes, upstream credit, MIT notice
- `DEMO.md` — 10-minute runbook with exact ports, process order, expected output
- `docs/diagram_normal_dh.md` — Mermaid: normal DH chat
- `docs/diagram_mitm_attack.md` — Mermaid: substitution attack
- `docs/diagram_signed_dh.md` — Mermaid: DHC1, MITM fails
- `--trace` flag in `run.py`/`mitm.py` — prints wire lines for demo without Wireshark
- `LICENSE`, `UPSTREAM.md` — upstream MIT text, upstream commit SHA and author names (verify from upstream)

### Phase 8 — Report, Slides, Rehearsal 🔲

See `IMPLEMENTATION_PLAN_v2.md` Part 8 for deliverables and Phase 12 for the 20 viva questions.

---

## Files in the Repo (current state)

```
DiffieHellman_V2/
├── run.py                  Server/client; --secure (DHC1); --key-dir, --peer-pub; --no-gui
├── mitm.py                 MITM proxy; --secure (substitute/splice/relay); --no-gui
├── network.py              stdlib TCP; base64-framed newline-delimited messages
├── diffie_hellman.py       RFC 3526 2048-bit MODP; subgroup check pow(v,q,p)==1; secrets.randbelow [2,q-1]
├── crypto_protocol.py      dhc1_core.Record wrapper; directional AES-256-GCM; counter nonces
├── dhc1_core.py            ★ NEW: pure DHC1 protocol core (Server, Client, Record, derive_keys)
├── auth_dh.py              ★ NEW: PEM key I/O, secure_handshake_server/client, fingerprint_hex
├── gen_keys.py             ★ NEW: key generation CLI (alice/bob/mallory)
├── gui.py                  Tkinter chat GUI (skipped with --no-gui)
├── headless_test.py        Integration: DH + AES round-trip (updated for is_server)
├── headless_mitm_test.py   Integration: MITM parameter injection (updated for is_server)
│
├── avispa/
│   ├── dh_unauth.hlpsl     ★ NEW: HLPSL model, expected UNSAFE (UNRUN)
│   ├── dh_auth.hlpsl       ★ NEW: HLPSL model, expected SAFE (UNRUN)
│   └── README_avispa.md    ★ NEW: install spike guide
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_args.py        Phase 1 tests (23)
│   ├── test_crypto_v2.py   Phase 2/3 tests (34)
│   ├── test_dhc1_core.py   ★ NEW: Phase 3 protocol tests (16)
│   └── test_auth_dh.py     ★ NEW: Phase 3 transport tests (12)
│
├── requirements.txt        cryptography==46.0.3, pyotp, qrcode, Pillow (exact pins)
├── requirements-dev.txt    ★ NEW: pytest==8.3.5
├── IMPLEMENTATION_PLAN_v2.md
├── PROGRESS_REPORT.md      This file
└── report/                 Original authors' report (unchanged)
```

---

## Quick Commands

```bash
# Run all tests
python -m pytest tests/ -v

# Run individual test files
python -m pytest tests/test_dhc1_core.py -v      # protocol tests
python -m pytest tests/test_auth_dh.py -v         # key and handshake tests

# Generate keys (prerequisite for --secure demo)
python gen_keys.py                                  # creates keys/alice/, keys/bob/, keys/mallory/

# Headless integration tests
python headless_test.py
python headless_mitm_test.py

# Demo: vulnerable MITM (3 terminals)
python run.py 9000 --no-gui
python mitm.py 127.0.0.1 9000 9001 --no-gui
python run.py 127.0.0.1 9001 --no-gui

# Demo: secure mode (MITM fails)
python run.py 9000 --secure --no-gui
python mitm.py 127.0.0.1 9000 9001 --secure --no-gui
python run.py 127.0.0.1 9001 --secure --no-gui

# Demo: relay mode (MITM sees only ciphertext)
python mitm.py 127.0.0.1 9000 9001 --secure --attack relay --no-gui

# See all git tags and commits
git tag -l && git log --oneline
```

---

## Appendix B: Phase Completion Audit Trail (updated)

| Phase | Status | Date | Tester | Commit or evidence |
|---|---|---|---|---|
| 0 Python 3 port | ✅ | 2026-09-30 | AI agent | tag `phase-0`, `63b402d` |
| G0 GUI check | 🔲 | | Team | Run on demo PC before submission |
| 1 `--secure`, `--no-gui` | ✅ | 2026-09-30 | AI agent | tag `phase-1`, `c901a1b` |
| 1.5 Transport and hygiene (partial) | ✅ | 2026-10-01 | AI agent | `df3f628` |
| 2 Crypto modernization | ✅ | 2026-09-30 | AI agent | tag `phase-2`, `5f083d7` |
| 2 fixes (F02, F23) | ✅ | 2026-10-01 | AI agent | `df3f628` |
| 3 Signed handshake (DHC1) | ✅ | 2026-10-01 | AI agent | `df3f628` — 84 tests pass |
| 4 Attack modes | ✅ | 2026-10-01 | AI agent | `df3f628` |
| 5 AVISPA (install spike) | 🔲 | | Team | HLPSL written; run on lab machine |
| 6 MFA | 🔲 | | | |
| 7 Docs | 🔲 | | | |
| 8 Report, slides, rehearsal | 🔲 | | | |
| Clean-env test, second machine | 🔲 | | | |
| Submission | 🔲 | | | |

---

*Report updated automatically by the AI agent. Update after each phase merge.*
