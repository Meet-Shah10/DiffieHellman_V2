# IMPLEMENTATION PLAN v2: IS FA2 "Secure Chat: Break It, Then Fix It"

> **Supersedes** `IMPLEMENTATION_PLAN.md` (v1) and overrides Sections 4.2, 9.1 and 9.6 of `IS_FA2_Project_Context.md` wherever they disagree. Update or annotate the context file so the two documents stop contradicting each other (finding F30).
>
> **Evidence tags used in this file**
> - `REPO` = read directly from the repo source (carried over from v1, not re-checked here).
> - `TESTED` = executed in a sandbox during this review (Python 3.12, `cryptography`, `pytest`). Re-run on your Python 3.13 venv before relying on it.
> - `ASSUMED` = inference that the team must confirm.
> - `UNRUN` = written but never executed (all formal-verification models are in this class).
> - Status markers: ✅ done, 🔲 todo, 🚦 gate (must pass before the next phase starts).

---

## PART 0: VERDICT AND WHAT CHANGED

v1 is a solid skeleton: the Python 3 port, the `--secure` plumbing, the PEM policy, the `HandshakeError` design and the domain-separation idea are all correct and stay. It is not yet airtight. It contains **13 critical and 17 lower-severity defects** (Part 1). Four of them would have produced a wrong or embarrassing result in front of the examiner:

1. The AVISPA models could never return SAFE for the signed protocol, because the secrecy goal targets public DH values the intruder sees by design. The "UNSAFE vs SAFE" slide would have been fake or unobtainable (F01).
2. The plan claims `1 < v < p-1` stops small-subgroup attacks. It does not. A non-residue such as `11` passes that check and fails the correct one, `v^q mod p == 1` (F02, `TESTED`).
3. The security analysis says the design has no forward secrecy. It does have it (ephemeral exponents, signed only by the long-term key). The viva answer Q14 in v1 would lose marks (F03).
4. The record layer uses one key for both directions and random nonces with no sequence numbers. In `--secure` mode Mallory can reflect, replay, reorder or drop ciphertexts undetected (F04, `TESTED`).

The fix set is folded into a single frozen protocol (Part 3), a tested reference core (Appendix A), corrected phases with hard gates (Part 4), and a corrected formal-verification plan (Part 5).

**Net scope change:** one extra handshake message, one extra phase (1.5, hygiene and transport), one new deliverables phase (8), and an AVISPA install spike on Day 1. No feature was added beyond what the context file already requires.

---

## PART 1: AUDIT FINDINGS

### 1.1 Critical (wrong result, false claim, or failed demo)

| ID | Where | Defect | Fix in v2 |
|---|---|---|---|
| F01 | v1 Phase 5 HLPSL | `secret(Gb, ...)` and `secret(Ga, ...)` target public DH values that travel in the clear, so secrecy is violated in **both** models and `dh_auth` cannot be SAFE. Also: `?` pattern syntax is not HLPSL (use primed variables); `start` is predefined but redeclared as a constant; `ki` is undeclared and `inv(ki)` is not given to the intruder; only client-to-server authentication is modelled, yet server authentication is the property that defeats the MITM; role order (Alice starts) contradicts the code (server starts). | Part 5: model `exp(G,X)`, derive the key, make a payload encrypted under the key the secret, authenticate in both directions, mirror the real role order. |
| F02 | v1 Phase 2 `validate_public_value`, Part 6, viva Q4 | Range check `1 < v < p-1` removes only orders 1 and 2. Order-`2q` elements still pass and leak one bit of the private exponent. `TESTED`: `11` passes the range check and fails `pow(v,q,p)==1`. | Reject anything outside the order-`q` subgroup (`dec()` in Appendix A). Correct the claim text. |
| F03 | v1 Part 6 "No forward secrecy", viva Q14 | Wrong. Fresh exponents per connection, signed by a long-term key, give forward secrecy against later key compromise (same idea as DHE-RSA). What a stolen signing key does break is **future impersonation**. Table row "Identity not bound: partial / Already fixed" contradicts itself. | Part 9 rewritten; viva Q14 rewritten. |
| F04 | v1 Phase 2 `CryptoProtocol` | One AES key for both directions, random 96-bit nonces, no counters. Mallory can reflect Alice's ciphertext back to her as if Bob sent it, replay it, reorder it, or drop it. `TESTED`: directional keys plus counters reject all four. | Two HKDF-derived keys, counter nonces, direction label as AAD (`Record` in Appendix A). |
| F05 | v1 Phase 3 signed data | `b"client-hello" + B_bytes + A_bytes` with `(bit_length+7)//8` encoding: the boundary between `B` and `A` is ambiguous. `TESTED`: two different splits produce identical bytes. | Fixed 256-byte big-endian encoding everywhere; length-checked on receive. |
| F06 | v1 Phase 3 protocol | Server signs only its own `A`. A replayed old server hello authenticates nobody live (no freshness, no key confirmation). `TESTED`: a replayed M1 passes the M1 check, and the replayer cannot produce the new M3. | Third message: server signs the full transcript including the client's fresh value. |
| F07 | v1 Phase 6 | `--mfa` is allowed without `--secure`. Over the unauthenticated channel Mallory decrypts the password and the OTP and can relay them within 30 seconds. TOTP is relayable by design. | `--mfa` without `--secure` is a hard error unless `--allow-insecure-mfa` is given (used once, deliberately, to demo the leak). |
| F08 | v1 Phase 6 `mfa.py` | Reason codes (`USER_NOT_FOUND`, `WRONG_OTP`) go back to the client: user enumeration, and "wrong OTP" confirms the password was right. A TOTP code can be reused inside its window (RFC 6238 section 5.2). Lockout lives only in process memory, so reconnecting resets it. Credentials are colon-delimited (breaks if the password has `:`). PBKDF2 at 200,000 iterations is below current OWASP guidance for SHA-512 (210,000, as far as I recall; verify). | Generic failure to the client, detail on the server terminal; last-used time-step stored; lockout persisted; JSON messages; 210,000 iterations; dummy hash for unknown users. |
| F09 | v1 Phase 4 `mitm.py` snippet | Reuses **one** `DiffieHellman` object for both legs, so Mallory's value toward Alice equals her value toward Bob. Sends to Bob before reading the client. Uses `get_line(conn)` and `conn.send()` while other phases use `conn.recv()`: the transport API is undefined. | Part 4, Phase 1.5 defines one transport API; Phase 4 uses two independent exchanges. |
| F10 | v1 `network.py` (unverified) | If `listen()` binds all interfaces, the demo exposes an interception proxy on the college LAN. This contradicts Context section 17. `ASSUMED`, check the source. | Bind `127.0.0.1` by default; any other address needs an explicit `--bind`. |
| F11 | v1 dependencies | `>=` ranges violate the context rule "pinned dependencies". `pytest` is in no requirements file, so the v1 clean-environment test fails by construction. After Phase 2 two crypto stacks ship (`pycryptodome` and `cryptography`). The Phase 0 headless tests call the CBC API that Phase 2 deletes and are missing from the Phase 2 file list. | Exact pins, `requirements-dev.txt`, drop `pycryptodome` in Phase 2, update the headless tests in the same commit. |
| F12 | v1 phases | Report, slides, backup video and viva sheet appear only in the timeline, with no phase, owner or gate. The video is slated for `docs/` in git. | New Phase 8; video goes to a release asset or drive link, never the repo. |
| F13 | v1 repo tree | No `LICENSE` file in the tree. MIT requires the copyright and permission notice to be kept. The upstream author names in v1 are unverified. | `LICENSE` with upstream text kept verbatim; `UPSTREAM.md` with upstream commit SHA. Verify the names from upstream `LICENSE` or `README`. |

### 1.2 High and medium

| ID | Defect | Fix |
|---|---|---|
| F14 | Phase 0 GUI check is still unticked, yet Phase 2 rewrites the code the GUI calls. The GUI is demo-critical. | Gate G0 before Phase 2. |
| F15 | Naming is inconsistent: context has Alice initiating and signing `A`; v1 has the server (Bob) sending `A` first; v1 HLPSL has Alice starting. | One convention (Part 3.1): **Server = Bob = sends first**, values named `Gs`, `Gc`. |
| F16 | No rule for mode mismatch. A secure endpoint facing a legacy peer may hang or fall back. | Fail closed, never negotiate down; timeouts; tests (Phase 3). |
| F17 | No socket timeouts or message-size limits. Tests that sleep, use fixed ports, and read piped stdout will hang or flake (Python block-buffers piped stdout). | Phase 1.5: timeouts, max line length, `PYTHONUNBUFFERED=1`, free-port helper, readiness by log line. |
| F18 | All four PEMs sit in one directory, so the Alice process can read Bob's private key. Mallory needs her own key pair for the own-key forgery. File names are hard-coded. Check-then-write key generation is racy. No fingerprint is shown for out-of-band verification. | `keys/alice/`, `keys/bob/`, `keys/mallory/`; `--key-dir`; `O_EXCL` creation, mode `0600`; print SHA-256 fingerprints. |
| F19 | `alice_mfa_qr.png` encodes the TOTP secret and is not git-ignored. | Ignore `*_mfa_qr.png`, `.pytest_cache/`, `venv*/`, `deps/`, `*.mp4`. |
| F20 | Wireshark on Windows loopback needs the Npcap loopback adapter and admin rights, which lab PCs may lack. The payload is base64 wrapped, so "Follow TCP Stream" is needed. No fallback. | Phase 7: `--trace` flag prints raw wire lines; Wireshark is optional. Risk R9. |
| F21 | The MFA demo depends on the phone and PC clocks agreeing and on the phone surviving. | Clock check in the pre-demo list; `enroll.py --show-code` prints the current code as a fallback. |
| F22 | Viva answers cite `mitm.py` line numbers (58 to 74). They drift after any edit. | Cite functions, not lines. |
| F23 | PSS verification with `MAX_LENGTH` salt is non-portable. Group sanity uses `assert`, which vanishes under `python -O`. Exponent comment says `[2,p-2]` but the code yields `[2,p-1]`. | Salt = 64 (digest size); explicit `raise`; exponent in `[2,q-1]`. |
| F24 | Timeline: AVISPA (highest install risk) is untouched until Day 6 and owned by one person. No feature freeze. Nothing is anchored to the unknown deadline. | Part 11. |
| F25 | Open items omit faculty approval of the topic and the one-PC versus two-PC decision (it changes key distribution). | Part 13. |
| F26 | `conn._sock.close()` reaches into a private attribute; the `run.py` snippet uses an undefined `is_server`. | `Transport.close()` in Phase 1.5. |
| F27 | v1 names CL-AtSe as the second AVISPA back-end for exponentiation. Its `exp` support is not confirmed; OFMC is the documented one. The AVISPA web interface is not verified to exist. `ASSUMED` both. | Part 5: OFMC first, CL-AtSe only if it accepts the model, no reliance on the web tool. |
| F28 | The runbook contains a personal local path. | Use `<repo>`. |
| F29 | v1 marks Phase 1 as "Day 2" while the audit trail shows Phases 0 and 1 done on the same day. | Part 11 re-baselines. |
| F30 | Context section 9.1 (sign `A` only) and section 4.2 conflict with the v1 design. | This file supersedes; annotate the context file. |

### 1.3 Verified correct in v1 (keep)

The RFC 3526 group-14 constant in v1 is correct. `TESTED`: 2048 bits, `p` prime, `q=(p-1)/2` prime, `2^q mod p == 1`, and the value matches the RFC formula `2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476)`. A full-size modular exponentiation takes about 22 ms, so speed is not a concern and risk R3 can be downgraded. Also correct: domain labels, `HandshakeError` raised by library and caught by `run.py`, the PEM policy (D15), the decision to drop `--toy-params`, HKDF over a bare hash, AES-GCM over CBC.

---

## PART 2: DECISION LOG (REVISED)

| # | Decision | Value | Change vs v1 |
|---|---|---|---|
| D1 | Python | 3.13 target, code must also run on 3.10 or later (`ASSUMED` lab PCs may differ; test on the demo machine) | clarified |
| D2 | GUI | keep, plus `--no-gui` | same |
| D3 | DH group | RFC 3526 group 14 in all modes | same |
| D5 | Signatures | RSA-PSS, SHA-512, **salt 64 bytes**, RSA-2048 | salt fixed |
| D8 | Record layer | AES-256-GCM, **two directional keys, counter nonces, direction in AAD** | new |
| D9 | KDF | HKDF-SHA-256, **salt = transcript hash**, 64-byte output split in two | new |
| D10 | Handshake | **3 messages, both DH values and both key fingerprints inside every signature** | new |
| D11 | Trust model | pinned public keys, distributed out of band; no fallback, no negotiation | clarified |
| D12 | MFA | TOTP plus PBKDF2-SHA-512 (210,000), inside the GCM channel, **requires `--secure`** | tightened |
| D13 | Lockout | 3 failures, 30 s, persisted in `users.json` | persisted |
| D14 | `HandshakeError` | raised by library, caught by `run.py` | same |
| D15 | PEM policy | `*.pem` ignored, `gen_keys.py` refuses overwrite atomically | same |
| D16 | Libraries | `cryptography` only, exact pins, `pycryptodome` removed in Phase 2 | new |
| D17 | Bind address | `127.0.0.1` default, `--bind` explicit | new |
| D18 | Formal verification | AVISPA (OFMC) as named in the syllabus; ProVerif only as an honestly labelled cross-check | clarified |
| D19 | Video and large binaries | never in git | new |

**Phase order:** 0 ✅, 1 ✅, **1.5**, 2, 3, 4, 5 (formal, install spike starts Day 1), 6 (MFA), 7 (docs), **8 (report, slides, rehearsal)**.

---

## PART 3: FROZEN PROTOCOL SPECIFICATION (DHC1)

Change nothing here without re-running the formal models and the Appendix A tests.

### 3.1 Naming (single convention, used in code, diagrams and models)

| Symbol | Meaning |
|---|---|
| S | server process, plays Bob, **sends first** (matches the upstream repo) |
| C | client process, plays Alice |
| M | Mallory, the MITM proxy |
| `Gs = g^s`, `Gc = g^c` | server and client DH public values (256 bytes each, big-endian, fixed width) |
| `FPs`, `FPc` | SHA-256 of each side's DER SubjectPublicKeyInfo (32 bytes) |
| `Ks`, `Kc` | long-term RSA keys, pinned by the peer |

### 3.2 Messages (one JSON object per line, `type` checked, version 1)

```
M1  S -> C : {t:"hello",   v:1, gs, sig_S}     sig_S = Sign_S( "DHC1|server-hello|" || "modp2048" || "|" || Gs )
M2  C -> S : {t:"auth",    gc, sig_C}          sig_C = Sign_C( "DHC1|client-auth|"  || FPs || FPc || Gs || Gc )
M3  S -> C : {t:"confirm", sig_S2}             sig_S2 = Sign_S( "DHC1|server-auth|" || FPs || FPc || Gs || Gc )

shared  = g^(s*c) mod p            (each side validates the peer value with the subgroup check first)
th      = SHA-256( FPs || FPc || Gs || Gc )
k_c2s || k_s2c = HKDF-SHA-256( ikm = enc(shared), salt = th, info = "DHC1 record keys", length = 64 )
record nonce   = 0x00000000 || counter64 (per direction, starts at 0), AAD = "c2s" or "s2c"
```

Why each element exists:

- M1 signature lets the client abort early on a forged `Gs` (good demo output), but it binds no freshness. M3 supplies freshness and key confirmation because it covers the client's fresh `Gc`.
- Every signed string starts with a unique label (cross-role replay is impossible) and uses only fixed-width fields (no re-parsing ambiguity).
- Both fingerprints are inside the signatures, so a signature cannot be lifted into a session with a different key pair (defence against unknown-key-share).
- Directional keys stop reflection. Counters stop replay, reorder and drop. Transcript-bound HKDF ties the keys to exactly this handshake.

### 3.3 Modes and failure behaviour

| Rule | Behaviour |
|---|---|
| Mode is fixed by `--secure`; there is **no negotiation and no fallback** | A secure endpoint that receives a legacy line aborts with `peer is not speaking DHC1`. |
| Every handshake read has a timeout (default 5 s) and a maximum line length (default 64 KiB) | Stalled or oversized input aborts. |
| Every abort path raises `HandshakeError`; only `run.py` prints and exits | Library code never calls `sys.exit`. |
| Vulnerable mode keeps the legacy 3-line `p, g, A` wire format | Client still rejects non-RFC `p, g` and runs the subgroup check on received values; Mallory's own valid values pass, so the MITM still works and the demo stays honest. |
| Vulnerable mode uses the same record layer, with empty fingerprints in the transcript hash | Mallory runs two separate exchanges and two record layers, as in upstream. |

### 3.4 Terminology fix for the report

Upstream calls the attack "parameter injection". In this codebase the working attack is **substitution of DH public values** by an active intermediary (Mallory sends her own `g^m` to each side). Rejecting bad `p, g` (Phase 2) blocks only the different attack of injecting weak parameters. Say both, and do not mix them up in the viva.

---

## PART 4: PHASED PLAN WITH GATES

### ✅ PHASE 0: Python 3 port (tag `phase-0`, commit `63b402d`)

Done. Carry over the v1 change list unchanged.

🚦 **G0 (new, blocking for Phase 2):** run Scenarios 1 and 2 with the Tkinter GUI on the actual demo machine. Both windows must open and show text. Record the result in the audit trail. If the GUI fails, keep `--no-gui` as the demo path and record that decision.

### ✅ PHASE 1: `--secure` and `--no-gui` plumbing (tag `phase-1`)

Done. Record the commit SHA in the audit trail (missing in v1).

### 🔲 PHASE 1.5: Transport, repo hygiene, test harness (new)

**Branch** `feat/foundation`. Must merge before Phase 2.

| Item | Work |
|---|---|
| Transport API | In `network.py`: `send_line(str)`, `recv_line(max_len=65536) -> str`, `settimeout(sec)`, `close()`. Replace every `conn._sock` use. One API for run, mitm, tests and MFA. |
| Bind address | Default `127.0.0.1`; `--bind ADDR` on `run.py` and `mitm.py`. Verify current behaviour first and record it (F10). |
| Licensing | Add `LICENSE` with the upstream MIT text verbatim. Add `UPSTREAM.md`: upstream URL, upstream commit SHA, authors copied from upstream `LICENSE` or `README` (do not trust v1's names until checked). `git remote add upstream ...` so `git diff --stat upstream/master` produces the "what we changed" table for the report. |
| Dependencies | `requirements.txt` with exact pins. `requirements-dev.txt` with pinned `pytest`. Generate pins from a clean 3.13 venv with `pip freeze`, then test on the demo machine. |
| Ignore file | `*.pem`, `keys/**/*.pem`, `users.json`, `*_mfa_qr.png`, `venv*/`, `__pycache__/`, `.pytest_cache/`, `deps/`, `*.mp4`. |
| Test helpers | `tests/helpers.py`: `free_port()`, `start(proc_args, ready_line, timeout)` (waits for a readiness line, not `sleep`), `kill_all()`. Launch every subprocess with `PYTHONUNBUFFERED=1` and `python -u`. Add a one-line `print("[*] listening", flush=True)` readiness signal to server and MITM. |
| CI | `.github/workflows/ci.yml`: install pinned deps, run `pytest -q`, matrix of ubuntu and windows, Python 3.10 and 3.13. This replaces "trust me, it works on a second machine". |

**Tests** (`tests/test_network.py`): oversized line rejected; read timeout raises; `close()` idempotent; default bind is loopback.

**Commit** `phase-1.5: transport API, timeouts, loopback default, LICENSE, pins, CI`

### 🔲 PHASE 2: Crypto modernization (MITM must still work)

**Branch** `feat/modern-crypto`.

| File | Change |
|---|---|
| `diffie_hellman.py` | RFC 3526 constants; explicit `raise` group sanity check (no `assert`); exponent `secrets.randbelow(q-2)+2`; `validate_public_value` = range check **and** `pow(v,q,p)==1`; reject non-RFC `p, g` from the peer. Drop `Crypto.PublicKey.RSA`. |
| `crypto_protocol.py` | Replace CBC and PKCS#7 with `derive_keys` and `Record` from Appendix A. Class takes `(shared_secret, fp_s, fp_c, gs, gc, is_server)`. |
| `mitm.py` | Holds two independent exchanges and two `Record` objects (toward server as a client role, toward client as a server role). |
| `run.py`, `gui.py` | Adapt to the new API. |
| `headless_test.py`, `headless_mitm_test.py` | Port to the new API in the **same commit** (F11). |
| `requirements.txt` | Remove `pycryptodome`; add pinned `cryptography`. |
| `README.md`, `DEMO.md` | Remove every CBC claim. |

**Tests** (`tests/test_crypto_v2.py`): round trip; tamper raises `InvalidTag`; **replay, reorder and drop rejected**; **reflection rejected**; two sessions give different keys and ciphertexts; group checks (2048 bits, `p` and `q` prime by Miller-Rabin, `g^q==1`); bad values rejected: `0, 1, p-1, p, 11 (non-residue), wrong length`; non-RFC `p, g` rejected; vulnerable MITM test still prints `[PASS] MITM attack succeeded`.

🚦 **G2:** `pytest` green and the vulnerable MITM test passes. If the MITM no longer works, stop and fix before Phase 3.

**Commit** `phase-2: AES-256-GCM directional keys, HKDF with transcript, subgroup check; MITM still works`

### 🔲 PHASE 3: Signed handshake (`--secure` becomes real)

**Branch** `feat/signed-dh`. Implement exactly Part 3; start from Appendix A.

| File | Action |
|---|---|
| `auth_dh.py` | Key generation, load and save (PKCS8 and SubjectPublicKeyInfo PEM), `sign`, `verify`, `fingerprint`, `HandshakeError`. Re-export from Appendix A where it fits. |
| `gen_keys.py` | `python gen_keys.py [alice bob mallory]`. Creates `keys/<name>/<name>_priv.pem` (mode `0600`) and `<name>_pub.pem` with `os.open(..., O_CREAT|O_EXCL)`. Refuses to overwrite. Prints fingerprints. Mallory's pair exists only so the own-key forgery can be demonstrated. |
| `crypto_protocol.py` | `secure_handshake_server(transport, priv, pinned_peer_pub)` and `secure_handshake_client(...)` wrap the `Server` and `Client` state machines from Appendix A, add timeouts, and return a `Record`. |
| `run.py` | `--secure`, `--key-dir`, `--peer-pub`. Prints `Pinned peer key SHA256: <hex>` at startup. Catches `HandshakeError` and `FileNotFoundError`, prints the abort banner, calls `transport.close()`, exits non-zero. |
| `mitm.py` | Unchanged in this phase. |

**Tests** (`tests/test_auth_dh.py` and Appendix A tests): sign and verify round trip; wrong key; tampered data; domain separation; transcript has no ambiguity; every malformed input raises `HandshakeError` (bad hex, wrong length, missing field, wrong type, oversized); secure client versus legacy server aborts within the timeout; legacy client versus secure server aborts; end-to-end secure chat in two threads; `gen_keys` refuses to overwrite and sets permissions; fingerprints are stable.

🚦 **G3:** secure chat works without a MITM and all tests are green.

**Commit** `phase-3: DHC1 signed handshake, gen_keys, fingerprints, fail-closed mode handling`

### 🔲 PHASE 4: Show the attack failing

**Branch** `feat/attack-demo`. Keep the attack code minimal and tied to this chat (Context section 17).

`mitm.py --secure` implements three behaviours, selected by `--attack`:

| Mode | What Mallory does | Expected result |
|---|---|---|
| `substitute` (default) | Reads the real M1, builds her own exchange with an independent exponent, signs her own `Gs` with **her own RSA key**, sends it to the client. Independently impersonates the client to the server with her own value. | Client: `Signature verification FAILED`. Server: aborts on M2 or times out. |
| `splice` | Keeps the real signature and swaps in her own `Gs`. | Client aborts (signature does not cover her value). |
| `relay` | Forwards every handshake line unmodified, then relays records. | Chat works; MITM log shows only ciphertext and `cannot decrypt (AES-GCM)`. This is the honest "she can do nothing useful" case. |

Two independent `DiffieHellman` objects, one per leg (fixes F09). No global state.

**Scenario tests** (`tests/test_secure_vs_mitm.py`, each with a timeout, free ports, readiness lines, `PYTHONUNBUFFERED=1`):

1. vulnerable chat works
2. vulnerable chat plus MITM: plaintext visible in the MITM log
3. secure chat works
4. secure plus MITM `substitute`: both endpoints print `Signature verification FAILED`; assert each endpoint separately, **do not assert output order** across processes
5. secure plus MITM `splice`: client aborts
6. secure plus MITM `relay`: chat works, no plaintext in MITM log
7. replayed M1 against a fresh client: client cannot complete because M3 fails
8. wrong pinned peer key: abort

🚦 **G4:** all eight scenarios green three runs in a row (catches flakiness).

**Commit** `phase-4: MITM substitute, splice and relay modes; 8 scenario tests`

### 🔲 PHASE 5: Formal verification (AVISPA) (see Part 5)

Starts on **Day 1** as an install spike. Model writing needs only the frozen Part 3 spec, so it runs in parallel with Phases 2 to 4.

### 🔲 PHASE 6: MFA (see Part 6)

**Branch** `feat/mfa`. Depends on G3.

### 🔲 PHASE 7: Docs and polish

**Branch** `feat/docs`.

| Item | Work |
|---|---|
| `README.md` | Credit upstream authors (verified names), MIT notice, all modes, exact commands, scope and ethics statement (localhost only, no ARP poisoning, no extension into a general tool). |
| `DEMO.md` | The runbook in Part 8, with ports and start order. |
| Diagrams | Mermaid for normal DH, the substitution attack, DHC1 with a failing MITM. Use the naming from Part 3.1. |
| `--trace` flag | Prints each wire line (truncated) so the demo can show ciphertext without Wireshark (F20). |
| Clean-environment test | See below. |

```powershell
python -m venv venv_test
venv_test\Scripts\pip install -r requirements.txt -r requirements-dev.txt
venv_test\Scripts\python -m pytest -q
venv_test\Scripts\python headless_test.py
venv_test\Scripts\python headless_mitm_test.py
```

**Commit** `phase-7: README, DEMO.md, diagrams, trace flag, clean-env test`

### 🔲 PHASE 8: Report, slides, rehearsal (new)

**Branch** `feat/report`. Owner: Verification and docs, with the lead reviewing.

| Deliverable | Location | Notes |
|---|---|---|
| Report (6 to 10 pages, confirm with faculty) | `docs/report/` | Follow Context section 13. Add a "what we changed" table generated from `git diff --stat upstream/master`. Name the folder `docs/report/` so it is never confused with upstream's `report/`. |
| Slides | `docs/slides/` | Include the syllabus map and the UNSAFE and SAFE screenshots **only if produced by a real run**. |
| Viva sheet | `docs/VIVA.md` | Part 12, each member signs off. |
| Backup video | release asset or drive link | Never committed to git. Link it from `DEMO.md`. |

---

## PART 5: FORMAL VERIFICATION PLAN (AVISPA)

### 5.1 Status and honesty rule

Nothing in this part has been run. No AVISPA or ProVerif binary was available in the review sandbox (ProVerif was not installable from the available package sources). Every model below is `UNRUN`. **Do not put an UNSAFE or SAFE screenshot in the report unless your own run produced it.** If AVISPA cannot be installed, say so in the report; do not imply the tool was run.

### 5.2 Install spike (Day 1, owner: Verification and docs, time box 3 hours)

Search results show AVISPA is distributed through the SPAN package hosted at IRISA (`people.irisa.fr/Thomas.Genet/span/`), with Windows, Linux and macOS packages for old versions, and OFMC is also available as open-source Haskell (build with `stack`). The older binary packages are described as no longer supported. Consequences:

1. Try the SPAN Linux package in WSL or a Linux VM first. Older binaries may need 32-bit libraries (`ASSUMED`; fix with multiarch packages or use a VM image).
2. Do not plan around an AVISPA web interface; its current existence is unverified.
3. If the binary path fails inside the time box, build OFMC from source with `stack`, or ask the faculty whether a lab machine already has AVISPA.
4. Record the method that worked in `avispa/README_avispa.md` and in the open-items list.

### 5.3 Defects in the v1 models and how to fix them

The corrections are listed under F01. The concrete modelling rules:

- Model DH as `exp(G, X)` with `G : text` and `X : text` fresh per role. The shared key is `exp(exp(G,X),Y)`, never a stand-in fresh value.
- The secret goal must target a **payload encrypted under the derived key**, not a public DH value. Example: after the handshake the client sends `{Msg'}_K` with `Msg'` fresh, and the goal is `secrecy_of sec_msg`.
- Receive unknown values with primed variables in the pattern (`RCV(GY'.{...}_inv(Ks))`), not with `?`.
- Use the predefined `start`; do not redeclare it.
- Give the intruder its own key and its private key: `intruder_knowledge = {alice, bob, ka, kb, ki, inv(ki)}`.
- Put labels in as `protocol_id` constants and include them inside the signed terms, matching Part 3.2.
- Model **both** authentication directions: server authenticates to client on `Gs`, client authenticates to server on `Gc`, plus agreement on the pair.
- Mirror the code's role order: the server sends first.
- Two sessions for the intruder: `session(alice, bob)`, `session(alice, i)`, `session(i, bob)`.

### 5.4 `dh_unauth.hlpsl` (UNRUN, expected UNSAFE)

```hlpsl
%% dh_unauth.hlpsl : unauthenticated DH, Dolev-Yao intruder. UNRUN.
%% Expected: UNSAFE (intruder substitutes DH values, learns the key).

role server(S, C : agent, G : text, SND, RCV : channel(dy))
played_by S def=
  local State : nat, X : text, GY : message, K : message, Msg : text
  init  State := 0
  transition
    1. State = 0 /\ RCV(start) =|>
       State' := 2 /\ X' := new() /\ SND(exp(G,X'))
    2. State = 2 /\ RCV({Msg'}_exp(GY',X)) =|>         %% payload under the derived key
       State' := 4 /\ request(S, C, auth_c_msg, Msg')
end role

role client(S, C : agent, G : text, SND, RCV : channel(dy))
played_by C def=
  local State : nat, Y : text, GX : message, Msg : text
  init  State := 0
  transition
    1. State = 0 /\ RCV(GX') =|>
       State' := 2 /\ Y' := new() /\ Msg' := new()
       /\ SND(exp(G,Y')) /\ SND({Msg'}_exp(GX',Y'))
       /\ witness(C, S, auth_c_msg, Msg') /\ secret(Msg', sec_msg, {S,C})
end role

role session(S, C : agent, G : text) def=
  local SS, RS, SC, RC : channel(dy)
  composition server(S, C, G, SS, RS) /\ client(S, C, G, SC, RC)
end role

role environment() def=
  const s, c : agent, g : text, sec_msg, auth_c_msg : protocol_id
  intruder_knowledge = {s, c, g}
  composition session(s, c, g) /\ session(s, i, g) /\ session(i, c, g)
end role

goal
  secrecy_of sec_msg
  authentication_on auth_c_msg
end goal

environment()
```

### 5.5 `dh_auth.hlpsl` (UNRUN, expected SAFE)

```hlpsl
%% dh_auth.hlpsl : DHC1 (Part 3.2) with signatures and both directions. UNRUN.
%% Expected: SAFE for secrecy and both authentication goals.
%% Likely edits when you first run it: declare K as symmetric_key or keep as
%% message depending on your AVISPA version; adjust the pairing of fingerprints
%% (here agents S and C stand in for FPs and FPc).

role server(S, C : agent, Ks, Kc : public_key, G : text, SND, RCV : channel(dy))
played_by S def=
  local State : nat, X : text, GY : message, Msg : text
  const server_hello, client_auth, server_auth : protocol_id
  init  State := 0
  transition
    1. State = 0 /\ RCV(start) =|>
       State' := 2 /\ X' := new()
       /\ SND(exp(G,X') . {server_hello.exp(G,X')}_inv(Ks))
       /\ witness(S, C, auth_s_gs, exp(G,X'))
    2. State = 2 /\ RCV(GY' . {client_auth.S.C.exp(G,X).GY'}_inv(Kc)
                        . {Msg'}_exp(GY',X)) =|>
       State' := 4
       /\ SND({server_auth.S.C.exp(G,X).GY'}_inv(Ks))
       /\ request(S, C, auth_c_gc, GY')
       /\ request(S, C, auth_c_msg, Msg')
end role

role client(S, C : agent, Ks, Kc : public_key, G : text, SND, RCV : channel(dy))
played_by C def=
  local State : nat, Y : text, GX : message, Msg : text
  const server_hello, client_auth, server_auth : protocol_id
  init  State := 0
  transition
    1. State = 0 /\ RCV(GX' . {server_hello.GX'}_inv(Ks)) =|>
       State' := 2 /\ Y' := new() /\ Msg' := new()
       /\ SND(exp(G,Y') . {client_auth.S.C.GX'.exp(G,Y')}_inv(Kc)
              . {Msg'}_exp(GX',Y'))
       /\ witness(C, S, auth_c_gc, exp(G,Y'))
       /\ witness(C, S, auth_c_msg, Msg')
       /\ secret(Msg', sec_msg, {S,C})
    2. State = 2 /\ RCV({server_auth.S.C.GX.exp(G,Y)}_inv(Ks)) =|>
       State' := 4 /\ request(C, S, auth_s_gs, GX)
end role

role session(S, C : agent, Ks, Kc : public_key, G : text) def=
  local SS, RS, SC, RC : channel(dy)
  composition server(S, C, Ks, Kc, G, SS, RS) /\ client(S, C, Ks, Kc, G, SC, RC)
end role

role environment() def=
  const s, c : agent, ks, kc, ki : public_key, g : text,
        sec_msg, auth_c_gc, auth_c_msg, auth_s_gs : protocol_id
  intruder_knowledge = {s, c, g, ks, kc, ki, inv(ki)}
  composition session(s, c, ks, kc, g)
           /\ session(s, i, ks, ki, g)
           /\ session(i, c, ki, kc, g)
end role

goal
  secrecy_of sec_msg
  authentication_on auth_c_gc, auth_c_msg, auth_s_gs
end goal

environment()
```

### 5.6 How to run and how to read results

```bash
# from SPAN's bundled AVISPA, or your own install
avispa avispa/dh_unauth.hlpsl --ofmc
avispa avispa/dh_auth.hlpsl   --ofmc
avispa avispa/dh_auth.hlpsl   --cl-atse     # only if it accepts exp; skip otherwise
```

- Read `SUMMARY` (SAFE or UNSAFE) and `DETAILS` (for example `ATTACK_FOUND`, `BOUNDED_NUMBER_OF_SESSIONS`).
- "SAFE" here means safe for a **bounded number of sessions** under Dolev-Yao with OFMC's defaults. Say so in the viva.
- If `dh_auth` reports UNSAFE, that is useful: read the trace, it may expose a real flaw or a modelling slip. Fix the model or the protocol, then re-run. Do not edit goals to obtain SAFE.

### 5.7 Fallback and cross-check (optional)

If AVISPA will not run, a ProVerif model of the same message flow gives a real machine-checked result, but it is **not** AVISPA and must be labelled ProVerif in the report. Syllabus credit is for AVISPA, so exhaust 5.2 first.

### 5.8 What the formal result does not cover

Implementation bugs (wrong label in code), side channels, the record layer (modelled only as "a payload under the derived key"), compromised private keys, and anything outside Dolev-Yao. The Python tests in Appendix A cover the implementation side.

---

## PART 6: MFA (TOTP) SPECIFICATION

**Purpose:** authenticate the **human** behind the client process. The RSA key authenticates the **machine** (or the key holder). Explain that layering in the viva. MFA does **not** stop a real-time MITM; the signed handshake does.

### 6.1 Rules

| Rule | Detail |
|---|---|
| Channel | Runs after the handshake, inside the GCM channel. `--mfa` requires `--secure`; otherwise exit with an error, unless `--allow-insecure-mfa` (demo only, shows Mallory capturing the password and OTP). |
| Messages | JSON objects sealed by `Record`, never colon-joined strings. |
| Client output | Generic `MFA_FAIL`. Specific reasons (`USER_NOT_FOUND`, `WRONG_PASSWORD`, `WRONG_OTP`, `LOCKED_OUT`, `OTP_REUSED`) appear **only on the server terminal**, so the demo still shows "right password, wrong code is rejected". |
| Unknown user | Still run one PBKDF2 against a dummy salt so timing does not reveal user existence. |
| Password hashing | PBKDF2-HMAC-SHA-512, **210,000** iterations, 16-byte random salt, `hmac.compare_digest`. |
| TOTP | `pyotp`, 30 s step, `valid_window=1`, store the last accepted time-step and reject any code at or below it (RFC 6238 section 5.2). |
| Lockout | 3 consecutive failures lock the user for 30 s; counters persist in `users.json` (`failed`, `locked_until`). Inject the clock so tests do not sleep. |
| Prompts | Use `getpass` for the password. Run prompts on the terminal **before** the GUI window opens, or confirm first that the handshake runs in the main thread (`ASSUMED`; check `run.py`). |
| Secrets at rest | `users.json` holds the TOTP secret in clear (demo limitation, state it). `enroll.py` prompts for the password, writes `keys/../users.json` and `alice_mfa_qr.png`, both git-ignored. |
| Fallback | `python enroll.py --show-code alice` prints the current code so the demo survives a dead phone. |

### 6.2 Flow

```
C -> S : Enc({"t":"mfa","user":u,"pw":p,"otp":"123456"})
S -> C : Enc({"t":"mfa_ok"})  or  Enc({"t":"mfa_fail"})     (no reason)
on fail: both sides close; server logs the reason
```

### 6.3 Tests (`tests/test_mfa.py`)

enroll creates record; correct login; wrong password; wrong OTP; OTP reuse rejected; unknown user gives the same client-visible result as a wrong password; lockout after 3 failures; lockout expires (fake clock); lockout survives a reconnect; password containing `:` works; constant-time comparison used; `--mfa` without `--secure` exits with an error; end-to-end over the channel in two threads.

**Commit** `phase-6: TOTP+PBKDF2 MFA inside GCM channel, replay protection, persisted lockout`

---

## PART 7: TEST STRATEGY

| Layer | Files | Proves |
|---|---|---|
| Unit | `tests/test_args.py` ✅, `test_network.py`, `test_crypto_v2.py`, `test_auth_dh.py`, `test_mfa.py` | Each rule in Parts 3 and 6 |
| Protocol | Appendix A test file (16 tests, `TESTED`) | Forgery, splice, substitution, replayed M1, reflection, replay, reorder, bad DH values |
| Scenario | `tests/test_secure_vs_mitm.py` | The 8 end-to-end scenarios with real processes |
| Integration | `headless_test.py`, `headless_mitm_test.py` | DH, record layer and MITM without the GUI |
| CI | `.github/workflows/ci.yml` | Clean install on Linux and Windows, Python 3.10 and 3.13 |
| Manual | Part 8 checklists | GUI, phone OTP, Wireshark |

Process-test rules: free ports from the OS; readiness by log line; `PYTHONUNBUFFERED=1`; every wait has a timeout; every process is killed in a `finally`; never assert cross-process output order; run the scenario file three times in a row before tagging.

---

## PART 8: DEMO RUNBOOK

Use `<repo>` paths. Three keys exist: `keys/alice/`, `keys/bob/`, `keys/mallory/`. The Alice process is pointed only at Alice's private key and Bob's public key, and symmetrically for Bob.

### 8.1 Pre-demo (day before)

```powershell
cd <repo>; venv\Scripts\activate
python gen_keys.py alice bob mallory       # refuses to overwrite; prints fingerprints
python enroll.py alice                       # prompts for a password; saves alice_mfa_qr.png
python -m pytest -q
python headless_test.py; python headless_mitm_test.py
```

Checklist:

- [ ] Fingerprint of Bob's key as printed by Alice's process equals the one printed by `gen_keys.py`
- [ ] PC clock and phone clock agree to within a few seconds (TOTP)
- [ ] `python enroll.py --show-code alice` works (phone fallback)
- [ ] GUI opens on the demo PC (gate G0), or `--no-gui` path rehearsed
- [ ] Wireshark: Npcap loopback adapter present **or** `--trace` rehearsed (F20)
- [ ] `git log --all --full-history -- "*.pem"` prints nothing
- [ ] Backup video link opens

### 8.2 Scenarios

| # | Commands (separate terminals) | Expected |
|---|---|---|
| 1 Normal | `python run.py 9000` then `python run.py 127.0.0.1 9000` | Banner `VULNERABLE`; chat works; `--trace` or Wireshark shows only ciphertext after the handshake |
| 2 Attack | server `python run.py 9000`; `python mitm.py 127.0.0.1 9000 9001`; client `python run.py 127.0.0.1 9001` | MITM log prints `[MITM][client] INTERCEPTED: <plaintext>` |
| 3 Fixed | same three with `--secure` on each | Client and server print `Signature verification FAILED` and `Aborting connection`; MITM prints the forgery attempt |
| 3b Relay | `mitm.py ... --secure --attack relay` | Chat works, MITM log shows ciphertext only |
| 4 MFA | `python run.py 9000 --secure --mfa` and client with the same flags | Right code: login OK. Wrong code: client sees `Login failed`, **server terminal** shows `WRONG_OTP`. Third failure: locked 30 s |
| 4b MFA leak (optional) | both with `--mfa --allow-insecure-mfa` through the MITM | MITM log shows the password and OTP: the reason `--mfa` requires `--secure` |

### 8.3 Talk track (10 minutes, unchanged structure from v1)

| Min | Step | Say |
|---|---|---|
| 0:00 | Title | "Key exchange without authentication is insecure. We break it, then fix it." |
| 1:00 | DH math | Notebook or slide, `g^a`, `g^b`, same secret, discrete log |
| 2:30 | Scenario 1 | "An eavesdropper sees only ciphertext." |
| 4:00 | MITM slide | "DH has no authentication. Mallory substitutes her own values." |
| 5:00 | Scenario 2 | "She reads everything; neither side notices." |
| 6:30 | Fix slide | "Signatures over a transcript with labels, both keys and both values." |
| 7:00 | Scenario 3 | "Same attacker, both endpoints abort." |
| 8:00 | Scenario 4 | "MFA protects the account; the signature protects the channel." |
| 9:00 | AVISPA | Only real run screenshots, or say clearly what was not run |
| 9:45 | Syllabus | Units I, III, IV |

---

## PART 9: SECURITY ANALYSIS (CORRECTED)

### 9.1 What `--secure` protects

| Threat | Protected | Mechanism |
|---|---|---|
| Passive eavesdropper | Yes, both modes | Discrete log hardness plus AES-256-GCM |
| Active MITM substituting DH values | Yes, `--secure` | RSA-PSS/SHA-512 over a labelled, fixed-width transcript |
| Replayed old server hello | Yes | M3 signs the client's fresh value |
| Cross-role signature replay | Yes | Distinct labels |
| Signature reuse under another key pair | Yes | Both fingerprints inside signatures |
| Small-subgroup and bad-parameter attacks | Yes | Subgroup check `v^q==1`, RFC group enforced |
| Ciphertext tampering, replay, reorder, drop, reflection | Yes | GCM, counters, directional keys |
| Past sessions after a later signing-key theft | **Yes (forward secrecy)** | Ephemeral exponents are fresh per connection and discarded |
| Password-only login | Yes | TOTP second factor |
| Downgrade by a MITM | Yes | No negotiation; secure endpoint fails closed |

### 9.2 What it does not protect

| Threat | Gap | Smallest honest mitigation |
|---|---|---|
| Stolen long-term private key | Attacker can impersonate that party in **future** sessions | Key rotation, passphrase-encrypted keys, revocation (PKI) |
| Key distribution | Keys are pinned out of band, no PKI, no revocation | X.509 and a CA (this is what TLS does) |
| Endpoint compromise | Plaintext visible on the endpoint | Out of scope |
| TOTP relay | A live MITM on a legacy channel can relay password and OTP | Signed channel (done); hardware tokens (WebAuthn) as future work |
| Traffic analysis | Message lengths and timing visible | Padding (future work) |
| Bounded-session formal result | AVISPA result is for a bounded number of sessions | State it |
| Denial of service | Anyone can abort the handshake | Out of scope |

---

## PART 10: RISK REGISTER

| # | Risk | L | I | Mitigation | Fallback |
|---|---|---|---|---|---|
| R1 | AVISPA will not install | High | Med | Day 1 spike, WSL or VM, build OFMC from source, ask faculty for lab access | Report states it was not run; show the attack trace as a hand-drawn sequence diagram; optional ProVerif cross-check labelled as such |
| R2 | Tkinter fails on demo PC | Low | High | Gate G0 | `--no-gui` plus terminal |
| R3 | Slow key operations | Very low | Low | Measured about 22 ms per 2048-bit exponentiation | None needed |
| R4 | Private key committed | Med | High | `*.pem` ignored, CI check, `git log` check | `git filter-repo --path-glob '*.pem' --invert-paths`, then rotate keys |
| R5 | Live demo crashes | Med | High | Rehearse three times | Backup video |
| R6 | Member absent on demo day | Low | High | Everyone runs every scenario | Solo demo |
| R7 | `pip install` blocked on lab network | Low | Med | Pre-download wheels into `deps/` (git-ignored, carried on USB) | `pip install --no-index --find-links deps/` |
| R8 | HLPSL errors | Med | Med | Start early, copy structure from the AVISPA examples | Part 5.7 |
| R9 | No Npcap or admin rights for Wireshark | Med | Low | `--trace` flag | Screenshot captured at home |
| R10 | Phone or clock problem for TOTP | Med | Med | Clock check, `--show-code` | Pre-recorded MFA segment |
| R11 | Flaky process tests | Med | Med | Helpers in Phase 1.5, three-run gate | Re-run, fix readiness logic |
| R12 | Deadline unknown | Med | High | Part 11 feature freeze relative to deadline | Must-haves first (Phases 0 to 4) |

---

## PART 11: TIMELINE (10 days, 4 members, re-baseline when the deadline is known)

**Feature freeze = Day 8.** After that, only bug fixes, docs and rehearsal. If the deadline is shorter, cut in this order: the CL-AtSe run (Part 5.6), MFA lockout persistence, Wireshark, then MFA itself. Never cut Phases 0 to 4 or the honest statement about AVISPA.

| Day | Lead / integrator | Crypto engineer | Auth and tools | Verification and docs |
|---|---|---|---|---|
| 1 | G0 GUI check; merge `phase-1`; record SHAs | Read upstream `network.py`, confirm bind address | Phase 1.5 CI and test helpers | **AVISPA install spike (time box 3 h)**; read upstream `report/` |
| 2 | Review Phase 1.5; `LICENSE`, `UPSTREAM.md` | Phase 1.5 transport API | `.gitignore`, pins, `requirements-dev.txt` | Start `dh_unauth.hlpsl` (Part 5) |
| 3 | Review | Phase 2 crypto | `test_crypto_v2.py` | Diagrams from Part 3 |
| 4 | G2; review | Phase 3 handshake | `test_auth_dh.py`, `gen_keys.py` | `dh_auth.hlpsl`, first AVISPA runs |
| 5 | G3; review | Phase 4 attack modes | `test_secure_vs_mitm.py` | Debug models; screenshots from real runs only |
| 6 | Review | Bug fixes | Phase 6 MFA core | Report draft sections 1 to 5 |
| 7 | Review | Code review of MFA | MFA tests, `enroll.py` | Report sections 6 to 9 |
| 8 | **Feature freeze**; Phase 7 docs | `--trace`, final fixes | MFA demo polish | Slides draft |
| 9 | Rehearsal 1 to 3 as MC; record backup | Fix bugs | Fix MFA timing | Viva sheet sign-offs |
| 10 | Clean-env test on second machine; submit | Buffer | Buffer | Proofread report, final slides |

---

## PART 12: VIVA PREPARATION (CORRECTED)

1. **Why is plain DH vulnerable if an eavesdropper cannot compute the key?** It resists passive attackers only. Nothing proves who sent each value, so an active attacker runs two exchanges.
2. **What exactly does Mallory send?** Her own `g^m1` to the server in place of the client's value, and her own `g^m2` to the client in place of the server's. She holds two keys and re-encrypts between them.
3. **How do signatures stop it?** Each side verifies the peer's signature with a pinned public key. Mallory cannot sign with the real private key, so a substituted value fails verification.
4. **Why is the server signature in M3 needed?** Freshness and key confirmation. M1 alone could be replayed; M3 covers the client's fresh value.
5. **Why labels, fingerprints and fixed-width fields?** Labels stop cross-role replay; fingerprints stop reuse under another key pair; fixed widths stop ambiguous re-parsing of the signed bytes.
6. **Why check `v^q mod p == 1`?** It confines values to the prime-order subgroup. A range check alone admits order-`2q` elements that leak a bit of the private exponent (shown with `11`).
7. **Does this design have forward secrecy?** Yes. Exponents are fresh per connection and discarded; only the long-term key signs. Stealing it later allows future impersonation, not decryption of recorded sessions.
8. **What is lost if the signing key is stolen?** Future impersonation and MITM on that identity. Mitigation: rotation, encrypted keys, PKI.
9. **Why two keys and counters in the record layer?** One key for both directions allows reflection; random nonces give no ordering. Directional keys plus counters reject reflection, replay, reorder and drop.
10. **Why AES-GCM over CBC?** Authenticated encryption detects tampering; the upstream CBC used a fixed IV and had no integrity check.
11. **Why HKDF with the transcript hash as salt?** Standard KDF; it binds keys to exactly this handshake and both identities.
12. **Why does `verify` raise instead of returning a boolean?** The caller cannot forget to check. Library code never exits; `run.py` decides.
13. **Why does MFA run inside the channel, and does it stop a MITM?** The credentials need a protected channel. MFA does not stop a live MITM on an unauthenticated channel, because TOTP is relayable; the signed handshake does. That is why `--mfa` requires `--secure`.
14. **What does the server tell a failed login?** Nothing specific. Reasons stay in the server log to prevent user enumeration.
15. **What does `hmac.compare_digest` prevent?** Timing side channels from early-exit comparison.
16. **What does AVISPA assume and output?** Dolev-Yao intruder; it reports SAFE or UNSAFE with an attack trace, for a bounded number of sessions.
17. **What does a SAFE result not cover?** Implementation bugs, side channels, compromised keys, the record layer, anything outside the model.
18. **Can Mallory succeed by relaying unchanged messages?** She becomes a transparent proxy and sees only ciphertext (the `relay` demo).
19. **Name versus mechanism: "parameter injection" versus substitution?** The working attack substitutes DH public values. Rejecting non-RFC `p, g` blocks a different attack.
20. **How does this relate to TLS?** Same pattern: ephemeral DH signed by a long-term key. TLS adds certificates (PKI), negotiation protected by a transcript MAC, and record-layer sequence numbers.

---

## PART 13: OPEN ITEMS

- [ ] Faculty approval of the topic and deliverables, marking scheme, report length, viva format
- [ ] Deadline (anchors Part 11)
- [ ] Group size and member names (roles assume 4)
- [ ] One PC or two lab PCs (two PCs need out-of-band public-key copy and `--bind`)
- [ ] Upstream commit SHA and verified author names (F13)
- [ ] Upstream `network.py` bind address and `run.py` thread layout (F10, Part 6 prompts)
- [ ] AVISPA install method that worked: ___
- [ ] Python version on the demo PC: ___
- [ ] Annotate or update `IS_FA2_Project_Context.md` (F30)

---

## PART 14: SYLLABUS MAPPING

| Component | File | Unit | Topic |
|---|---|---|---|
| Diffie-Hellman, RFC 3526 group, subgroup check | `diffie_hellman.py` | III | Diffie-Hellman |
| AES-256-GCM record layer | `crypto_protocol.py` | III | AES, authenticated encryption |
| MITM attack demo | `mitm.py` | I | Man-in-the-middle |
| RSA-PSS with SHA-512 signatures | `auth_dh.py` | III, IV | RSA, digital signatures, SHA-512 |
| Pinned keys, fingerprints | `gen_keys.py`, `UPSTREAM.md` | IV | Key management |
| HKDF key derivation | `crypto_protocol.py` | IV | Cryptography for authentication |
| TOTP, PBKDF2-SHA-512 | `mfa.py`, `enroll.py` | IV | Multi-factor authentication |
| AVISPA models | `avispa/*.hlpsl` | IV | MITM in public-key exchange, AVISPA |
| Threat model and limits | Part 9 | I | Threats, NIST CSF |

---

## PART 15: FINAL REPO TREE

```
<repo>/
  run.py  mitm.py  network.py  diffie_hellman.py  crypto_protocol.py  gui.py
  auth_dh.py  gen_keys.py  enroll.py  mfa.py
  headless_test.py  headless_mitm_test.py
  keys/            (git-ignored contents: alice/ bob/ mallory/)
  tests/           __init__.py helpers.py test_args.py test_network.py test_crypto_v2.py
                   test_auth_dh.py test_secure_vs_mitm.py test_mfa.py
  avispa/          dh_unauth.hlpsl dh_auth.hlpsl README_avispa.md
  docs/            diagrams/ report/ slides/ VIVA.md avispa_unsafe.png avispa_safe.png
  report/          (upstream authors' report, unchanged)
  .github/workflows/ci.yml
  requirements.txt  requirements-dev.txt
  LICENSE  UPSTREAM.md  README.md  DEMO.md
  IS_FA2_Project_Context.md  IMPLEMENTATION_PLAN.md (this file)  .gitignore
```

---

## PART 16: DEFINITION OF DONE

**Code**
- [ ] `pytest -q` green on a clean install (CI and one second machine)
- [ ] `headless_test.py` passes; `headless_mitm_test.py` prints `[PASS] MITM attack succeeded`
- [ ] `--secure` chat works; `--secure` plus MITM: both endpoints abort; `relay` shows ciphertext only
- [ ] `--mfa --secure`: right OTP in, wrong OTP rejected, reused OTP rejected, third failure locks
- [ ] Scenario file passed three runs in a row

**Hygiene**
- [ ] `git log --all --full-history -- "*.pem"` prints nothing; QR PNG and `users.json` never committed
- [ ] Pinned requirements; no `pycryptodome`; `LICENSE` and `UPSTREAM.md` present
- [ ] Mallory's attack code is minimal, binds loopback by default, and is documented as lab-only

**Formal**
- [ ] AVISPA screenshots exist **only** if produced by a real run; otherwise the report states the tool was not run

**Docs and demo**
- [ ] README, DEMO.md, three diagrams, report, slides, `VIVA.md`
- [ ] Demo rehearsed three times; backup video linked (not committed)
- [ ] Every member answered all 20 viva questions without notes
- [ ] Original authors credited (names verified from upstream)

---

## APPENDIX A: TESTED REFERENCE CORE

`dhc1_core.py` implements Parts 3.1 and 3.2 as pure functions and state machines (no sockets). `TESTED`: 16 tests passed on Python 3.12. Drop it into the repo, then wrap it with the transport in Phase 3.

```python
"""dhc1_core.py: reference core for the signed-DH chat (protocol DHC1).
Pure functions, no sockets, so every rule below is unit-testable.
Security ideas (explain these in the viva):
  * fixed-width encodings: signed transcripts cannot be re-parsed differently
  * subgroup check v^q == 1: peer value must lie in the prime-order subgroup
  * domain labels + both fingerprints + both DH values inside every signature
  * 3 messages: the server signs a transcript containing the client's fresh value
  * directional keys + sequence numbers: no reflection, replay, reorder or drop
"""
import hashlib, secrets, re
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, InvalidTag

# RFC 3526 group 14 (2048-bit MODP). Safe prime: q = (p-1)/2 is prime, g = 2 has order q.
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
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
G = 2
Q = (P - 1) // 2
WIDTH = 256                       # bytes of a 2048-bit field element
GROUP_ID = b"modp2048"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64)   # salt = digest size


class HandshakeError(Exception):
    """Any handshake failure. Library code raises it; run.py catches it and closes."""


def new_exponent() -> int:
    return secrets.randbelow(Q - 2) + 2                  # uniform in [2, q-1]

def enc(n: int) -> bytes:
    return n.to_bytes(WIDTH, "big")                      # fixed width, never variable

def dec(b: bytes) -> int:
    """Decode and VALIDATE a peer DH value (raises HandshakeError)."""
    if not isinstance(b, (bytes, bytearray)) or len(b) != WIDTH:
        raise HandshakeError("DH value has wrong length")
    v = int.from_bytes(b, "big")
    if not (1 < v < P - 1) or pow(v, Q, P) != 1:         # range AND subgroup membership
        raise HandshakeError("DH value outside the prime-order subgroup")
    return v

def unhex(s, n=None) -> bytes:
    try:
        b = bytes.fromhex(s)
    except (ValueError, TypeError):
        raise HandshakeError("malformed hex field")
    if n is not None and len(b) != n:
        raise HandshakeError("field has wrong length")
    return b

def sign(priv, data: bytes) -> bytes:
    return priv.sign(data, PSS, hashes.SHA512())

def verify(pub, sig: bytes, data: bytes) -> None:
    try:
        pub.verify(sig, data, PSS, hashes.SHA512())
    except InvalidSignature:
        raise HandshakeError("signature verification failed")

def fingerprint(pub) -> bytes:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()                  # 32 bytes, shown as hex to users

# --- signed transcripts (every field fixed width, label first) ---
def t_server_hello(gs: bytes) -> bytes:
    return b"DHC1|server-hello|" + GROUP_ID + b"|" + gs
def t_client_auth(fp_s, fp_c, gs, gc) -> bytes:
    return b"DHC1|client-auth|" + fp_s + fp_c + gs + gc
def t_server_auth(fp_s, fp_c, gs, gc) -> bytes:
    return b"DHC1|server-auth|" + fp_s + fp_c + gs + gc

def derive_keys(shared: int, fp_s: bytes, fp_c: bytes, gs: bytes, gc: bytes):
    """HKDF-SHA-256 bound to the whole transcript. Returns (k_c2s, k_s2c)."""
    th = hashlib.sha256(fp_s + fp_c + gs + gc).digest()
    okm = HKDF(hashes.SHA256(), 64, salt=th, info=b"DHC1 record keys").derive(enc(shared))
    return okm[:32], okm[32:]

class Record:
    """AES-256-GCM record layer. One key per direction, counter nonce, direction in AAD."""
    def __init__(self, k_send, k_recv, label_send: bytes, label_recv: bytes):
        self._ks, self._kr = AESGCM(k_send), AESGCM(k_recv)
        self._ls, self._lr = label_send, label_recv
        self._ns = self._nr = 0
    @staticmethod
    def _nonce(n): return b"\x00\x00\x00\x00" + n.to_bytes(8, "big")
    def seal(self, pt: bytes) -> str:
        ct = self._ks.encrypt(self._nonce(self._ns), pt, self._ls); self._ns += 1
        return ct.hex()
    def open(self, wire: str) -> bytes:
        ct = bytes.fromhex(wire)
        pt = self._kr.decrypt(self._nonce(self._nr), ct, self._lr)   # InvalidTag on any deviation
        self._nr += 1
        return pt

def make_records(k_c2s, k_s2c, is_server: bool):
    if is_server:
        return Record(k_s2c, k_c2s, b"s2c", b"c2s")
    return Record(k_c2s, k_s2c, b"c2s", b"s2c")

# --- handshake state machines (message dicts in, message dicts out) ---
class Server:
    def __init__(self, priv, pub_s, pub_c_pinned):
        self.priv, self.fp_s, self.pub_c = priv, fingerprint(pub_s), pub_c_pinned
        self.fp_c = fingerprint(pub_c_pinned)
        self.s = new_exponent(); self.gs = enc(pow(G, self.s, P))
    def m1(self):
        return {"t": "hello", "v": 1, "gs": self.gs.hex(),
                "sig": sign(self.priv, t_server_hello(self.gs)).hex()}
    def on_m2(self, m):
        if m.get("t") != "auth": raise HandshakeError("unexpected message type")
        gc = unhex(m.get("gc"), WIDTH); sig = unhex(m.get("sig"))
        gcv = dec(gc)
        verify(self.pub_c, sig, t_client_auth(self.fp_s, self.fp_c, self.gs, gc))
        k = derive_keys(pow(gcv, self.s, P), self.fp_s, self.fp_c, self.gs, gc)
        m3 = {"t": "confirm", "sig": sign(self.priv, t_server_auth(self.fp_s, self.fp_c, self.gs, gc)).hex()}
        return m3, make_records(*k, is_server=True)

class Client:
    def __init__(self, priv, pub_c, pub_s_pinned):
        self.priv, self.fp_c, self.pub_s = priv, fingerprint(pub_c), pub_s_pinned
        self.fp_s = fingerprint(pub_s_pinned)
        self.c = new_exponent(); self.gc = enc(pow(G, self.c, P))
    def on_m1(self, m):
        if m.get("t") != "hello" or m.get("v") != 1: raise HandshakeError("unexpected message type")
        self.gs = unhex(m.get("gs"), WIDTH); sig = unhex(m.get("sig"))
        self.gsv = dec(self.gs)
        verify(self.pub_s, sig, t_server_hello(self.gs))
        return {"t": "auth", "gc": self.gc.hex(),
                "sig": sign(self.priv, t_client_auth(self.fp_s, self.fp_c, self.gs, self.gc)).hex()}
    def on_m3(self, m):
        if m.get("t") != "confirm": raise HandshakeError("unexpected message type")
        verify(self.pub_s, unhex(m.get("sig")), t_server_auth(self.fp_s, self.fp_c, self.gs, self.gc))
        k = derive_keys(pow(self.gsv, self.c, P), self.fp_s, self.fp_c, self.gs, self.gc)
        return make_records(*k, is_server=False)
```

### Protocol tests (`tests/test_dhc1_core.py`, 16 passed)

```python
import pytest, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag
from dhc1_core import *
def kp():
    k = rsa.generate_private_key(65537, 2048); return k, k.public_key()
S, C, M = kp(), kp(), kp()
def mr(n, k=16):
    import random
    d, s = n-1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-2); x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True
def honest():
    srv, cli = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1])
    m2 = cli.on_m1(srv.m1()); m3, rs = srv.on_m2(m2); rc = cli.on_m3(m3); return rs, rc
def test_group(): assert P.bit_length() == 2048 and mr(P) and mr(Q) and pow(G, Q, P) == 1
def test_chat_roundtrip():
    rs, rc = honest(); assert rs.open(rc.seal(b"hi")) == b"hi" and rc.open(rs.seal(b"yo")) == b"yo"
def test_fresh_sessions():
    a = honest(); b = honest(); assert a[0].seal(b"x") != b[0].seal(b"x")
def test_tamper():
    rs, rc = honest(); w = rc.seal(b"hello"); w = w[:-2] + ("00" if w[-2:] != "00" else "01")
    with pytest.raises(InvalidTag): rs.open(w)
def test_replay_and_reorder():
    rs, rc = honest(); w1, w2 = rc.seal(b"1"), rc.seal(b"2")
    with pytest.raises(InvalidTag): rs.open(w2)          # reorder/drop
    assert rs.open(w1) == b"1" and rs.open(w2) == b"2"
    with pytest.raises(InvalidTag): rs.open(w1)          # replay
def test_reflection():
    rs, rc = honest(); w = rc.seal(b"from client")
    with pytest.raises(InvalidTag): rc.open(w)           # reflected back to sender
def test_bad_dh_values():
    for bad in (enc(0), enc(1), enc(P - 1), enc(11), b"\x01" * 255, b"\xff" * 256):
        with pytest.raises(HandshakeError):                # 11 is a non-residue: passes a range check only
            dec(bad)
def test_mallory_substitutes_A_with_own_key_signature():
    srv, cli = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1])
    mal = Server(M[0], M[1], C[1]); forged = mal.m1()    # valid signature, wrong signer
    with pytest.raises(HandshakeError): cli.on_m1(forged)
def test_splice_real_sig_on_mallory_value():
    srv, cli = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1])
    mal = Server(M[0], M[1], C[1]); m1 = srv.m1(); m1["gs"] = mal.gs.hex()
    with pytest.raises(HandshakeError): cli.on_m1(m1)
def test_garbage_sig():
    srv, cli = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1]); m1 = srv.m1(); m1["sig"] = "00"*256
    with pytest.raises(HandshakeError): cli.on_m1(m1)
def test_mallory_substitutes_B():
    srv, cli = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1]); m2 = cli.on_m1(srv.m1())
    m2["gc"] = enc(pow(G, 5, P)).hex()
    with pytest.raises(HandshakeError): srv.on_m2(m2)
def test_server_auth_needs_fresh_m3():
    s1, c1 = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1]); m1 = s1.m1()
    c1.on_m1(m1)                                          # client answers replayed/old M1
    s2 = Server(S[0], S[1], C[1]); fake = {"t": "confirm", "sig": "00"*256}
    with pytest.raises(HandshakeError): c1.on_m3(fake)
def test_m3_from_other_session_rejected():
    s1, c1 = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1]); m2 = c1.on_m1(s1.m1()); m3a, _ = s1.on_m2(m2)
    s2, c2 = Server(S[0], S[1], C[1]), Client(C[0], C[1], S[1]); c2.on_m1(s2.m1())
    with pytest.raises(HandshakeError): c2.on_m3(m3a)
def test_malformed_fields():
    cli = Client(C[0], C[1], S[1])
    for m in ({}, {"t": "hello", "v": 1}, {"t": "hello", "v": 1, "gs": "zz", "sig": "00"},
              {"t": "hello", "v": 1, "gs": "00", "sig": "00"}, {"t": "auth"}):
        with pytest.raises(HandshakeError): cli.on_m1(m)
def test_domain_separation():
    sig = sign(S[0], t_server_hello(b"x"*256))
    with pytest.raises(HandshakeError): verify(S[1], sig, t_server_auth(b"a"*32, b"b"*32, b"x"*128, b"x"*128))
def test_transcript_fixed_width_no_ambiguity():
    a, b = t_client_auth(b"f"*32, b"g"*32, enc(3), enc(4)), t_client_auth(b"f"*32, b"g"*32, enc(4), enc(3))
    assert a != b and len(a) == len(b"DHC1|client-auth|") + 32 + 32 + 256 + 256
```

---

## APPENDIX B: PHASE COMPLETION AUDIT TRAIL

| Phase | Status | Date | Tester | Commit or evidence |
|---|---|---|---|---|
| 0 Python 3 port | ✅ | 2026-09-30 | AI agent | tag `phase-0`, `63b402d` |
| G0 GUI check | 🔲 | | Team | |
| 1 `--secure`, `--no-gui` | ✅ | 2026-09-30 | AI agent | tag `phase-1`, SHA: ___ |
| 1.5 Transport and hygiene | 🔲 | | | |
| 2 Crypto modernization | 🔲 | | | |
| 3 Signed handshake | 🔲 | | | |
| 4 Attack fails | 🔲 | | | |
| 5 AVISPA (install spike Day 1) | 🔲 | | | |
| 6 MFA | 🔲 | | | |
| 7 Docs | 🔲 | | | |
| 8 Report, slides, rehearsal | 🔲 | | | |
| Clean-env test, second machine | 🔲 | | | |
| Submission | 🔲 | | | |
