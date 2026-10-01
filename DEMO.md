# IS FA2 — Jury Demo Guide
# "Secure Chat: Break It, Then Fix It"

> **Time budget:** 10 minutes  
> **Laptop:** One machine, 4 PowerShell/terminal windows open side by side  
> **Pre-condition:** `venv\Scripts\activate` run in ALL 4 windows  
> **Ports used:** 9000 (server), 9001 (MITM listens for client)

---

## Before the Jury Arrives (5-minute setup)

Open **4 terminal windows**, all in the project folder:

```powershell
cd c:\Users\ASUS\Desktop\Harsh\PROJECTS\IS_FA2\DiffieHellman_V2
venv\Scripts\activate
```

Run this in ONE window to prove everything is green:

```powershell
python -m pytest tests\ -v --tb=short
# Expected: 84 passed, 1 skipped  in ~10s
```

Then run this to show the key fingerprints you will reference:

```powershell
python gen_keys.py
# Keys already exist — it will print fingerprints and refuse to overwrite
```

---

## DEMO SCENARIO 1 — Normal Encrypted Chat (2 min)

**What you show:** Alice and Bob can chat. Wireshark (or --no-gui output) proves messages are encrypted end-to-end.

### Step-by-step

**Window 1 — Bob (Server):**
```powershell
python run.py 9000 --no-gui
```
Expected output immediately:
```
[*] DH Chat | Role: Server | Mode: VULNERABLE (unsigned DH)
[!] WARNING: DH values are unauthenticated — MITM attack is possible.
```

**Window 2 — Alice (Client):**
```powershell
python run.py 127.0.0.1 9000 --no-gui
```
Expected output:
```
[*] DH Chat | Role: Client | Mode: VULNERABLE (unsigned DH)
[!] WARNING: DH values are unauthenticated — MITM attack is possible.
```

**Type in Window 2 (Alice's stdin):**
```
Attack at dawn
Bank PIN is 1234
```

**What Bob's window (Window 1) shows:**
```
[Other] Attack at dawn
[Other] Bank PIN is 1234
```

**Say to jury:**
> "Alice and Bob agree on a shared AES-256-GCM key via Diffie-Hellman — without ever sending the key itself over the wire. Everything is encrypted. But watch what happens when Mallory sits in the middle."

Press `Ctrl+C` in both windows.

---

## DEMO SCENARIO 2 — MITM Attack (Vulnerable Mode) (3 min)

**What you show:** Mallory intercepts between Alice and Bob. She reads every message in plaintext without either side knowing.

### Step-by-step (EXACT ORDER matters)

**Window 1 — Bob (Server) — start first:**
```powershell
python run.py 9000 --no-gui
```

**Window 3 — Mallory (MITM) — start second:**
```powershell
python mitm.py 127.0.0.1 9000 9001 --no-gui
```
Expected:
```
[*] MITM | Mode: VULNERABLE — parameter injection active
[!] All messages will be decrypted and logged in plaintext.
[*] listening
```

**Window 2 — Alice (Client) — connects to Mallory on port 9001:**
```powershell
python run.py 127.0.0.1 9001 --no-gui
```

**Type in Window 2 (Alice):**
```
Attack at dawn
Bank PIN is 1234
Top secret data
```

**What Mallory's window (Window 3) shows:**
```
[MITM][client] INTERCEPTED: Attack at dawn
[MITM][client] INTERCEPTED: Bank PIN is 1234
[MITM][client] INTERCEPTED: Top secret data
```

**What Bob's window (Window 1) shows:**
```
[Other] Attack at dawn
[Other] Bank PIN is 1234
[Other] Top secret data
```

**Say to jury:**
> "Bob receives all messages normally — he has no idea Mallory is in the middle. Alice has no idea either. This is the classic Man-in-the-Middle attack on unauthenticated Diffie-Hellman. Mallory intercepts the key exchange at the start, runs TWO separate DH sessions — one with Bob, one with Alice — and decrypts everything."

**Point at Mallory's window:**
> "This is the exact vulnerability: DH proves secrecy from eavesdroppers but not authenticity. Without signatures, anyone can substitute their own public value."

Press `Ctrl+C` in all three windows.

---

## DEMO SCENARIO 3 — Attack Fails with `--secure` (3 min)

**What you show:** The same MITM attack fails completely when `--secure` is used. Both Alice and Bob abort with a `HANDSHAKE FAILED` message. Mallory cannot establish sessions with either.

### Step-by-step

**Window 1 — Bob (Server) with `--secure`:**
```powershell
python run.py 9000 --secure --no-gui
```
Expected:
```
[*] DH Chat | Role: Server | Mode: SECURE (RSA-PSS/SHA-512 signed DH — DHC1)
[*] Pinned peer key  SHA256: b31dbea5...    ← Alice's fingerprint
```

**Window 3 — Mallory (MITM) with `--secure` — substitute attack:**
```powershell
python mitm.py 127.0.0.1 9000 9001 --secure --no-gui
```
Expected:
```
[*] MITM | Mode: SECURE wire-format | Attack: substitute
[*] Running Phase 4 attack — see --attack for options.
[*] listening
```

**Window 2 — Alice (Client) with `--secure`:**
```powershell
python run.py 127.0.0.1 9001 --secure --no-gui
```

**What Alice's window (Window 2) shows — connection ABORTS:**
```
[*] DH Chat | Role: Client | Mode: SECURE (RSA-PSS/SHA-512 signed DH — DHC1)
[*] Pinned peer key  SHA256: 52a62a4d...

[!!!] HANDSHAKE FAILED: signature verification failed
[!!!] Aborting connection — possible man-in-the-middle attack.
```

**What Mallory's window (Window 3) shows:**
```
[MITM] Received M1 from server: t=hello
[MITM] SUBSTITUTE: building Mallory's own DH exchange toward each side.
[MITM] Signing forged M1 with Mallory's own RSA key.
[MITM] Sent forged M1 to client. Client should abort (Signature verification FAILED).
[MITM] Got from client: nothing (client aborted)
[MITM] Attack complete. Both endpoints should have printed 'HANDSHAKE FAILED'.
```

**Say to jury:**
> "Alice verifies the RSA-PSS/SHA-512 signature on the server's DH value. The signature is pinned to Bob's public key fingerprint — which Alice loaded from a file she got from Bob out-of-band. Mallory has her own RSA key, not Bob's, so her forged signature fails verification immediately. Alice aborts before any key material is established. Mallory is completely blocked."

> "This is our DHC1 protocol: Diffie-Hellman authenticated with RSA-PSS/SHA-512 signatures. The signature covers a domain-separation label PLUS the DH value, which prevents cross-role and replay attacks."

Press `Ctrl+C` in all windows.

---

## DEMO SCENARIO 4 — Automated Test Suite (1 min)

**What you show:** All 84 unit tests pass in under 11 seconds.

```powershell
python -m pytest tests\ -v
```

**Point out key test classes to jury:**

| Test Class / Test | What it proves |
|---|---|
| `test_mallory_substitutes_Gs_with_own_key_signature` | Forged sig with wrong key → rejected |
| `test_splice_real_sig_on_mallory_value` | Real sig on wrong DH value → rejected |
| `test_garbage_signature` | Garbage bytes as sig → rejected |
| `test_domain_separation` | "server-hello" sig won't pass "client-hello" check |
| `test_replay_and_reorder` | Old messages cannot be replayed |
| `test_tamper` | Flipping one ciphertext byte → `InvalidTag` |
| `TestHeadlessRegression::test_mitm_still_works_vulnerable_mode` | MITM works in vulnerable mode (the problem is real) |

---

## What to Say for Each Viva Question

### Q: "What is the Man-in-the-Middle attack you demonstrated?"

> "In unauthenticated DH, Alice and Bob exchange public values g^a and g^b over an untrusted network. Mallory intercepts both. She sends her own g^m1 to Bob (so Bob computes g^(a·m1) — a key with Mallory). She sends her own g^m2 to Alice (so Alice computes g^(b·m2) — another key with Mallory). Now Mallory has two separate sessions: she decrypts from Alice, reads the plaintext, re-encrypts for Bob. Neither side detects this because DH alone doesn't prove who sent the public value."

---

### Q: "How does RSA-PSS/SHA-512 fix it?"

> "Before the DH exchange, each party generates an RSA-2048 key pair. Bob signs his DH public value g^b using RSA-PSS with SHA-512. Alice verifies the signature against Bob's public key — a key she received out-of-band (fingerprint pinned). Mallory cannot forge Bob's signature without Bob's private key. So if Alice receives a value with a signature that doesn't verify against the pinned key, she immediately aborts. Mallory is blocked at the handshake before any key material is agreed."

---

### Q: "What is domain separation and why does your signature cover labels?"

> "Without labels, a valid server signature sig(g^b) could be replayed as if it were a client signature — a cross-role attack. We prepend 'server-hello' to what the server signs and 'client-hello' to what the client signs. A message signed under 'server-hello' will never pass verification under 'client-hello' because the signed data is different. This is domain separation."

---

### Q: "Why AES-256-GCM over AES-CBC?"

> "AES-CBC provides confidentiality only. An attacker can flip bits in the ciphertext to produce predictable changes in the plaintext without detection — a bit-flip attack. AES-GCM is authenticated encryption: it produces a 16-byte authentication tag over the ciphertext. If even one bit changes, decryption raises InvalidTag. Our test `test_tamper_detection_ciphertext` demonstrates this. We also use a fresh 12-byte random nonce per message to prevent repeated-prefix leakage."

---

### Q: "What is HKDF and why use it?"

> "The original code derived the AES key with SHA-256(str(shared_secret)) — converting the integer to a decimal string and hashing it. This is non-standard and wastes entropy. HKDF (RFC 5869) is the standard key derivation function: it takes the DH shared secret as input keying material and produces a cryptographically uniform 32-byte key. It also accepts an 'info' field for domain separation between different uses of the same secret."

---

### Q: "Why is your DH group stronger than the original?"

> "The original code used RSA.generate(2048).p — a roughly 1024-bit factor of an RSA key — as the DH prime, and a random integer as the generator. A random generator may only generate a small subgroup, making discrete log much easier. We replaced this with RFC 3526 Group 14: a pre-vetted 2048-bit safe prime where g=2 generates the full prime-order subgroup of size (p-1)/2. Any received p/g that doesn't exactly match this constant is rejected — closing the parameter injection attack entirely."

---

## Quick Reference Card (print this)

```
PORT LAYOUT:
  9000 = Bob (real server)
  9001 = Mallory (MITM listens; Alice connects here)

SCENARIO 1 — Normal chat:
  Window 1:  python run.py 9000 --no-gui
  Window 2:  python run.py 127.0.0.1 9000 --no-gui
  Type in Window 2, see output in Window 1.

SCENARIO 2 — MITM attack (vulnerable):
  Window 1:  python run.py 9000 --no-gui
  Window 3:  python mitm.py 127.0.0.1 9000 9001 --no-gui
  Window 2:  python run.py 127.0.0.1 9001 --no-gui
  Type in Window 2 → Window 3 shows INTERCEPTED.

SCENARIO 3 — Attack fails (secure):
  Window 1:  python run.py 9000 --secure --no-gui
  Window 3:  python mitm.py 127.0.0.1 9000 9001 --secure --no-gui
  Window 2:  python run.py 127.0.0.1 9001 --secure --no-gui
  Window 2 prints: [!!!] HANDSHAKE FAILED

SCENARIO 4 — Tests:
  python -m pytest tests\ -v   →  84 passed in ~10s

IF SOMETHING GOES WRONG:
  Ctrl+C all windows, wait 3 seconds, restart in order: Server → MITM → Client
  If port in use: change 9000→9002, 9001→9003
```
