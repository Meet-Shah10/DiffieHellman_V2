# IS FA2 Project: "Secure Chat: Break It, Then Fix It"

> **Purpose of this file:** single source of truth for the project. Paste it into any AI agent / LLM as context, and share it with all group members.
> **Status markers used below:** ✅ verified from the source, ⚠️ NOT verified / must be tested by the team, 🛠 something we must build.

---

## 0. Instructions for an AI agent reading this file

1. Treat this file as the project spec. Do not change the project scope without asking the user.
2. The project is a **defensive, educational** security demonstration run in a **local lab** (all machines are the team's own). Do not help extend it toward attacking real systems.
3. Sections marked ⚠️ are assumptions. Ask the user to run the suggested checks and paste back the output before building on them.
4. When writing code: Python 3, small readable functions, comments that explain the *security idea* (students must explain this in a viva).
5. Always keep the demo reproducible: pinned dependencies in `requirements.txt`, a README with exact commands.
6. The first thing to do is **Phase 0** (Section 8): get the base repo running and report what Python version it needs.

---

## 1. Context

| Item | Detail |
|---|---|
| Course | Information Security (IS), T.Y. B.Tech CSE (AI & ML), PCCoE Pune |
| Assessment | **FA2** (formative assessment 2) |
| Task | Demonstrate a **security application**. Existing GitHub repos are allowed and can be modified, but the work must map to IS, as our group's assigned topic is "Security Applications". It does not have to sit strictly inside the syllabus, only close to it. |
| Deliverables (expected) | Live demo, GitHub repo (our modified fork), short report, slides, viva readiness. ⚠️ Confirm exact deliverables and marking scheme with the faculty. |
| Group size | ⚠️ Fill in: ___ members (the task split in Section 10 assumes 4) |
| Deadline | ⚠️ Fill in: ___ |

### Syllabus (units relevant to us)

| Unit | Topics |
|---|---|
| I | Intro to information security, NIST Cybersecurity Framework, security policy, threats and vulnerabilities, **man-in-the-middle attack**, DDoS, viruses, honeypots, firewalls |
| II | Conventional ciphers (substitution, transposition, one-time pad, block and stream ciphers); self-learning: steganography |
| III | **DES, AES, RSA, Diffie-Hellman key exchange**; self-learning: public-key cryptography, RSA and DH problem solving |
| IV | **Authentication and digital signatures**: cryptography for authentication, **SHA-512**, key management (**Kerberos**), zero-trust; self-learning: **multi-factor authentication**; case study: **identifying MITM attacks in public key exchange protocols using the AVISPA tool** |

---

## 2. Project summary

We build a small **encrypted chat application** between two users (Alice and Bob) that agrees on its encryption key using **Diffie-Hellman (DH)** and encrypts messages with **AES**. Then we show, live:

1. **It works** in normal conditions, and an eavesdropper sees only encrypted data.
2. **It can be broken:** an active attacker (Mallory) performs a **man-in-the-middle (MITM) attack** and reads everything, because plain DH has no authentication.
3. **It can be fixed:** we add **digital signatures** (RSA + SHA-512) so each side authenticates its DH value, and the same attack now fails.
4. **Bonus layers:** **MFA (TOTP)** before chat login, and a **formal verification** of the protocol in **AVISPA** showing the unauthenticated version is UNSAFE and the authenticated version is SAFE.

**One-line pitch:** *"We demonstrate why key exchange without authentication is insecure, break a real DH chat with a MITM attack, and fix it with signatures, MFA, and formal verification."*

---

## 3. Core concepts (what every member must be able to explain)

### 3.1 Diffie-Hellman key exchange
- Public parameters: a large prime `p` and a generator `g`.
- Alice picks secret `a`, sends `A = g^a mod p`. Bob picks secret `b`, sends `B = g^b mod p`.
- Alice computes `K = B^a mod p`, Bob computes `K = A^b mod p`. Both get `g^(ab) mod p`.
- An eavesdropper sees `p, g, A, B` but must solve the **discrete logarithm problem** to get `K`, which is infeasible at real sizes.
- Then `K` is hashed (for example SHA-256) into an **AES key**.

### 3.2 Why it breaks: MITM
- DH stops a **passive** eavesdropper, but gives **no authentication**. Alice cannot tell if `B` truly came from Bob.
- Mallory intercepts: she sends her own `M1` to Bob (pretending to be Alice) and her own `M2` to Alice (pretending to be Bob).
- Result: Alice↔Mallory share key `K1`, Mallory↔Bob share key `K2`. Mallory decrypts with `K1`, reads, re-encrypts with `K2`, forwards. Neither victim notices.

### 3.3 The fix: authenticated key exchange
- Each side **signs** its DH public value (and ideally both values plus a nonce) with its long-term private key.
- The other side verifies using the sender's **known public key** (pre-shared, or from a certificate).
- Mallory cannot forge the signature, so substituting her own DH value fails verification and the connection aborts.
- This is the same idea as certificates in TLS/HTTPS.

### 3.4 MFA (TOTP)
- Something you know (password) plus something you have (phone with authenticator app).
- TOTP = a 6-digit code from a shared secret and the current time (RFC 6238), valid about 30 seconds.

### 3.5 AVISPA
- A tool suite for **automatic formal verification** of security protocols. You describe the protocol in **HLPSL**, state goals (for example secrecy, authentication), and its back-ends (OFMC, CL-AtSe) report **SAFE** or **UNSAFE** and show the attack trace.

---

## 4. Architecture

### 4.1 Demo topology

```
Scenario A (normal):      Alice ───────────────► Bob (server)

Scenario B (attack):      Alice ───► Mallory ───► Bob
                                   (MITM proxy)

Scenario C (fixed):       Alice ───► Mallory ───► Bob
                          (signature check fails on Alice/Bob side → connection aborted)
```

### 4.2 Protocol (fixed version)

```
Setup (offline):  Alice and Bob each have an RSA key pair; each knows the other's PUBLIC key.

1. Alice → Bob : A = g^a mod p,  Sig_Alice(A)
2. Bob → Alice : B = g^b mod p,  Sig_Bob(B || A)        (binds the reply to Alice's value)
3. Both verify the signature with the other's public key. If it fails → abort.
4. K = g^(ab) mod p  →  AES key = SHA-256(K)
5. Messages encrypted with AES-GCM (authenticated encryption).
```

⚠️ Note: signing only the DH value protects against simple MITM. For viva readiness, know that a fully robust protocol also includes nonces/identities (to stop replay and identity-misbinding) and that real protocols use this same pattern (for example TLS, or STS / SIGMA-style protocols).

---

## 5. Repositories and tools

### 5.1 Primary base repo (the vulnerable chat + MITM)
**`jaybosamiya/DiffieHellman-ManInTheMiddle`**
URL: https://github.com/jaybosamiya/DiffieHellman-ManInTheMiddle

| Item | Status |
|---|---|
| Purpose | Secure chat server exchanging keys with DH, plus a MITM attack that breaks it ("parameter injection through MITM") ✅ |
| License | MIT ✅ (keep the copyright notice; credit the original authors in our report and README) |
| State | **Archived / read-only since Nov 2018** ✅ (we must fork or clone it; we cannot push to it) |
| Files ✅ | `run.py`, `crypto_protocol.py`, `diffie_hellman.py`, `network.py`, `mitm.py`, `gui.py`, `report/`, `.gitignore`, `README.md` |
| Language/version | ⚠️ Repo dates from 2015, so it may target **Python 2** (print statements, `raw_input`, etc). Test first. |
| GUI toolkit | ⚠️ Unknown, read `gui.py` imports |

**Documented usage (from its README) ✅:**

Normal chat:
```bash
# terminal 1 (server)
python run.py <port>
# terminal 2 (client)
python run.py <server_ip> <port>
```

MITM attack:
```bash
# terminal 1: real server on port_1
python run.py <port_1>
# terminal 2: MITM, sits between (README text omits the script name, it is presumably mitm.py ⚠️)
python mitm.py <server_ip> <port_1> <port_2>
# terminal 3: client connects to the MITM, not the server
python run.py <mitm_ip> <port_2>
```

(The README notes that real-world interception could use ARP poisoning and so on, in which case the same IP/port is used. **We do not do this. We use different ports on localhost/our own lab machines.**)

**Read `report/` folder first:** it likely explains the exact attack technique (parameter injection) and is useful for our own report and viva. ⚠️ Verify.

### 5.2 Supporting repos (optional / reference)

| Repo | Use for |
|---|---|
| https://github.com/shreeshb51/diffie_hellman_key_exchange_simulator | Jupyter notebook: interactive DH with small numbers, Miller-Rabin primality, primitive roots, optional MITM simulation. Use in the first 2 minutes of the demo to explain the math visually. |
| https://github.com/systemslibrarian/crypto-lab-diffie-hellman-mitm | Browser-based lesson: DH, discrete-log break on toy primes, and an ECDSA-signed fix. Good **reference design** for our fix. ⚠️ Very new (mid-2026), so review the code before relying on it. |
| https://github.com/flytelyte/dh_protocol | DH with Sophie-Germain primes and a MITM-resistant authenticated version (uses Sage). Reference for secure parameter choice. |
| https://github.com/DevMahdiTR/kerbospringreact-implementation | Optional Unit IV extra: Kerberos AS/TGS implementation in Spring Boot + React. Only if time remains. |

### 5.3 Libraries

| Library | Use |
|---|---|
| `cryptography` | RSA/ECDSA signing, SHA-512, AES-GCM, key derivation |
| `pyotp` | TOTP generation/verification |
| `qrcode` (+ `Pillow`) | QR code for authenticator-app enrollment |
| `pwntools` (optional) | Convenient sockets, if we rewrite the base |
| Wireshark | Show raw encrypted traffic vs MITM-decrypted traffic |
| AVISPA / SPAN | Formal protocol verification (Section 9.6) |

---

## 6. Environment setup

```bash
# 1. Fork the base repo on GitHub (button top-right), then clone YOUR fork
git clone https://github.com/<our-team-account>/DiffieHellman-ManInTheMiddle.git
cd DiffieHellman-ManInTheMiddle

# 2. Create a virtual environment (Python 3.10+ recommended)
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install libraries
pip install cryptography pyotp qrcode pillow

# 4. Save dependencies for teammates
pip freeze > requirements.txt
```

**Branching rule:** `main` is always demo-ready. Each person works on a branch (`feat/signatures`, `feat/mfa`, `feat/avispa`, ...) and opens a pull request.

---

## 7. Base code map (what to read, in this order)

| File | What to find out (⚠️ verify by reading) |
|---|---|
| `run.py` | Entry point: how it decides server vs client from the arguments |
| `network.py` | Socket send/receive, message framing |
| `diffie_hellman.py` | How `p`, `g`, private and public values are generated; key size; **are parameters sent over the wire and trusted by the receiver** (this is what "parameter injection" refers to) |
| `crypto_protocol.py` | Handshake sequence, how the shared secret becomes a symmetric key, which cipher is used |
| `mitm.py` | How it accepts the client, connects to the server, and relays/decrypts messages |
| `gui.py` | GUI framework and how it calls the protocol (we may skip the GUI for the demo) |
| `report/` | The authors' explanation of the attack |

**Questions to answer and write into our report** (after reading):
1. Which Python version does it need?
2. What cipher/mode does it use? Is it secure by modern standards?
3. Exactly what does the MITM change in the handshake?
4. Where in `crypto_protocol.py` should the signature step go?

---

## 8. Step-by-step plan

### Phase 0: Get the base running (Day 1, everyone blocked until this is done)
1. Fork and clone the repo.
2. Try to run the **normal chat** (two terminals, localhost).
3. Try to run the **MITM** scenario (three terminals).
4. If there are Python 2 errors: run `python -m lib2to3` / `2to3 -w .` or fix by hand (`print` → `print()`, `raw_input` → `input`, `xrange` → `range`, bytes vs str).
5. **Decision point:** if the base is not running within about 1 day, switch to the **fallback (Section 12)**. Do not burn a week on legacy code.

### Phase 1: Understand and document the baseline
- Complete the questions in Section 7.
- Take screenshots: normal chat, MITM terminal showing plaintext.
- Record the attack flow as a sequence diagram (Mermaid or draw.io).

### Phase 2: Modernize the crypto (small, safe improvements)
- Use the `cryptography` library for **AES-GCM** (authenticated encryption) instead of any custom/ECB cipher.
- Derive the AES key with **SHA-256 or HKDF** from the DH shared secret.
- Use a **standard large prime** (for example the 2048-bit MODP group from RFC 3526) instead of a weak or short one, unless a toy prime is deliberately used for the small-number explanation.

### Phase 3: Add the signature fix (core contribution) 🛠
Create `auth_dh.py` (see Section 9.1 for code), then change the handshake in `crypto_protocol.py`:
- Add a **command-line flag** `--secure` (off = vulnerable mode, on = signed mode) so the demo can toggle between both with the same code.
- Key generation script: `gen_keys.py` creates `alice_priv.pem`, `alice_pub.pem`, `bob_priv.pem`, `bob_pub.pem`. Each side loads its own private key and the other's public key.
- In secure mode: send `(A, signature)`; on receive, verify, and **abort with a clear message** on failure.

### Phase 4: Show the attack failing 🛠
- Run the same MITM with `--secure`.
- Expected output: client prints `Signature verification FAILED. Possible man-in-the-middle attack. Connection aborted.`
- Add a MITM log line so the audience sees Mallory's attempt fail.

### Phase 5: MFA add-on 🛠 (Section 9.2)
- Flask or CLI login step: password + TOTP code before chat starts.
- Show: correct password with wrong code is rejected.

### Phase 6: AVISPA verification 🛠 (Section 9.6)
- Model the unauthenticated DH and authenticated DH in HLPSL, run OFMC, and screenshot the UNSAFE and SAFE outputs.

### Phase 7: Report, slides, rehearsal (Section 13)

---

## 9. Implementation details

### 9.1 Signature module (`auth_dh.py`)

Uses RSA-PSS with SHA-512 (maps to the "SHA-512" topic in Unit IV).

```python
# auth_dh.py: authentication layer for Diffie-Hellman
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def generate_keypair(bits: int = 2048):
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()

def save_keys(private, public, name: str):
    with open(f"{name}_priv.pem", "wb") as f:
        f.write(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))      # demo only; real systems encrypt this
    with open(f"{name}_pub.pem", "wb") as f:
        f.write(public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

def load_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                   salt_length=padding.PSS.MAX_LENGTH)

def sign(private, data: bytes) -> bytes:
    return private.sign(data, _PSS, hashes.SHA512())

def verify(public, signature: bytes, data: bytes) -> bool:
    try:
        public.verify(signature, data, _PSS, hashes.SHA512())
        return True
    except InvalidSignature:
        return False
```

**Helper for the key and message encryption:**

```python
# session.py: derive AES key from DH secret and encrypt messages
import os, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(shared_secret: int) -> bytes:
    raw = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw).digest()          # 32 bytes → AES-256

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt(key: bytes, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)   # raises if tampered
```

**Handshake logic to add (pseudocode, adapt to the repo's network/protocol code):**

```python
# Client (Alice)
A = pow(g, a, p)
send(A_bytes, sign(alice_priv, A_bytes))

B_bytes, sigB = recv()
if not verify(bob_pub, sigB, B_bytes + A_bytes):     # Bob signs (B || A)
    abort("Signature verification FAILED: possible MITM")
K = pow(int.from_bytes(B_bytes, "big"), a, p)
key = derive_key(K)

# Server (Bob)
A_bytes, sigA = recv()
if not verify(alice_pub, sigA, A_bytes):
    abort("Signature verification FAILED: possible MITM")
B = pow(g, b, p)
send(B_bytes, sign(bob_priv, B_bytes + A_bytes))
K = pow(int.from_bytes(A_bytes, "big"), b, p)
key = derive_key(K)
```

⚠️ Mallory can still *relay* genuine messages unchanged (that would just be a passive proxy and gives her nothing). She cannot substitute her own DH value. Be ready to explain this in the viva.

### 9.2 MFA module (TOTP)

```python
# mfa.py
import pyotp, qrcode, hashlib, os, hmac

# --- enrollment (once per user) ---
secret = pyotp.random_base32()
uri = pyotp.TOTP(secret).provisioning_uri(name="alice@is-demo", issuer_name="IS-FA2-Chat")
qrcode.make(uri).save("alice_mfa_qr.png")      # scan with Google Authenticator / Authy
# store `secret` server-side (demo: a JSON file)

# --- login ---
def hash_pw(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 200_000)

def login(user_record, password, otp_code) -> bool:
    pw_ok = hmac.compare_digest(hash_pw(password, user_record["salt"]), user_record["hash"])
    otp_ok = pyotp.TOTP(user_record["totp_secret"]).verify(otp_code, valid_window=1)
    return pw_ok and otp_ok
```

Demo: show (1) right password + right code → in; (2) right password + wrong code → rejected (this is what MFA protects against: a stolen password alone is not enough).
Optional: add backup codes and a max-attempts lockout.

### 9.3 Key generation script (`gen_keys.py`)

```python
from auth_dh import generate_keypair, save_keys
for name in ("alice", "bob"):
    priv, pub = generate_keypair()
    save_keys(priv, pub, name)
print("Keys generated. Distribute only *_pub.pem to the other party.")
```

### 9.4 Mode switch

Add `--secure` to `run.py` (argparse). Same codebase for both demos:
```bash
python run.py 9000                # vulnerable server
python run.py 9000 --secure       # signed-DH server
```

### 9.5 Traffic visualization (optional but impactful)
- Wireshark on the loopback interface (filter: `tcp.port == 9000`): show that the payload is unreadable.
- In the MITM terminal, print `[MITM] Alice says: <plaintext>`.
- In secure mode, print `[MITM] Attack failed: endpoints rejected forged DH value`.

### 9.6 AVISPA part

Steps:
1. Install AVISPA (or use **SPAN**, the animator GUI). ⚠️ Setup can be fiddly; try a Linux VM or the AVISPA web interface if available; test early.
2. Write two HLPSL files:
   - `dh_unauth.hlpsl`: roles Alice, Bob, session, environment; goal `secrecy_of` the key; intruder = Dolev-Yao.
   - `dh_auth.hlpsl`: same, plus signatures (`{...}_inv(Ka)`) and goal `authentication_on`.
3. Run back-end **OFMC** (and CL-AtSe). Expected ⚠️ (verify): unauthenticated → **UNSAFE** with an attack trace; authenticated → **SAFE**.
4. Screenshot outputs for the slides and report.

Skeleton idea only (**untested**; adapt from AVISPA's example protocols in its `testsuite/`):
```
role alice(A,B: agent, Ka,Kb: public_key, G: text, SND,RCV: channel(dy)) ...
role bob(...) ...
role session(...) ...
role environment() ...
goal
  secrecy_of sec_key
  authentication_on alice_bob_dh
end goal
```
Tell the AI agent: *"Write HLPSL for Diffie-Hellman in both unauthenticated and signature-authenticated variants, following AVISPA's documentation conventions, and explain each role"*, then **run it**. Do not trust unrun HLPSL.

---

## 10. Demo script (aim: 10 to 12 minutes)

| Time | Step | What to show | Say |
|---|---|---|---|
| 0:00 | Intro | Title slide + topology diagram | "Key exchange without authentication is insecure. We will break it and fix it." |
| 1:00 | DH basics | Simulator notebook with small numbers | Explain `g^a`, `g^b`, same secret |
| 3:00 | Normal chat | 2 terminals + Wireshark | "An eavesdropper sees only ciphertext." |
| 5:00 | **The attack** | 3 terminals: server, MITM, client | Client connects via Mallory; MITM terminal prints plaintext |
| 7:00 | **The fix** | Re-run with `--secure` | "Signatures stop Mallory substituting her DH value." Client shows the abort message |
| 9:00 | MFA | Login with authenticator app | Stolen password alone is not enough |
| 10:00 | AVISPA | Screenshot: UNSAFE vs SAFE | "Formal verification agrees with our demo." |
| 11:00 | Wrap-up | Syllabus map slide | Units I, III, IV covered |

**Rehearse three times.** Keep a pre-recorded screen capture as backup in case the live demo fails.

---

## 11. Syllabus mapping (put this on a slide)

| Project part | Syllabus topic |
|---|---|
| MITM attack demo | Unit I (MITM), Unit IV case study (MITM in public-key exchange) |
| Diffie-Hellman | Unit III |
| AES-GCM message encryption | Unit III (AES) |
| RSA signatures | Units III and IV (RSA, digital signatures) |
| SHA-512 hashing | Unit IV (Secure Hash Functions, SHA-512) |
| Key management (public key distribution) | Unit IV (key management) |
| MFA (TOTP) | Unit IV self-learning (MFA) |
| AVISPA verification | Unit IV case study (AVISPA tool) |
| Security policy / threat discussion | Unit I (threats, vulnerabilities, NIST framework) |

---

## 12. Risks and fallbacks

| Risk | Fallback |
|---|---|
| Base repo will not run (Python 2 / dependency problems) | Rewrite a minimal version ourselves, about 150 lines: socket server/client, DH with `pow()`, AES-GCM, a MITM proxy that does two separate DH exchanges. Reuse the repo only as design reference and credit it. |
| GUI does not work | Skip the GUI and use the CLI only (terminals are fine for this demo) |
| AVISPA will not install | Use the web interface, or show the attack trace manually in a sequence diagram; mention AVISPA as verified externally only if we really ran it |
| Live demo crashes | Pre-recorded video + screenshots |
| Time shortage | Must-have: Phases 0 to 4. MFA and AVISPA are the bonus layers (AVISPA is named in the syllabus, so prioritize it over Kerberos) |

---

## 13. Report and viva

### Report outline (about 6 to 10 pages ⚠️ check faculty requirement)
1. Problem statement and objective
2. Background: DH, MITM, digital signatures, SHA-512, MFA
3. Base project credit (jaybosamiya repo, MIT license) and what **we** changed
4. System design and architecture diagrams
5. Implementation (modules, key files, how to run)
6. Results: screenshots (normal, attack, fixed, MFA, AVISPA)
7. Security analysis: what the fix does and does not protect against (replay, key compromise, no forward secrecy in static-key signing variants, and so on)
8. Syllabus mapping
9. Limitations and future work (certificates/PKI, TLS, forward secrecy, Kerberos, hardware tokens)
10. References

### Likely viva questions (everyone should be able to answer)
1. Why is plain DH vulnerable to MITM, given that the eavesdropper cannot compute the key?
2. What exactly does Mallory send to Alice and to Bob?
3. How do signatures stop this? What does Alice need to already know (Bob's public key), and how would that work on the internet (certificates/CA)?
4. Why SHA-512 and RSA-PSS? What does the hash do in a signature?
5. Why AES-GCM instead of AES-ECB?
6. What is the discrete logarithm problem?
7. What does MFA protect against that a password cannot?
8. What does AVISPA output, and what does UNSAFE mean?
9. What are the limits of our fix? (Replay, compromised private key, key distribution problem.)
10. How does this relate to HTTPS/TLS?

---

## 14. Team roles (edit names; adjust to group size)

| Role | Member | Responsibilities |
|---|---|---|
| Lead / integrator | ___ | Repo owner, Phase 0, merges PRs, keeps `main` demo-ready |
| Crypto engineer | ___ | Phases 2 to 4: `auth_dh.py`, `session.py`, handshake changes, `--secure` flag |
| Auth + tools | ___ | Phase 5 (MFA) + Wireshark captures |
| Verification + docs | ___ | Phase 6 (AVISPA), report, slides, syllabus mapping |

**Everyone:** read Section 3 and be able to explain the full attack and fix, because the viva questions can go to anyone.

---

## 15. Suggested timeline (compress or stretch to the real deadline)

| Day(s) | Goal |
|---|---|
| 1 | Phase 0: base repo runs (or fallback decided) |
| 2 | Phase 1: read code, document baseline, screenshots |
| 3 to 4 | Phase 2 + 3: modern crypto, signature fix |
| 5 | Phase 4: attack fails in secure mode |
| 6 to 7 | Phase 5 + 6: MFA, AVISPA |
| 8 | Report + slides draft |
| 9 | Full rehearsal x3, record backup video |
| 10 | Buffer / submission |

---

## 16. Repository hygiene checklist

- [ ] Fork created; README explains vulnerable vs `--secure` mode with exact commands
- [ ] Original authors credited and MIT license file kept
- [ ] `requirements.txt` present; tested on a clean virtual environment
- [ ] `*_priv.pem` files are **git-ignored** (never commit private keys, even demo ones, as it is a bad habit and looks bad in a security course)
- [ ] `docs/` folder with diagrams, screenshots, AVISPA files
- [ ] Demo script (Section 10) included as `DEMO.md`

---

## 17. Ethics and scope

- This project is for **learning and demonstration only**. All attacks run between processes on the team's own machines (localhost or a private lab network).
- Do **not** run ARP poisoning or any interception on college or public networks, or on anyone else's traffic.
- Keep attack code minimal and tied to this chat demo. Do not extend it into a general-purpose attack tool.

---

## 18. Ready-to-paste prompt for an AI coding agent

```
You are helping a group of B.Tech students on an Information Security course project (context file attached).
Project: fork jaybosamiya/DiffieHellman-ManInTheMiddle (MIT license, archived, 2015, possibly Python 2),
get it running under Python 3, then add:
  (1) a --secure flag that authenticates Diffie-Hellman values with RSA-PSS/SHA-512 signatures,
  (2) AES-GCM encryption with a key derived from the DH secret,
  (3) a TOTP-based MFA login step,
so we can demo: normal chat -> MITM attack succeeds -> same attack fails in secure mode.
Rules: local lab only; readable code with comments explaining the security idea; pinned requirements.
First task: read run.py, network.py, diffie_hellman.py, crypto_protocol.py, mitm.py and tell me
(a) the Python version needed, (b) cipher/mode used, (c) where the handshake happens,
(d) the minimal changes needed to run under Python 3. Do not write new features until I confirm.
```

---

## 19. Open items (fill in and keep updated)

- [ ] Group size and member names
- [ ] Exact FA2 deadline and deliverables (report length, PPT, viva format)
- [ ] Faculty approval of the topic ("Secure chat + MITM + signatures + MFA + AVISPA")
- [ ] Python version needed by base repo: ___
- [ ] AVISPA installation method decided: ___
- [ ] Backup demo video recorded: ___
