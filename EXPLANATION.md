# IS FA2 Project – Plain Language Explanation
## "Diffie-Hellman Secure Chat: Break It, Then Fix It"

---

> **Who this is for:** The project team — to understand the idea thoroughly
> enough to explain it confidently in front of a jury, without getting lost
> in maths or code.

---

## Part 1 – The Big Picture (What are we actually doing?)

Imagine you and your friend want to whisper secrets to each other across a
room full of strangers. The challenge: how do you agree on a secret language
without the strangers overhearing you decide it?

That is exactly the problem cryptography solves for computers on the internet.

Our project builds a **private chat application** that:

1. **Works correctly** — Alice and Bob can chat, and nobody else can read the messages.
2. **Gets attacked** — A third person called Mallory sits in the middle and reads everything, even though Alice and Bob think they are safe. This is called a **Man-in-the-Middle (MITM) attack**.
3. **Gets fixed** — We upgrade the chat with a security mechanism that makes the MITM attack impossible.

The whole demo runs on one laptop. You play all three roles — Alice, Bob, and Mallory — using three terminal windows.

---

## Part 2 – The Key Ideas (Explained Like You're Explaining to a Friend)

### 2.1 Diffie-Hellman Key Exchange

**The problem it solves:** Alice and Bob want a shared secret, but the only
way they can talk is through a network where anyone can listen.

**The magic trick:** They each pick a private number (they never share it),
mix it with a public number, and exchange the mixed result. Due to a
mathematical property, they both end up with the **same final answer** — but
anyone who only saw the mixed numbers cannot figure out the private numbers
or the final answer.

**Real life analogy (paint mixing):**
- There is a public colour: Yellow (everyone knows this).
- Alice picks a secret colour: Red. She mixes them → Orange. She sends Orange.
- Bob picks a secret colour: Blue. He mixes them → Green. He sends Green.
- Alice takes Green and adds her Red → a final mix.
- Bob takes Orange and adds his Blue → the same final mix.
- A spy only ever saw Yellow, Orange, and Green. They cannot reverse-engineer the secret Red or Blue.

**In the code:** `diffie_hellman.py` handles this. The "public colour" is a
large prime number (p) and a generator (g). The "mixed result" is a number
like `g^(secret) mod p`.

---

### 2.2 AES-256-GCM Encryption

Once Alice and Bob have their shared secret key, they use it to **lock their
messages**.

**AES-256-GCM** is the lock. It is:
- **AES-256** — an incredibly strong cipher. 256 bits means there are more
  possible keys than atoms in the observable universe.
- **GCM** (Galois/Counter Mode) — adds a "seal" to every message. If
  anyone tampers with the locked message even slightly (flipping one bit),
  the seal breaks and the message is thrown away. This prevents
  **tampering attacks**.

**In the code:** `crypto_protocol.py` handles this. Every message gets a
fresh random 12-byte "nonce" (like a unique ID) so even identical messages
look different when encrypted.

---

### 2.3 The Problem — Why Diffie-Hellman Alone is Not Enough

Here is the flaw. When Alice and Bob exchange those "mixed colours" over the
internet, **who checks that the mixed colour actually came from the right person?**

Nobody. That is the vulnerability.

**The MITM attack:**
- Alice wants to talk to Bob.
- Mallory sits between them on the network.
- Mallory intercepts Alice's mixed colour and sends her OWN mixed colour to Bob.
- Mallory intercepts Bob's mixed colour and sends her OWN mixed colour to Alice.
- Result:
  - Alice thinks she shares a secret with Bob. She actually shares one with Mallory.
  - Bob thinks he shares a secret with Alice. He actually shares one with Mallory.
  - Every message Alice sends, Mallory decrypts, reads, and re-encrypts for Bob.
  - Both sides see a perfectly normal chat. Neither knows Mallory is in the middle.

**This is not theoretical — this is what our demo SHOWS.**

---

### 2.4 The Fix — RSA-PSS Signatures ("The Stamp of Authenticity")

To stop the MITM attack, we add **digital signatures**.

**What is a digital signature?**
Think of a wax seal on a royal letter in medieval times. Only the king had the unique ring that made that seal. Anyone could verify the seal was real by looking at it — but nobody else could fake it.

**RSA is our version of that ring.**

- Each person generates a **key pair**: a private key (kept secret, like the ring) and a public key (shared with everyone, like the design of the seal).
- When Bob sends his DH value, he also **signs it with his private RSA key**.
- Alice checks the signature against Bob's **known public key**.
- If the signature matches → she trusts the DH value came from Bob.
- If the signature does NOT match → she immediately stops and prints "HANDSHAKE FAILED".

**Mallory cannot forge Bob's signature because she does not have Bob's private key.**

**In the code:** `auth_dh.py` and `dhc1_core.py` handle this. We use
**RSA-PSS with SHA-512** — the most secure variant of RSA signing.

---

### 2.5 Domain Separation Labels (Closing a Subtle Loophole)

Even with signatures, there is a subtle trick an attacker could try:
take Bob's valid signature (meant for the server's DH value) and replay
it as if it were Alice's signature (meant for the client's DH value).

We close this by making each side sign a **different thing**:
- The server (Bob) signs: the text `"server-hello"` + his DH value.
- The client (Alice) signs: the text `"client-hello"` + her DH value + Bob's DH value.

A server signature can never be mistaken for a client signature because
they cover different data. This is called **domain separation**.

---

### 2.6 RFC 3526 Group (Why We Use a Specific Prime)

The original code picked DH parameters somewhat randomly, which is weak.
We replaced it with **RFC 3526 Group 14** — a standardised, vetted
2048-bit prime used in industry (TLS, SSH, etc.).

Both sides must use **exactly** this prime. If anyone tries to send
different DH parameters, the connection is rejected immediately.

---

### 2.7 TOTP (Bonus: Second-Factor Login)

After the secure handshake is complete, we can also demonstrate **TOTP
(Time-based One-Time Password)** — the kind of 6-digit code you see on
Google Authenticator. This adds a second layer of login ("something you
have") on top of the encrypted channel.

---

### 2.8 AVISPA Formal Verification

**AVISPA** is a tool that takes the protocol written in a special language
and mathematically proves whether it is safe or not.

We have two AVISPA models in the `avispa/` folder:
- The **unauthenticated DH** model → AVISPA says: **UNSAFE** (confirms the attack is real).
- The **authenticated DH (our fix)** model → AVISPA says: **SAFE** (confirms our fix works).

This is the most rigorous proof possible — not just testing, but mathematical verification.

---

## Part 3 – The Full Story as One Flow (Read This Before the Demo)

Here is the entire story, beginning to end, in order:

```
STEP 1: Bob starts the server. He listens for connections.

STEP 2: Alice connects to Bob. They do a Diffie-Hellman key exchange
        — exchanging "mixed colours" over the network.

STEP 3: Both sides now have the same shared AES key. They use it to
        encrypt and decrypt chat messages with AES-256-GCM.

--- Normal chat works. This is SCENARIO 1. ---

STEP 4: Mallory starts before Alice connects. She connects to Bob
        herself (impersonating Alice), and listens for Alice.

STEP 5: Alice connects, thinking she's talking to Bob. She's actually
        talking to Mallory.

STEP 6: Alice sends "Attack at dawn". Mallory decrypts it, prints it,
        and re-encrypts it for Bob. Bob receives it normally.

--- Mallory reads everything. This is SCENARIO 2 (the attack). ---

STEP 7: We restart, but this time everyone uses --secure mode.

STEP 8: Bob starts. He prepares to SIGN his DH value with his RSA
        private key.

STEP 9: Mallory starts. She tries the same attack.

STEP 10: Mallory sends a DH value to Alice — but she has to sign it.
         She signs it with HER OWN private key (she can't use Bob's).

STEP 11: Alice checks the signature against BOB'S public key (which
         she loaded from a file beforehand). The signature was made
         with Mallory's key, so it FAILS.

STEP 12: Alice prints "HANDSHAKE FAILED" and closes the connection.
         No key is ever derived. No messages are ever sent.

--- Attack blocked. This is SCENARIO 3 (the fix). ---
```

---

## Part 4 – Demo Guide (Exact Commands, Exactly What to Say)

### Setup (Do This Before Jury Arrives)

Open **4 PowerShell windows** in the project folder:

```powershell
cd C:\Users\ASUS\Desktop\Harsh\PROJECTS\IS_FA2\DiffieHellman_V2
.\venv\Scripts\activate
```

Run the tests to confirm everything is working:

```powershell
python -m pytest tests\ -v
```
You should see: **84 passed, 1 skipped** in about 10 seconds.

Generate/confirm keys are present (do this once):

```powershell
python gen_keys.py
```
It will print the SHA-256 fingerprints of Alice, Bob, and Mallory's public keys.
Keep these fingerprints visible — you will reference them in Scenario 3.

---

### SCENARIO 1 — Normal Encrypted Chat

**What this proves:** Alice and Bob can communicate securely.
**What the jury learns:** DH creates a shared key; AES-GCM encrypts with it.

**Window 1 — Bob (Server):**
```powershell
python run.py 9000 --no-gui
```
You will see:
```
[*] DH Chat | Role: Server | Mode: VULNERABLE (unsigned DH)
[!] WARNING: DH values are unauthenticated — MITM attack is possible.
```

**Window 2 — Alice (Client):**
```powershell
python run.py 127.0.0.1 9000 --no-gui
```
You will see the same banner.

**Now type in Window 2 (Alice's terminal):**
```
Hello Bob!
This is encrypted!
```

**Bob's window (Window 1) shows:**
```
[Other] Hello Bob!
[Other] This is encrypted!
```

**Say to jury:**
> "Alice and Bob did a Diffie-Hellman key exchange automatically when they connected. Neither of them sent the key — they derived it independently from each other's public values. Now all messages are AES-256-GCM encrypted. Without the key, the ciphertext is meaningless. But — there is a flaw. Nothing proved that the public values actually came from Alice and Bob. Watch what Mallory can do."

**Press Ctrl+C in BOTH windows.**

---

### SCENARIO 2 — The MITM Attack (Vulnerable Mode)

**What this proves:** Unauthenticated DH is completely broken against an active attacker.
**What the jury learns:** Confidentiality ≠ authenticity.

**Start in this order (ORDER MATTERS):**

**Window 1 — Bob (Server) first:**
```powershell
python run.py 9000 --no-gui
```

**Window 3 — Mallory (MITM proxy) second:**
```powershell
python mitm.py 127.0.0.1 9000 9001 --no-gui
```
You will see:
```
[*] MITM | Mode: VULNERABLE — parameter injection active
[!] All messages will be decrypted and logged in plaintext.
[*] listening
```

**Window 2 — Alice (Client) LAST — connects to port 9001 (Mallory), NOT 9000:**
```powershell
python run.py 127.0.0.1 9001 --no-gui
```

**Type in Window 2 (Alice):**
```
Attack at dawn
Bank PIN is 1234
Top secret data
```

**Mallory's window (Window 3) shows:**
```
[MITM][client] INTERCEPTED: Attack at dawn
[MITM][client] INTERCEPTED: Bank PIN is 1234
[MITM][client] INTERCEPTED: Top secret data
```

**Bob's window (Window 1) ALSO shows — he received them normally:**
```
[Other] Attack at dawn
[Other] Bank PIN is 1234
[Other] Top secret data
```

**Say to jury:**
> "Look at Window 3 — Mallory is reading every single message in clear text. Now look at Window 1 — Bob received all messages normally. He has no idea Mallory was here. Alice has no idea either. The chat appeared to work perfectly. This is the MITM attack on unauthenticated Diffie-Hellman. Mallory ran TWO separate DH sessions — one with Bob, one with Alice — and bridged them. She has one key for Bob and another for Alice."

> "The root cause: DH proves that two parties AGREED on a key. It does NOT prove WHO those two parties are. You need authentication for that."

**Press Ctrl+C in ALL THREE windows.**

---

### SCENARIO 3 — The Fix (Secure Mode Blocks Mallory)

**What this proves:** RSA-PSS signatures make the MITM attack impossible.
**What the jury learns:** Authentication + key exchange = secure protocol.

**Start in this order:**

**Window 1 — Bob (Server) with --secure:**
```powershell
python run.py 9000 --secure --no-gui
```
You will see:
```
[*] DH Chat | Role: Server | Mode: SECURE (RSA-PSS/SHA-512 signed DH — DHC1)
[*] Pinned peer key  SHA256: b31dbea5d6087296e2c1d6459f23a26b6473e934...
```
**Point to the jury:** "That fingerprint is Alice's public key, pre-loaded into Bob's program. Bob will only complete the handshake with someone who signs messages using the matching private key."

**Window 3 — Mallory (MITM) with --secure:**
```powershell
python mitm.py 127.0.0.1 9000 9001 --secure --no-gui
```
You will see:
```
[*] MITM | Mode: SECURE wire-format | Attack: substitute
[*] Running Phase 4 attack
[*] listening
```
**Point to jury:** "Mallory knows the secure wire format. She is going to try the same attack — but she will have to sign her forged DH value. She can only use her own private key."

**Window 2 — Alice (Client) with --secure, connecting to Mallory's port:**
```powershell
python run.py 127.0.0.1 9001 --secure --no-gui
```

**Alice's window (Window 2) immediately shows:**
```
[*] DH Chat | Role: Client | Mode: SECURE (RSA-PSS/SHA-512 signed DH — DHC1)
[*] Pinned peer key  SHA256: 52a62a4d18224eded6d4d4390e7747b1...

[!!!] HANDSHAKE FAILED: signature verification failed
[!!!] Aborting connection — possible man-in-the-middle attack.
```

**Mallory's window (Window 3) shows:**
```
[MITM] Received M1 from server: t=hello
[MITM] SUBSTITUTE: building Mallory's own DH exchange toward each side.
[MITM] Signing forged M1 with Mallory's own RSA key.
[MITM] Sent forged M1 to client. Client should abort (Signature verification FAILED).
[MITM] Got from client: nothing (client aborted)
[MITM] Attack complete. Both endpoints should have printed 'HANDSHAKE FAILED'.
```

**Say to jury:**
> "Alice checked the signature on the incoming DH value against BOB's pinned public key fingerprint — that number you saw on the screen. Mallory signed it with her OWN private key, not Bob's. The fingerprints don't match. Alice aborts immediately. No key is ever derived. No messages are ever sent. Mallory is completely blocked."

> "This is the DHC1 protocol: Diffie-Hellman authenticated with RSA-PSS/SHA-512 signatures. The private key never leaves the owner's machine. Only the public key is shared — and even if Mallory knows the public key, she cannot reverse-engineer the private key."

**Press Ctrl+C in all windows.**

---

### SCENARIO 4 — Show the Test Suite (Optional but Impressive)

```powershell
python -m pytest tests\ -v
```

**As the tests run, point out:**

| Test name | What it proves |
|-----------|----------------|
| `test_mallory_substitutes_Gs_with_own_key_signature` | Mallory's own key → rejected |
| `test_splice_real_sig_on_mallory_value` | Real sig on wrong DH value → rejected |
| `test_garbage_signature` | Random bytes as sig → rejected |
| `test_domain_separation` | "server-hello" sig cannot be used as "client-hello" |
| `test_replay_and_reorder` | Old messages cannot be replayed |
| `test_tamper` | Flip one bit in ciphertext → `InvalidTag` detected |
| `test_mitm_still_works_vulnerable_mode` | Confirms the attack is REAL in vulnerable mode |

**Say to jury:**
> "84 automated tests, passing in under 11 seconds. Each test is a documented security claim — not just 'does the chat work' but 'is each specific attack blocked?'. This is how production-grade security code is verified."

---

## Part 5 – Likely Jury Questions and How to Answer Them

### "What exactly is Man-in-the-Middle?"
> "When two parties are communicating, an attacker positions herself
> between them — intercepting all messages. She decrypts from one side,
> reads the plaintext, and re-encrypts for the other side. Both parties
> think they are talking directly to each other. The 'middle' part is
> that the attacker is invisible — she's in the channel, not at either end."

---

### "Why doesn't Diffie-Hellman alone prevent this?"
> "Diffie-Hellman solves the KEY AGREEMENT problem: how to agree on a
> secret key without sending it. But it doesn't solve the IDENTITY problem:
> who is on the other end? In DH, you exchange public values over the
> network. Anyone can intercept them and substitute their own. DH proves
> you agreed on a key — it doesn't prove who you agreed with."

---

### "How do RSA signatures fix this?"
> "Each party has a key pair — a private key (secret, never shared) and a
> public key (shared with everyone). When Bob sends his DH value, he signs
> it with his private key. Alice verifies using Bob's public key. If the
> verification passes, the DH value really came from Bob — because only
> Bob has the private key needed to create that signature. Mallory cannot
> forge the signature without Bob's private key."

---

### "What is RSA-PSS? Why not just RSA?"
> "RSA-PSS (Probabilistic Signature Scheme) is a safer way to do RSA
> signatures. Basic RSA signatures are deterministic and have known
> weaknesses. PSS adds randomness (a salt) to the signing process, making
> it provably secure. We also use SHA-512 to hash the data before signing
> — SHA-512 is the strongest standard hash function available."

---

### "What is domain separation?"
> "Imagine a signature that says 'approved'. Without context, you could
> take a document that was 'approved' for one purpose and use it for a
> completely different purpose. Domain separation adds context: instead of
> signing just the DH value, the server signs the text 'server-hello'
> PLUS the DH value. The client signs 'client-hello' PLUS its values. A
> server signature can never be mistaken for a client signature because
> they cover different data."

---

### "What is AES-GCM? How is it different from normal AES?"
> "AES by itself is just encryption — it makes data unreadable. But if
> an attacker flips a bit in the encrypted data, a basic AES mode like
> CBC will decrypt it to garbled-but-valid-looking data. You wouldn't
> know it was tampered with. GCM (Galois/Counter Mode) solves this: it
> generates a 16-byte authentication tag over the encrypted data. If
> even one bit changes, the tag check fails and the message is rejected.
> This is called Authenticated Encryption."

---

### "What is HKDF?"
> "HKDF stands for HMAC-based Key Derivation Function. After the DH
> exchange, both sides have the same big number — the shared secret.
> But you can't just use that number directly as an AES key: it might
> not be uniformly random. HKDF takes the shared secret and derives a
> proper, uniformly random key from it. It's the cryptographic equivalent
> of turning raw ingredients into a perfectly calibrated final product."

---

### "What is AVISPA?"
> "AVISPA is a tool for formal verification of security protocols. You
> write the protocol in a formal language (HLPSL), and AVISPA
> mathematically checks whether the protocol achieves its security goals
> — like secrecy and authentication — under all possible attack scenarios.
> We have two models: the unauthenticated DH model (AVISPA says UNSAFE,
> confirming our attack is real) and our fixed protocol (AVISPA says SAFE,
> confirming our fix works)."

---

## Part 6 – Quick Reference (Print and Keep Beside You)

```
PORTS:
  9000 = Bob (real server)
  9001 = Mallory proxy (Alice connects here in MITM scenarios)

ORDER ALWAYS: Server first → MITM second → Client last

SCENARIO 1 — Normal chat:
  Win 1: python run.py 9000 --no-gui
  Win 2: python run.py 127.0.0.1 9000 --no-gui

SCENARIO 2 — MITM attack:
  Win 1: python run.py 9000 --no-gui
  Win 3: python mitm.py 127.0.0.1 9000 9001 --no-gui
  Win 2: python run.py 127.0.0.1 9001 --no-gui
  → Mallory reads everything in Window 3

SCENARIO 3 — Secure fix:
  Win 1: python run.py 9000 --secure --no-gui
  Win 3: python mitm.py 127.0.0.1 9000 9001 --secure --no-gui
  Win 2: python run.py 127.0.0.1 9001 --secure --no-gui
  → Window 2 prints HANDSHAKE FAILED

SCENARIO 4 — Tests:
  python -m pytest tests\ -v   →  84 passed in ~10s

IF A PORT IS BUSY:
  Change 9000→9002, 9001→9003 in all three commands

IF gen_keys is needed:
  python gen_keys.py
```

---

*This document is for the IS-FA2 project team to understand and
present the project clearly in front of the jury.*
