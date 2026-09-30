# AVISPA Models — DHC1 Protocol Formal Verification

> **Status:** UNRUN. No AVISPA or ProVerif binary was available in the
> development environment. Do **not** include UNSAFE or SAFE screenshots in
> the report unless your own run produced them (Part 5.1 honesty rule).

## Files

| File | Expected result |
|---|---|
| `dh_unauth.hlpsl` | **UNSAFE** — intruder substitutes DH values and learns the session payload |
| `dh_auth.hlpsl` | **SAFE** — RSA-PSS signatures over labelled transcript, both directions |

## Install spike (Day 1 — time-box 3 hours, owner: Verification and docs)

### Option A — SPAN package (Linux / WSL)

```bash
# SPAN bundles AVISPA for Linux (may need 32-bit libs on modern systems)
# Download from: http://people.irisa.fr/Thomas.Genet/span/
sudo dpkg --add-architecture i386
sudo apt-get install libc6:i386 libstdc++6:i386
# Unpack SPAN, then:
./span/bin/avispa avispa/dh_unauth.hlpsl --ofmc
./span/bin/avispa avispa/dh_auth.hlpsl   --ofmc
```

### Option B — OFMC from source (any platform with Haskell stack)

```bash
git clone https://github.com/ofmc/ofmc.git
cd ofmc && stack build && stack exec ofmc -- avispa/dh_auth.hlpsl
```

### Option C — Ask faculty for lab-machine access

If the lab already has AVISPA installed, run the models there and screenshot
the terminal output. Record the method that worked below.

## How to run

```bash
# Local AVISPA binary (path may vary):
avispa avispa/dh_unauth.hlpsl --ofmc
avispa avispa/dh_auth.hlpsl   --ofmc
avispa avispa/dh_auth.hlpsl   --cl-atse   # only if it accepts exp(); skip otherwise
```

## How to read results

- Read the `SUMMARY` line: `SAFE` or `UNSAFE`.
- Read `DETAILS`: look for `ATTACK_FOUND` (with a trace) or `BOUNDED_NUMBER_OF_SESSIONS`.
- "SAFE" means safe for a **bounded number of sessions** under Dolev-Yao with
  OFMC defaults. State this explicitly in the viva.
- If `dh_auth` reports UNSAFE, read the trace — it may expose a real flaw or
  a modelling slip. Fix the model or the protocol; do **not** edit goals to
  obtain SAFE.

## Fallback

If AVISPA cannot be installed within the time box:
- State clearly in the report and slides that AVISPA was not run.
- Optionally show a ProVerif cross-check **labelled as ProVerif** (not AVISPA).
- Show the hand-drawn attack sequence diagram as a substitute for the UNSAFE trace.

## Install method that worked

> _Fill in after the Day 1 spike._

---

*Audit: record AVISPA version and OFMC back-end version here after the first
successful run.*
