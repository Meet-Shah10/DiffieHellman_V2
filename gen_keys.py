#!/usr/bin/env python
"""gen_keys.py — one-shot CLI to generate RSA-2048 key pairs for DHC1.

Usage:
    python gen_keys.py                          # generate alice, bob, mallory
    python gen_keys.py alice bob                # only those names
    python gen_keys.py alice bob mallory        # explicit

Each name creates:
    keys/<name>/<name>_priv.pem   (PKCS8, mode 0600 — NEVER commit)
    keys/<name>/<name>_pub.pem    (SubjectPublicKeyInfo)

Refuses to overwrite an existing key (FileExistsError).
Prints SHA-256 fingerprint of each public key for out-of-band verification.

Phase 3 / F18: key separation (alice/, bob/, mallory/), O_EXCL creation,
fingerprint display.
"""

import os
import sys

from auth_dh import (
    generate_keypair,
    save_private_key,
    save_public_key,
    fingerprint_hex,
)

DEFAULT_NAMES = ["alice", "bob", "mallory"]


def gen_keys_for(name: str, base_dir: str = "keys") -> None:
    """Generate (or refuse to overwrite) a key pair for *name*."""
    key_dir = os.path.join(base_dir, name)
    os.makedirs(key_dir, exist_ok=True)

    priv_path = os.path.join(key_dir, f"{name}_priv.pem")
    pub_path  = os.path.join(key_dir, f"{name}_pub.pem")

    priv, pub = generate_keypair()

    try:
        save_private_key(priv, priv_path)
    except FileExistsError:
        print(f"[!] {priv_path} already exists — skipping (will not overwrite).  "
              f"Delete manually to regenerate.", flush=True)
        return

    try:
        save_public_key(pub, pub_path)
    except FileExistsError:
        # Private key was just written; log and continue (public key is not secret)
        print(f"[!] {pub_path} already exists — skipping public key write.", flush=True)

    fp = fingerprint_hex(pub)
    print(f"[+] {name:10s}  priv={priv_path}  pub={pub_path}", flush=True)
    print(f"           fingerprint: {fp}", flush=True)


def main() -> None:
    names = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_NAMES
    print(f"[*] Generating RSA-2048 key pairs for: {', '.join(names)}", flush=True)
    for name in names:
        gen_keys_for(name)
    print("[*] Done.  Pin these fingerprints out of band before running --secure.", flush=True)


if __name__ == "__main__":
    main()
