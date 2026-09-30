#!/usr/bin/env python
"""run.py — DH Secure Chat server/client.

Phase 0: Python 3 port (print, bytes/str, socket)
Phase 1: argparse --secure / --no-gui; mode banner; StdinReaderThread
Phase 2: DH parameter validation (see diffie_hellman.py)
Phase 3: --secure wires the full DHC1 signed handshake (auth_dh.py);
         --key-dir selects the key directory; --peer-pub selects the pinned
         peer public key; HandshakeError is caught and prints abort banner.

Usage:
    python run.py <port>               [--secure [--key-dir DIR] [--peer-pub FILE]] [--no-gui]
    python run.py <ip> <port>          [--secure [--key-dir DIR] [--peer-pub FILE]] [--no-gui]
"""

import threading
import sys
import argparse
import json
import os
import network
from diffie_hellman import DiffieHellman
from crypto_protocol import CryptoProtocol


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

def parse_args():
    """
    Server mode: run.py <port> [--secure] [--no-gui]
    Client mode: run.py <ip> <port> [--secure] [--no-gui]
    """
    parser = argparse.ArgumentParser(
        description="DH Secure Chat — IS FA2 demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run.py 9000                                    # vulnerable server\n"
            "  python run.py 127.0.0.1 9000                          # vulnerable client\n"
            "  python run.py 9000 --secure                           # signed-DH server\n"
            "  python run.py 9000 --secure --key-dir keys/bob        # explicit key dir\n"
            "  python run.py 127.0.0.1 9000 --secure                 # signed-DH client\n"
            "  python run.py 9000 --no-gui                           # CLI / test mode\n"
        ),
    )
    parser.add_argument(
        "positional", nargs="+", metavar="arg",
        help="Server: port   |   Client: ip port",
    )
    parser.add_argument(
        "--secure", action="store_true",
        help="Enable RSA-PSS/SHA-512 signed DH (DHC1 protocol).",
    )
    parser.add_argument(
        "--key-dir", default=None,
        help=(
            "Directory containing <name>_priv.pem and <name>_pub.pem. "
            "Default: keys/bob (server) or keys/alice (client)."
        ),
    )
    parser.add_argument(
        "--peer-pub", default=None,
        help=(
            "Path to the pinned peer public key PEM file. "
            "Default: keys/alice/alice_pub.pem (server) or keys/bob/bob_pub.pem (client)."
        ),
    )
    parser.add_argument(
        "--no-gui", action="store_true",
        help=(
            "Read chat input from stdin; print received messages to stdout. "
            "Required for subprocess-based automated tests."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(role: str, secure: bool) -> None:
    """Print startup mode banner so the audience immediately sees the mode."""
    if secure:
        mode = "SECURE (RSA-PSS/SHA-512 signed DH — DHC1)"
    else:
        mode = "VULNERABLE (unsigned DH)"
    print(f"[*] DH Chat | Role: {role} | Mode: {mode}", flush=True)
    if not secure:
        print("[!] WARNING: DH values are unauthenticated — MITM attack is possible.",
              flush=True)


def print_abort(reason: str) -> None:
    """Print the abort banner when a HandshakeError is caught."""
    print(f"\n[!!!] HANDSHAKE FAILED: {reason}", flush=True)
    print("[!!!] Aborting connection — possible man-in-the-middle attack.", flush=True)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

args = parse_args()

if len(args.positional) not in (1, 2):
    print("Error: provide 'port' (server) or 'ip port' (client).", file=sys.stderr)
    sys.exit(1)

is_server = (len(args.positional) == 1)
conn = network.Connection()
crypto_protocol = None   # set after handshake


def get_line():
    """Block until a non-None line is received."""
    line = None
    while line is None:
        line = conn.recv()
    return line


# ---------------------------------------------------------------------------
# Helper: resolve default key paths
# ---------------------------------------------------------------------------

def _resolve_key_paths(is_server: bool, key_dir: str | None, peer_pub: str | None):
    """Return (priv_path, pub_path, peer_pub_path) based on role and flags."""
    if is_server:
        default_name = "bob"
        default_peer = "alice"
    else:
        default_name = "alice"
        default_peer = "bob"

    kd = key_dir if key_dir else os.path.join("keys", default_name)
    priv_path = os.path.join(kd, f"{default_name}_priv.pem")
    pub_path  = os.path.join(kd, f"{default_name}_pub.pem")

    if peer_pub:
        peer_pub_path = peer_pub
    else:
        peer_pub_path = os.path.join("keys", default_peer, f"{default_peer}_pub.pem")

    return priv_path, pub_path, peer_pub_path


# ---------------------------------------------------------------------------
# Handshake + connection setup
# ---------------------------------------------------------------------------

if is_server:
    print_banner("Server", args.secure)
    try:
        conn.listen(int(args.positional[0]))
    except Exception as e:
        print(f"Unable to open port {args.positional[0]}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.secure:
        # Phase 3: DHC1 signed handshake
        from auth_dh import (
            load_private_key, load_public_key,
            secure_handshake_server,
            fingerprint_hex, HandshakeError,
        )
        priv_path, pub_path, peer_pub_path = _resolve_key_paths(
            True, args.key_dir, args.peer_pub
        )
        try:
            priv = load_private_key(priv_path)
            pub  = load_public_key(pub_path)
            peer_pub = load_public_key(peer_pub_path)
        except FileNotFoundError as e:
            print(f"[!] Key file not found: {e}", file=sys.stderr)
            print("[!] Run: python gen_keys.py", file=sys.stderr)
            conn._sock.close()
            sys.exit(1)
        print(f"[*] Pinned peer key  SHA256: {fingerprint_hex(peer_pub)}", flush=True)
        try:
            record = secure_handshake_server(conn, priv, pub, peer_pub)
        except HandshakeError as e:
            print_abort(str(e))
            conn._sock.close()
            sys.exit(1)
        # Wrap Record in a thin adapter so the message loop below is unchanged
        class _SecureProtocol:
            def encrypt(self, s: str) -> str: return record.seal(s.encode())
            def decrypt(self, s: str) -> str: return record.open(s).decode()
        crypto_protocol = _SecureProtocol()
        print("[+] Secure handshake complete (DHC1).", flush=True)
    else:
        # Vulnerable path
        dh = DiffieHellman()
        p, g, A = dh.generate_public_broadcast()
        conn.send(str(p))
        conn.send(str(g))
        conn.send(str(A))
        B = int(get_line())
        try:
            crypto_protocol = CryptoProtocol(dh.get_shared_secret(B), is_server=True)
        except ValueError as e:
            print(f"[!] DH public value rejected: {e}", file=sys.stderr)
            conn._sock.close()
            sys.exit(1)

else:
    print_banner("Client", args.secure)
    try:
        conn.connect(args.positional[0], int(args.positional[1]))
    except Exception as e:
        print(
            f"Unable to connect to {args.positional[0]}:{args.positional[1]}: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.secure:
        # Phase 3: DHC1 signed handshake
        from auth_dh import (
            load_private_key, load_public_key,
            secure_handshake_client,
            fingerprint_hex, HandshakeError,
        )
        priv_path, pub_path, peer_pub_path = _resolve_key_paths(
            False, args.key_dir, args.peer_pub
        )
        try:
            priv = load_private_key(priv_path)
            pub  = load_public_key(pub_path)
            peer_pub = load_public_key(peer_pub_path)
        except FileNotFoundError as e:
            print(f"[!] Key file not found: {e}", file=sys.stderr)
            print("[!] Run: python gen_keys.py", file=sys.stderr)
            conn._sock.close()
            sys.exit(1)
        print(f"[*] Pinned peer key  SHA256: {fingerprint_hex(peer_pub)}", flush=True)
        try:
            record = secure_handshake_client(conn, priv, pub, peer_pub)
        except HandshakeError as e:
            print_abort(str(e))
            conn._sock.close()
            sys.exit(1)
        class _SecureProtocol:
            def encrypt(self, s: str) -> str: return record.seal(s.encode())
            def decrypt(self, s: str) -> str: return record.open(s).decode()
        crypto_protocol = _SecureProtocol()
        print("[+] Secure handshake complete (DHC1).", flush=True)
    else:
        # Vulnerable path
        p = int(get_line())
        g = int(get_line())
        A = int(get_line())
        try:
            dh = DiffieHellman(p, g)
        except ValueError as e:
            print(f"[!] DH parameter rejection: {e}", file=sys.stderr)
            print("[!] Server sent non-standard DH parameters. Aborting.", file=sys.stderr)
            conn._sock.close()
            sys.exit(1)
        _, _, B = dh.generate_public_broadcast()
        conn.send(str(B))
        try:
            crypto_protocol = CryptoProtocol(dh.get_shared_secret(A), is_server=False)
        except ValueError as e:
            print(f"[!] DH public value rejected: {e}", file=sys.stderr)
            conn._sock.close()
            sys.exit(1)


# ---------------------------------------------------------------------------
# Message sending
# ---------------------------------------------------------------------------

def send_message(text: str) -> None:
    conn.send(crypto_protocol.encrypt(text))


# ---------------------------------------------------------------------------
# Input thread (GUI or stdin)
# ---------------------------------------------------------------------------

if args.no_gui:
    # stdin reader thread — subprocess tests write lines to our stdin;
    # we pick them up here and send them as encrypted chat messages.
    class StdinReaderThread(threading.Thread):
        daemon = True

        def run(self):
            try:
                for raw_line in sys.stdin:
                    text = raw_line.rstrip("\n")
                    if text:
                        send_message(text)
                        print(f"[Me] {text}", flush=True)
            except EOFError:
                pass   # stdin closed — subprocess test finished writing

    StdinReaderThread().start()
else:
    class GUIThread(threading.Thread):
        daemon = True

        def run(self):
            import gui
            gui.set_send_message_callback(send_message)
            gui.start()

    GUIThread().start()


# ---------------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------------

while True:
    line = conn.recv()
    if line is not None:
        if line != "":
            try:
                from cryptography.exceptions import InvalidTag
                plaintext = crypto_protocol.decrypt(line)
            except InvalidTag:
                print("[!] Received message failed authentication — dropping.", flush=True)
                continue
            if args.no_gui:
                print(f"[Other] {plaintext}", flush=True)
            else:
                import gui
                gui.add_new_text("[Other] " + plaintext)
    else:
        break
