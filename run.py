#! /usr/bin/env python
# Phase 0: Python 3 port (print, bytes/str, socket, pycryptodome)
# Phase 1: argparse --secure / --no-gui; mode banner; stdin reader thread

import threading
import sys
import argparse
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
        description='DH Secure Chat — IS FA2 demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python run.py 9000                    # vulnerable server\n'
            '  python run.py 127.0.0.1 9000          # vulnerable client\n'
            '  python run.py 9000 --secure           # signed-DH server (Phase 3+)\n'
            '  python run.py 9000 --no-gui           # CLI mode (for tests)\n'
        ),
    )
    parser.add_argument(
        'positional', nargs='+', metavar='arg',
        help="Server: port   |   Client: ip port",
    )
    parser.add_argument(
        '--secure', action='store_true',
        help='Enable RSA-PSS/SHA-512 signed DH (Phase 3+; no-op in Phase 1)',
    )
    parser.add_argument(
        '--no-gui', action='store_true',
        help=(
            'Read chat input from stdin; print received messages to stdout. '
            'Required for subprocess-based automated tests.'
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(role: str, secure: bool) -> None:
    """Print startup mode banner so the audience immediately sees the mode."""
    if secure:
        # Phase 1: --secure is parsed but crypto not wired yet
        mode = "SECURE (signed DH — Phase 3 not yet active)"
    else:
        mode = "VULNERABLE (unsigned DH)"
    print(f"[*] DH Chat | Role: {role} | Mode: {mode}", flush=True)
    if not secure:
        print("[!] WARNING: DH values are unauthenticated — MITM attack is possible.",
              flush=True)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

args = parse_args()

if len(args.positional) not in (1, 2):
    print("Error: provide 'port' (server) or 'ip port' (client).", file=sys.stderr)
    sys.exit(1)

is_server = (len(args.positional) == 1)
conn = network.Connection()
dh = None


def get_line():
    """Block until a non-None line is received."""
    line = None
    while line is None:
        line = conn.recv()
    return line


if is_server:
    print_banner("Server", args.secure)
    try:
        conn.listen(int(args.positional[0]))
    except Exception as e:
        print(f"Unable to open port {args.positional[0]}: {e}", file=sys.stderr)
        sys.exit(1)
    dh = DiffieHellman()
    p, g, A = dh.generate_public_broadcast()
    conn.send(str(p))
    conn.send(str(g))
    conn.send(str(A))
    B = int(get_line())
    crypto_protocol = CryptoProtocol(dh.get_shared_secret(B))
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
    p = int(get_line())
    g = int(get_line())
    A = int(get_line())
    # Phase 2: DiffieHellman(p, g) raises ValueError if p/g ≠ RFC 3526 constants
    # → rejects parameter-injection attacks at the group level.
    # validate_public_value(A, p) is called inside get_shared_secret below.
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
        crypto_protocol = CryptoProtocol(dh.get_shared_secret(A))
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
                    text = raw_line.rstrip('\n')
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
        if line != '':
            plaintext = crypto_protocol.decrypt(line)
            if args.no_gui:
                print(f"[Other] {plaintext}", flush=True)
            else:
                import gui
                gui.add_new_text("[Other] " + plaintext)
    else:
        break
