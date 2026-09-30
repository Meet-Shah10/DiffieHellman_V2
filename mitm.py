#!/usr/bin/env python
"""mitm.py — DH Man-in-the-Middle proxy.

Phase 0: Python 3 port (print, bytes/str, socket)
Phase 1: argparse --secure / --no-gui; mode banner; log_intercept()
Phase 4: --secure wires Phase 4 attack modes; two independent DH exchanges (F09):
         substitute (default): Mallory signs with her own key → endpoints abort
         splice:  Mallory swaps Gs but keeps real signature → endpoints abort
         relay:   Mallory forwards unmodified → chat works, only ciphertext visible

Usage:
    python mitm.py <server_ip> <server_port> <client_port> [--secure [--attack MODE]] [--no-gui]

Attack modes (--secure only):
    substitute  Mallory signs her forged Gs with her OWN RSA key (default).
                Both endpoints abort: client gets wrong signer, server gets wrong auth.
    splice      Mallory swaps Gs but keeps the real server signature.
                Client aborts: the signature covers the wrong value.
    relay       Mallory forwards every handshake message unchanged.
                Chat works; Mallory sees only GCM ciphertext.
"""

import json
import os
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
    parser = argparse.ArgumentParser(
        description="DH MITM Proxy — IS FA2 demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python mitm.py 127.0.0.1 9000 9001                       # vulnerable MITM\n"
            "  python mitm.py 127.0.0.1 9000 9001 --secure               # substitute attack\n"
            "  python mitm.py 127.0.0.1 9000 9001 --secure --attack relay # relay / spy mode\n"
            "  python mitm.py 127.0.0.1 9000 9001 --no-gui               # stdout logging\n"
        ),
    )
    parser.add_argument("server_ip",   help="Real server IP")
    parser.add_argument("server_port", type=int, help="Real server port")
    parser.add_argument("client_port", type=int, help="Port to listen on for the victim client")
    parser.add_argument(
        "--secure", action="store_true",
        help="Speak DHC1 signed wire format and attempt a forgery attack.",
    )
    parser.add_argument(
        "--attack", choices=["substitute", "splice", "relay"], default="substitute",
        help=(
            "Attack mode (only with --secure). "
            "substitute: sign forged value with Mallory's own key (default). "
            "splice: keep real sig but swap DH value. "
            "relay: forward everything unchanged (spy mode)."
        ),
    )
    parser.add_argument(
        "--no-gui", action="store_true",
        help="Log intercepted messages to stdout; suppress Tkinter window.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(secure: bool, attack: str = "substitute") -> None:
    if secure:
        print(
            f"[*] MITM | Mode: SECURE wire-format | Attack: {attack}\n"
            f"[*] Running Phase 4 attack — see --attack for options.",
            flush=True,
        )
    else:
        print(
            "[*] MITM | Mode: VULNERABLE — parameter injection active\n"
            "[!] All messages will be decrypted and logged in plaintext.",
            flush=True,
        )


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
            pass


def log_info(msg: str) -> None:
    print(f"[MITM] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Transport helpers (used in secure mode)
# ---------------------------------------------------------------------------

def send_json(conn, obj: dict) -> None:
    conn.send(json.dumps(obj))


def recv_json(conn) -> dict:
    line = conn.recv()
    if line is None:
        return {}
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

args = parse_args()
print_banner(args.secure, args.attack)

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
print("[*] listening", flush=True)   # readiness signal for test harness

try:
    conn_server.connect(server_ip, server_port)
except Exception as e:
    print(f"Unable to connect to {server_ip}:{server_port}: {e}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------

if not args.secure:
    # ----- Vulnerable path (unchanged from Phase 0, two independent DH — F09) -----
    def get_line(conn):
        line = None
        while line is None:
            line = conn.recv()
        return line

    p_server = int(get_line(conn_server))
    g_server = int(get_line(conn_server))
    A_server = int(get_line(conn_server))

    # Mallory runs her own DH toward the server
    dh_server = DiffieHellman(p_server, g_server)
    _, _, B_to_server = dh_server.generate_public_broadcast()
    conn_server.send(str(B_to_server))
    crypto_toward_server = CryptoProtocol(dh_server.get_shared_secret(A_server), is_server=False)

    # Mallory runs her own DH toward the client
    dh_client = DiffieHellman(p_server, g_server)
    _, _, A_to_client = dh_client.generate_public_broadcast()
    conn_client.send(str(p_server))
    conn_client.send(str(g_server))
    conn_client.send(str(A_to_client))   # ← Mallory's own value, not server's
    B_from_client = int(get_line(conn_client))
    crypto_toward_client = CryptoProtocol(dh_client.get_shared_secret(B_from_client), is_server=True)

    log_info("Vulnerable key exchange complete. Relaying and decrypting messages.")

else:
    # ----- Secure / Phase 4 path -----
    from dhc1_core import (
        HandshakeError, G, P, Q, enc,
        new_exponent, fingerprint,
        t_server_hello, t_client_auth, t_server_auth,
        sign, verify, derive_keys, make_records,
        unhex,
    )
    from auth_dh import load_private_key, load_public_key, fingerprint_hex

    # Load Mallory's own key pair (for the 'substitute' attack)
    mallory_priv_path = os.path.join("keys", "mallory", "mallory_priv.pem")
    mallory_pub_path  = os.path.join("keys", "mallory", "mallory_pub.pem")
    try:
        mal_priv = load_private_key(mallory_priv_path)
        mal_pub  = load_public_key(mallory_pub_path)
    except FileNotFoundError:
        mal_priv = mal_pub = None
        log_info("Mallory's keys not found — substitute attack will use garbage sig.")

    attack = args.attack

    # Step 1: receive M1 from real server
    m1 = recv_json(conn_server)
    log_info(f"Received M1 from server: t={m1.get('t')}")

    if attack == "relay":
        # --- Relay mode: forward everything unchanged ---
        log_info("RELAY mode: forwarding all handshake messages unchanged.")
        send_json(conn_client, m1)                        # forward M1 to client
        m2 = recv_json(conn_client)                       # receive M2 from client
        log_info(f"Received M2 from client: t={m2.get('t')}")
        send_json(conn_server, m2)                        # forward M2 to server
        m3 = recv_json(conn_server)                       # receive M3 from server
        log_info(f"Received M3 from server: t={m3.get('t')}")
        send_json(conn_client, m3)                        # forward M3 to client
        log_info("RELAY: handshake forwarded. Session established between Alice and Bob.")
        log_info("Mallory can only see ciphertext — cannot decrypt (AES-GCM).")

        # In relay mode, Mallory cannot decrypt. Set up dummy objects that just
        # forward bytes without decrypting.
        class RelaySession:
            """Blind relay: forward ciphertext without decrypting."""
            pass

        crypto_toward_server = RelaySession()
        crypto_toward_client = RelaySession()
        relay_mode = True

    elif attack == "substitute":
        # --- Substitute mode: Mallory signs her own Gs with her own key ---
        log_info("SUBSTITUTE: building Mallory's own DH exchange toward each side.")

        # Mallory toward server: pretend to be the client
        mal_s = new_exponent()
        mal_Gs_for_server = enc(pow(G, mal_s, P))  # Mallory's value toward server

        # Mallory toward client: forge M1 with her own Gs and her own signature
        mal_c = new_exponent()
        mal_Gs_for_client = enc(pow(G, mal_c, P))  # Mallory's value toward client

        if mal_priv is not None:
            forged_sig = sign(mal_priv, t_server_hello(mal_Gs_for_client)).hex()
            log_info("Signing forged M1 with Mallory's own RSA key.")
        else:
            forged_sig = "00" * 256   # garbage
            log_info("WARNING: no Mallory key — using garbage signature.")

        forged_m1 = {
            "t": "hello",
            "v": 1,
            "gs": mal_Gs_for_client.hex(),
            "sig": forged_sig,
        }
        send_json(conn_client, forged_m1)   # client will reject: wrong signer
        log_info("Sent forged M1 to client. Client should abort (Signature verification FAILED).")

        # Complete the substitute handshake toward server too
        # (server will abort when it cannot verify Mallory's M2 as coming from Alice)
        # For demo purposes: forward the real M1 to the client was skipped;
        # we now attempt to complete the leg toward the server with garbage too.
        m2_from_client = recv_json(conn_client)   # likely never arrives; client aborted
        log_info(f"Got from client: {m2_from_client.get('t', 'nothing (client aborted)')}")
        # Don't bother completing the server leg; both sides have aborted.
        relay_mode = False
        crypto_toward_server = crypto_toward_client = None

    elif attack == "splice":
        # --- Splice mode: keep real signature, swap Gs ---
        log_info("SPLICE: keeping real server signature, swapping in Mallory's Gs.")

        # Generate Mallory's own DH value for the client
        mal_c = new_exponent()
        mal_Gc = enc(pow(G, mal_c, P))

        spliced_m1 = dict(m1)
        spliced_m1["gs"] = mal_Gc.hex()   # real sig covers different Gs → will fail
        send_json(conn_client, spliced_m1)
        log_info("Sent spliced M1 to client. Client should abort (sig covers wrong value).")

        m2_from_client = recv_json(conn_client)
        log_info(f"Got from client: {m2_from_client.get('t', 'nothing (client aborted)')}")
        relay_mode = False
        crypto_toward_server = crypto_toward_client = None

    else:
        raise ValueError(f"Unknown attack mode: {attack!r}")


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
            if line != "":
                if cp_receive is None or cp_send is None:
                    # Attack caused abort — nothing more to relay
                    break
                if isinstance(cp_receive, CryptoProtocol):
                    try:
                        from cryptography.exceptions import InvalidTag
                        plaintext = cp_receive.decrypt(line)
                        log_intercept(name, plaintext)
                        conn_send.send(cp_send.encrypt(plaintext))
                    except (InvalidTag, Exception) as e:
                        log_info(f"[{name}] decrypt error: {e}")
                else:
                    # RelaySession: blind forward
                    conn_send.send(line)
        else:
            break


if args.secure:
    if getattr(args, 'attack', 'substitute') == 'relay':
        # Relay mode: blind-forward encrypted records in both directions
        t = threading.Thread(
            target=session,
            args=(conn_server, crypto_toward_server, conn_client, crypto_toward_client, "server"),
            daemon=True,
        )
        t.start()
        session(conn_client, crypto_toward_client, conn_server, crypto_toward_server, "client")
    else:
        # Substitute / splice: both endpoints have aborted; nothing to relay
        log_info("Attack complete. Both endpoints should have printed 'HANDSHAKE FAILED'.")
else:
    # Vulnerable mode: bidirectional relay with decryption
    t = threading.Thread(
        target=session,
        args=(conn_server, crypto_toward_server, conn_client, crypto_toward_client, "server"),
        daemon=True,
    )
    t.start()
    session(conn_client, crypto_toward_client, conn_server, crypto_toward_server, "client")
