"""
headless_mitm_test.py  -  verifies the MITM scenario without any GUI.
Three threads: real server (port 19877), MITM proxy (listens 19878, connects 19877),
client (connects 19878).  MITM decrypts every message and prints it in plaintext.

Run with:  python headless_mitm_test.py

Phase 2/3 note: CryptoProtocol uses directional keys; is_server flags must be
mirrored correctly on each side of each leg.
"""
import threading
import time
import network
from diffie_hellman import DiffieHellman
from crypto_protocol import CryptoProtocol

PORT_SERVER = 19877   # real Bob
PORT_MITM   = 19878   # Mallory listens here; client connects here

MESSAGES = ["Attack at dawn", "Bank PIN is 1234", "Top secret data"]

captured_by_mitm = []
server_received  = []
errors = []


# ── Real server (Bob) ──────────────────────────────────────────────────────────
def run_server():
    try:
        conn = network.Connection()
        conn.listen(PORT_SERVER)

        dh = DiffieHellman()
        p, g, A = dh.generate_public_broadcast()
        conn.send(str(p)); conn.send(str(g)); conn.send(str(A))
        B = int(conn.recv())
        cp = CryptoProtocol(dh.get_shared_secret(B), is_server=True)

        for _ in MESSAGES:
            raw = conn.recv()
            if raw is None: break
            pt = cp.decrypt(raw)
            server_received.append(pt)
        conn._sock.close()
    except Exception as e:
        errors.append("SERVER: " + str(e))


# ── MITM (Mallory) ─────────────────────────────────────────────────────────────
def run_mitm():
    try:
        conn_server = network.Connection()   # toward real server
        conn_client = network.Connection()   # toward victim client

        # First, listen for the victim client
        conn_client.listen(PORT_MITM)

        # Then connect to the real server
        conn_server.connect("127.0.0.1", PORT_SERVER)

        # --- Receive server's p, g, A ---
        p_s = int(conn_server.recv())
        g_s = int(conn_server.recv())
        A_s = int(conn_server.recv())

        # Mallory↔Server DH  (inject Mallory's own B to Bob)
        dh_s = DiffieHellman(p_s, g_s)
        _, _, B_mallory = dh_s.generate_public_broadcast()
        conn_server.send(str(B_mallory))
        cp_server = CryptoProtocol(dh_s.get_shared_secret(A_s), is_server=False)  # Mallory acts as client toward server

        # Mallory↔Client DH  (inject Mallory's own A to Alice)
        dh_c = DiffieHellman(p_s, g_s)
        _, _, A_mallory = dh_c.generate_public_broadcast()
        conn_client.send(str(p_s))
        conn_client.send(str(g_s))
        conn_client.send(str(A_mallory))   # ← forged value
        B_c = int(conn_client.recv())
        cp_client = CryptoProtocol(dh_c.get_shared_secret(B_c), is_server=True)   # Mallory acts as server toward client

        # Relay: client → MITM → server, printing plaintext
        for _ in MESSAGES:
            raw = conn_client.recv()
            if raw is None: break
            pt = cp_client.decrypt(raw)
            captured_by_mitm.append(pt)
            print(f"[MITM] Intercepted: {pt}")
            # re-encrypt with the server key and forward
            conn_server.send(cp_server.encrypt(pt))

        conn_server._sock.close()
        conn_client._sock.close()
    except Exception as e:
        errors.append("MITM: " + str(e))


# ── Client (Alice) ─────────────────────────────────────────────────────────────
def run_client():
    try:
        time.sleep(0.5)   # let server and mitm bind first
        conn = network.Connection()
        conn.connect("127.0.0.1", PORT_MITM)   # ← connects to MITM, not server

        p = int(conn.recv())
        g = int(conn.recv())
        A = int(conn.recv())   # receives Mallory's A, thinks it's Bob's
        dh = DiffieHellman(p, g)
        _, _, B = dh.generate_public_broadcast()
        conn.send(str(B))
        cp = CryptoProtocol(dh.get_shared_secret(A), is_server=False)

        for msg in MESSAGES:
            conn.send(cp.encrypt(msg))
            time.sleep(0.1)

        conn._sock.close()
    except Exception as e:
        errors.append("CLIENT: " + str(e))


# ── run ────────────────────────────────────────────────────────────────────────
print("Starting MITM scenario...")
print(f"  Real server on port {PORT_SERVER}")
print(f"  MITM proxy  on port {PORT_MITM}  (client connects here)")
print()

st = threading.Thread(target=run_server, daemon=True)
mt = threading.Thread(target=run_mitm,   daemon=True)
ct = threading.Thread(target=run_client, daemon=True)

st.start()
time.sleep(0.1)
mt.start()
ct.start()

ct.join(timeout=20)
mt.join(timeout=5)
st.join(timeout=5)

if errors:
    print("\n[FAIL] Errors:", errors)
else:
    ok = (captured_by_mitm == MESSAGES and server_received == MESSAGES)
    print(f"\n[+] MITM captured {len(captured_by_mitm)}/{len(MESSAGES)} messages in plaintext")
    print(f"[+] Server ultimately received all {len(server_received)} messages")
    print("\n" + ("[PASS] MITM attack succeeded — unauthenticated DH is broken." if ok else "[FAIL] Mismatch!"))
