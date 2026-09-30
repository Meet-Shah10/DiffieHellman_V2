"""
headless_test.py  -  verifies the full DH handshake + AES-CBC round-trip
without launching any GUI.  Run with:  venv/Scripts/python headless_test.py
"""
import threading
import time
import network
from diffie_hellman import DiffieHellman
from crypto_protocol import CryptoProtocol

SERVER_PORT = 19876
MESSAGES = ["Hello from client!", "Secret message 42", "Python 3 works!"]

results = {"server_received": [], "client_received": []}
errors  = []


def run_server():
    try:
        conn = network.Connection()
        conn.listen(SERVER_PORT)

        # DH handshake (server side)
        dh = DiffieHellman()
        p, g, A = dh.generate_public_broadcast()
        conn.send(str(p))
        conn.send(str(g))
        conn.send(str(A))
        B = int(conn.recv())
        cp = CryptoProtocol(dh.get_shared_secret(B))

        # receive all messages from client
        for _ in MESSAGES:
            raw = conn.recv()
            plaintext = cp.decrypt(raw)
            results["server_received"].append(plaintext)
            # echo back
            conn.send(cp.encrypt("ECHO:" + plaintext))

        conn._sock.close()
    except Exception as e:
        errors.append("SERVER: " + str(e))


def run_client():
    try:
        time.sleep(0.3)   # give server time to bind
        conn = network.Connection()
        conn.connect("127.0.0.1", SERVER_PORT)

        # DH handshake (client side)
        p = int(conn.recv())
        g = int(conn.recv())
        A = int(conn.recv())
        dh = DiffieHellman(p, g)
        _, _, B = dh.generate_public_broadcast()
        conn.send(str(B))
        cp = CryptoProtocol(dh.get_shared_secret(A))

        # send messages, collect echoes
        for msg in MESSAGES:
            conn.send(cp.encrypt(msg))
            raw = conn.recv()
            echo = cp.decrypt(raw)
            results["client_received"].append(echo)

        conn._sock.close()
    except Exception as e:
        errors.append("CLIENT: " + str(e))


# ── run ────────────────────────────────────────────────────────────────────────
st = threading.Thread(target=run_server, daemon=True)
ct = threading.Thread(target=run_client, daemon=True)
st.start()
ct.start()
ct.join(timeout=15)
st.join(timeout=5)

if errors:
    print("\n[FAIL] Errors:")
    for e in errors:
        print("  ", e)
else:
    print("\n[+] Server received:")
    for m in results["server_received"]:
        print("    ", m)
    print("[+] Client received echoes:")
    for m in results["client_received"]:
        print("    ", m)

    ok = (results["server_received"] == MESSAGES and
          results["client_received"] == ["ECHO:" + m for m in MESSAGES])
    print("\n" + ("[PASS] All messages round-tripped correctly." if ok else "[FAIL] Mismatch!"))
