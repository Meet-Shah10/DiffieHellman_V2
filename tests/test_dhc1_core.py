"""tests/test_dhc1_core.py — 16 protocol-level tests for dhc1_core.py.

These are the tests from IMPLEMENTATION_PLAN_v2.md Appendix A, adapted
to use pytest conventions and grouped into clear categories.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag
from dhc1_core import (
    P, Q, G, enc, dec, WIDTH,
    sign, verify,
    fingerprint,
    t_server_hello, t_client_auth, t_server_auth,
    HandshakeError,
    Server, Client,
    Record, make_records, derive_keys,
    unhex,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _kp():
    """Generate an RSA-2048 key pair."""
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k, k.public_key()


@pytest.fixture(scope="module")
def keys_S():
    return _kp()

@pytest.fixture(scope="module")
def keys_C():
    return _kp()

@pytest.fixture(scope="module")
def keys_M():
    """Mallory's key pair."""
    return _kp()


def honest_session(keys_S, keys_C):
    """Run a complete honest handshake; return (server_record, client_record)."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])
    m2 = cli.on_m1(srv.m1())
    m3, rs = srv.on_m2(m2)
    rc = cli.on_m3(m3)
    return rs, rc


# ---------------------------------------------------------------------------
# Group sanity (test_group)
# ---------------------------------------------------------------------------

def _miller_rabin(n, k=16):
    import random
    if n < 4:
        return n == 2 or n == 3
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def test_group():
    """RFC 3526 group 14: p and q are (probabilistically) prime, g^q == 1."""
    assert P.bit_length() == 2048
    assert _miller_rabin(P), "P should be prime"
    assert _miller_rabin(Q), "Q should be prime"
    assert pow(G, Q, P) == 1


# ---------------------------------------------------------------------------
# Honest session (test_chat_roundtrip, test_fresh_sessions)
# ---------------------------------------------------------------------------

def test_chat_roundtrip(keys_S, keys_C):
    rs, rc = honest_session(keys_S, keys_C)
    assert rs.open(rc.seal(b"hello from client")) == b"hello from client"
    assert rc.open(rs.seal(b"hello from server")) == b"hello from server"


def test_fresh_sessions(keys_S, keys_C):
    """Two sessions must produce different ciphertexts (different ephemeral keys)."""
    rs1, rc1 = honest_session(keys_S, keys_C)
    rs2, rc2 = honest_session(keys_S, keys_C)
    assert rc1.seal(b"x") != rc2.seal(b"x"), "Two sessions must differ"


# ---------------------------------------------------------------------------
# Record layer (test_tamper, test_replay_and_reorder, test_reflection)
# ---------------------------------------------------------------------------

def test_tamper(keys_S, keys_C):
    """Flipping a bit in the ciphertext raises InvalidTag."""
    rs, rc = honest_session(keys_S, keys_C)
    wire = rc.seal(b"hello")
    bad = wire[:-2] + ("00" if wire[-2:] != "00" else "01")
    with pytest.raises(InvalidTag):
        rs.open(bad)


def test_replay_and_reorder(keys_S, keys_C):
    """Replay and reorder/drop are rejected by counter nonces."""
    rs, rc = honest_session(keys_S, keys_C)
    w1, w2 = rc.seal(b"first"), rc.seal(b"second")
    # Reorder: consume w2 before w1 → w2 fails (wrong counter)
    with pytest.raises(InvalidTag):
        rs.open(w2)
    # Now w1 succeeds (counter is still at 0)
    assert rs.open(w1) == b"first"
    assert rs.open(w2) == b"second"
    # Replay: w1 already consumed
    with pytest.raises(InvalidTag):
        rs.open(w1)


def test_reflection(keys_S, keys_C):
    """A ciphertext from client reflected back to the client is rejected."""
    rs, rc = honest_session(keys_S, keys_C)
    wire = rc.seal(b"from client")
    with pytest.raises(InvalidTag):
        rc.open(wire)   # client tries to open its own outgoing ciphertext


# ---------------------------------------------------------------------------
# DH value validation (test_bad_dh_values)
# ---------------------------------------------------------------------------

def test_bad_dh_values():
    """dec() must reject values outside the prime-order subgroup."""
    bad_values = [
        enc(0),               # zero
        enc(1),               # order 1
        enc(P - 1),           # order 2
        enc(11),              # passes range but fails subgroup check (F02)
        b"\x01" * 255,        # wrong length (255 instead of 256)
        b"\xff" * 256,        # max value > P
    ]
    for bad in bad_values:
        with pytest.raises(HandshakeError):
            dec(bad)


# ---------------------------------------------------------------------------
# Attack scenarios (Mallory substitutes, splices, etc.)
# ---------------------------------------------------------------------------

def test_mallory_substitutes_Gs_with_own_key_signature(keys_S, keys_C, keys_M):
    """Mallory signs her own Gs with her own key. Client has pinned server's key → abort."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])

    # Mallory builds her own M1 signed with her key
    mal = Server(keys_M[0], keys_M[1], keys_C[1])
    forged_m1 = mal.m1()   # valid sig under Mallory's key, not server's key

    with pytest.raises(HandshakeError):
        cli.on_m1(forged_m1)   # client checks against pinned server key → fail


def test_splice_real_sig_on_mallory_value(keys_S, keys_C, keys_M):
    """Mallory keeps the real server signature but swaps Gs. Client detects mismatch."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])
    mal = Server(keys_M[0], keys_M[1], keys_C[1])

    m1 = srv.m1()
    m1["gs"] = mal.gs.hex()   # real sig, wrong Gs

    with pytest.raises(HandshakeError):
        cli.on_m1(m1)


def test_garbage_signature(keys_S, keys_C):
    """A garbage sig in M1 is rejected."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])
    m1 = srv.m1()
    m1["sig"] = "00" * 256
    with pytest.raises(HandshakeError):
        cli.on_m1(m1)


def test_mallory_substitutes_Gc(keys_S, keys_C, keys_M):
    """Mallory swaps Gc in M2. Server verifies against client's pinned key → fail."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])

    m2 = cli.on_m1(srv.m1())
    m2["gc"] = enc(pow(G, 5, P)).hex()   # different value, same signature

    with pytest.raises(HandshakeError):
        srv.on_m2(m2)


def test_replayed_M3_from_different_session(keys_S, keys_C):
    """M3 from one session cannot be replayed into another."""
    # Session A
    s1 = Server(keys_S[0], keys_S[1], keys_C[1])
    c1 = Client(keys_C[0], keys_C[1], keys_S[1])
    m2a = c1.on_m1(s1.m1())
    m3a, _ = s1.on_m2(m2a)

    # Session B — different ephemeral values
    s2 = Server(keys_S[0], keys_S[1], keys_C[1])
    c2 = Client(keys_C[0], keys_C[1], keys_S[1])
    c2.on_m1(s2.m1())

    with pytest.raises(HandshakeError):
        c2.on_m3(m3a)   # M3 covers c1's Gc, not c2's Gc


def test_server_auth_garbage_M3(keys_S, keys_C):
    """A garbage M3 signature is rejected."""
    srv = Server(keys_S[0], keys_S[1], keys_C[1])
    cli = Client(keys_C[0], keys_C[1], keys_S[1])
    cli.on_m1(srv.m1())
    with pytest.raises(HandshakeError):
        cli.on_m3({"t": "confirm", "sig": "00" * 256})


# ---------------------------------------------------------------------------
# Malformed field tests
# ---------------------------------------------------------------------------

def test_malformed_M1_fields(keys_S, keys_C):
    """Various malformed M1s raise HandshakeError."""
    cli = Client(keys_C[0], keys_C[1], keys_S[1])
    bad_m1s = [
        {},                                                       # empty
        {"t": "hello", "v": 1},                                  # missing gs, sig
        {"t": "hello", "v": 1, "gs": "zz", "sig": "00"},         # bad hex gs
        {"t": "hello", "v": 1, "gs": "00", "sig": "00"},         # wrong length gs
        {"t": "auth"},                                            # wrong type
    ]
    for m in bad_m1s:
        with pytest.raises(HandshakeError):
            cli.on_m1(m)


# ---------------------------------------------------------------------------
# Transcript properties (domain separation, fixed width)
# ---------------------------------------------------------------------------

def test_domain_separation(keys_S):
    """A signature for server_hello cannot be presented as server_auth."""
    data = t_server_hello(b"x" * WIDTH)
    sig = sign(keys_S[0], data)
    # Verify against a different label / context
    with pytest.raises(HandshakeError):
        verify(
            keys_S[1], sig,
            t_server_auth(b"a" * 32, b"b" * 32, b"x" * WIDTH, b"x" * WIDTH),
        )


def test_transcript_fixed_width_no_ambiguity():
    """Two different (fp_s, fp_c, gs, gc) tuples produce different transcripts."""
    ta = t_client_auth(b"f" * 32, b"g" * 32, enc(3), enc(4))
    tb = t_client_auth(b"f" * 32, b"g" * 32, enc(4), enc(3))
    assert ta != tb
    expected_len = len(b"DHC1|client-auth|") + 32 + 32 + WIDTH + WIDTH
    assert len(ta) == expected_len
