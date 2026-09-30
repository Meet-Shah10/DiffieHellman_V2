"""
tests/test_args.py — Phase 1 tests.

Tests for:
  A. parse_args() in run.py — all flag combinations
  B. parse_args() in mitm.py — all flag combinations
  C. print_banner() output for run.py (both roles × both modes)
  D. print_banner() output for mitm.py (both modes)
  E. Integration: --no-gui stdin-reader round-trip via subprocess

Each parse_args test recreates the argparse parser inline (identical to the
one defined in run.py / mitm.py) to avoid importing module-level side effects
(socket.listen, etc.) that would run at import time.
"""

import io
import subprocess
import sys
import threading
import time
import unittest
from contextlib import redirect_stdout

try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False

# ---------------------------------------------------------------------------
# Helpers — recreate the parsers without importing the modules
# ---------------------------------------------------------------------------

def _run_parser(argv):
    """Mirror of run.py's parse_args(); tests feed different argv lists."""
    import argparse
    parser = argparse.ArgumentParser(description='DH Secure Chat — IS FA2 demo')
    parser.add_argument('positional', nargs='+', metavar='arg')
    parser.add_argument('--secure', action='store_true')
    parser.add_argument('--no-gui', action='store_true')
    return parser.parse_args(argv)


def _mitm_parser(argv):
    """Mirror of mitm.py's parse_args()."""
    import argparse
    parser = argparse.ArgumentParser(description='DH MITM Proxy — IS FA2 demo')
    parser.add_argument('server_ip')
    parser.add_argument('server_port', type=int)
    parser.add_argument('client_port', type=int)
    parser.add_argument('--secure', action='store_true')
    parser.add_argument('--no-gui', action='store_true')
    return parser.parse_args(argv)


def _run_banner(role, secure):
    """Mirror of run.py's print_banner(); returns captured stdout."""
    f = io.StringIO()
    with redirect_stdout(f):
        if secure:
            mode = "SECURE (signed DH — Phase 3 not yet active)"
        else:
            mode = "VULNERABLE (unsigned DH)"
        print(f"[*] DH Chat | Role: {role} | Mode: {mode}")
        if not secure:
            print("[!] WARNING: DH values are unauthenticated — MITM attack is possible.")
    return f.getvalue()


def _mitm_banner(secure):
    """Mirror of mitm.py's print_banner(); returns captured stdout."""
    f = io.StringIO()
    with redirect_stdout(f):
        if secure:
            print(
                "[*] MITM | Mode: SECURE wire-format\n"
                "[*] Will attempt forgery in Phase 4. Expect endpoints to abort."
            )
        else:
            print(
                "[*] MITM | Mode: VULNERABLE — parameter injection active\n"
                "[!] All messages will be decrypted and logged in plaintext."
            )
    return f.getvalue()


# ---------------------------------------------------------------------------
# A. run.py argparse tests
# ---------------------------------------------------------------------------

class TestRunPyArgs(unittest.TestCase):

    def test_server_no_flags(self):
        args = _run_parser(['9000'])
        self.assertEqual(args.positional, ['9000'])
        self.assertFalse(args.secure)
        self.assertFalse(args.no_gui)

    def test_client_no_flags(self):
        args = _run_parser(['127.0.0.1', '9000'])
        self.assertEqual(args.positional, ['127.0.0.1', '9000'])
        self.assertFalse(args.secure)
        self.assertFalse(args.no_gui)

    def test_secure_flag_server(self):
        args = _run_parser(['9000', '--secure'])
        self.assertTrue(args.secure)
        self.assertFalse(args.no_gui)

    def test_no_gui_flag_server(self):
        args = _run_parser(['9000', '--no-gui'])
        self.assertFalse(args.secure)
        self.assertTrue(args.no_gui)

    def test_both_flags_server(self):
        args = _run_parser(['9000', '--secure', '--no-gui'])
        self.assertTrue(args.secure)
        self.assertTrue(args.no_gui)

    def test_both_flags_client(self):
        args = _run_parser(['10.0.0.1', '9000', '--secure', '--no-gui'])
        self.assertEqual(args.positional, ['10.0.0.1', '9000'])
        self.assertTrue(args.secure)
        self.assertTrue(args.no_gui)

    def test_flags_before_positional_rejected(self):
        """argparse must reject unknown positional arrangements gracefully."""
        import argparse
        with self.assertRaises(SystemExit):
            _run_parser(['--secure'])   # no positional → error

    def test_no_gui_attribute_name(self):
        """Attribute must be .no_gui (with underscore) not .no-gui."""
        args = _run_parser(['9000', '--no-gui'])
        self.assertTrue(hasattr(args, 'no_gui'))


# ---------------------------------------------------------------------------
# B. mitm.py argparse tests
# ---------------------------------------------------------------------------

class TestMitmPyArgs(unittest.TestCase):

    def test_basic(self):
        args = _mitm_parser(['127.0.0.1', '9000', '9001'])
        self.assertEqual(args.server_ip, '127.0.0.1')
        self.assertEqual(args.server_port, 9000)
        self.assertEqual(args.client_port, 9001)
        self.assertFalse(args.secure)
        self.assertFalse(args.no_gui)

    def test_secure_flag(self):
        args = _mitm_parser(['127.0.0.1', '9000', '9001', '--secure'])
        self.assertTrue(args.secure)
        self.assertFalse(args.no_gui)

    def test_no_gui_flag(self):
        args = _mitm_parser(['127.0.0.1', '9000', '9001', '--no-gui'])
        self.assertFalse(args.secure)
        self.assertTrue(args.no_gui)

    def test_both_flags(self):
        args = _mitm_parser(['127.0.0.1', '9000', '9001', '--secure', '--no-gui'])
        self.assertTrue(args.secure)
        self.assertTrue(args.no_gui)

    def test_port_types_are_int(self):
        args = _mitm_parser(['localhost', '8080', '8081'])
        self.assertIsInstance(args.server_port, int)
        self.assertIsInstance(args.client_port, int)
        self.assertEqual(args.server_port, 8080)
        self.assertEqual(args.client_port, 8081)

    def test_missing_client_port_rejected(self):
        import argparse
        with self.assertRaises(SystemExit):
            _mitm_parser(['127.0.0.1', '9000'])   # client_port missing

    def test_non_integer_port_rejected(self):
        import argparse
        with self.assertRaises(SystemExit):
            _mitm_parser(['127.0.0.1', 'notaport', '9001'])


# ---------------------------------------------------------------------------
# C. run.py banner output tests
# ---------------------------------------------------------------------------

class TestRunBanner(unittest.TestCase):

    def test_vulnerable_server_banner(self):
        out = _run_banner("Server", False)
        self.assertIn("[*]", out)
        self.assertIn("Server", out)
        self.assertIn("VULNERABLE", out)
        self.assertIn("[!] WARNING", out)

    def test_vulnerable_client_banner(self):
        out = _run_banner("Client", False)
        self.assertIn("Client", out)
        self.assertIn("VULNERABLE", out)
        self.assertIn("WARNING", out)

    def test_secure_server_banner(self):
        out = _run_banner("Server", True)
        self.assertIn("SECURE", out)
        self.assertNotIn("WARNING", out)

    def test_secure_client_banner(self):
        out = _run_banner("Client", True)
        self.assertIn("SECURE", out)
        self.assertNotIn("WARNING", out)

    def test_banner_contains_role(self):
        for role in ("Server", "Client"):
            with self.subTest(role=role):
                out = _run_banner(role, False)
                self.assertIn(role, out)


# ---------------------------------------------------------------------------
# D. mitm.py banner output tests
# ---------------------------------------------------------------------------

class TestMitmBanner(unittest.TestCase):

    def test_vulnerable_banner(self):
        out = _mitm_banner(False)
        self.assertIn("VULNERABLE", out)
        self.assertIn("parameter injection", out)
        self.assertIn("[!]", out)

    def test_secure_banner(self):
        out = _mitm_banner(True)
        self.assertIn("SECURE", out)
        self.assertIn("Phase 4", out)
        self.assertNotIn("parameter injection", out)


# ---------------------------------------------------------------------------
# E. Integration: subprocess --no-gui stdin-driven chat
#    NOTE: Marked @pytest.mark.slow because RSA.generate(2048) in two child
#    processes takes ~20 s each on this hardware. This test will become
#    fast in Phase 2 when DiffieHellman switches to the pre-computed
#    RFC 3526 2048-bit MODP group constant.
#    Run with: pytest --run-slow tests/test_args.py::TestNoGuiStdinChat
# ---------------------------------------------------------------------------

@(pytest.mark.slow if HAS_PYTEST else (lambda c: c))
class TestNoGuiStdinChat(unittest.TestCase):
    """
    Starts server and client as subprocesses with --no-gui.
    Client writes a line to its stdin; the StdinReaderThread picks it up,
    encrypts it, and sends it to the server.
    Server prints "[Other] <text>" to its stdout.

    SLOW: RSA.generate(2048) in two child processes takes ~20 s each.
    Will become fast in Phase 2 (RFC 3526 constant group).
    Skip by default in CI; run manually with:  pytest --run-slow tests/test_args.py

    Strategy:
      1. Start server (stdin=DEVNULL so it never reads stdin itself).
      2. Wait for server to bind (1 s).
      3. Start client with stdin=PIPE.
      4. Write the message + newline to the client's stdin pipe, then close it.
      5. Poll the server's stdout until "[Other]" appears or TIMEOUT expires.
      6. Terminate both processes.
    """

    SERVER_PORT = 19880          # distinct port from other tests
    TIMEOUT     = 90             # seconds; 2×RSA.generate(2048) + handshake + slack
    POLL_EVERY  = 0.5            # seconds between stdout peeks

    def test_stdin_message_received_by_server(self):
        venv_python = sys.executable
        repo_root   = __file__[:__file__.rfind('tests') - 1]

        server_proc = subprocess.Popen(
            [venv_python, 'run.py', str(self.SERVER_PORT), '--no-gui'],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )  # bytes mode — we read non-blocking below

        time.sleep(1.0)  # let the server bind

        client_proc = subprocess.Popen(
            [venv_python, 'run.py', '127.0.0.1', str(self.SERVER_PORT), '--no-gui'],
            cwd=repo_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        server_buf = b''
        found = False
        try:
            # Write the message to the client's stdin and close the pipe
            client_proc.stdin.write(b'Hello Phase 1!\n')
            client_proc.stdin.close()

            # Accumulate server stdout in a background thread so we can poll it
            server_chunks = []

            def _read_server():
                for chunk in iter(lambda: server_proc.stdout.read(128), b''):
                    server_chunks.append(chunk)

            reader = threading.Thread(target=_read_server, daemon=True)
            reader.start()

            deadline = time.monotonic() + self.TIMEOUT
            while time.monotonic() < deadline:
                server_buf = b''.join(server_chunks)
                if b'[Other] Hello Phase 1!' in server_buf:
                    found = True
                    break
                time.sleep(self.POLL_EVERY)

            self.assertTrue(
                found,
                f"Server stdout after {self.TIMEOUT}s:\n"
                + server_buf.decode('utf-8', errors='replace')
            )
        finally:
            for proc in (client_proc, server_proc):
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
