#! /usr/bin/env python
# Python-3 port: replaced pwntools with stdlib sockets; base64 via base64 module.

import socket
import base64


class Connection():

    def __init__(self):
        self._sock = None       # raw socket for this side of the connection
        self._server_sock = None  # kept alive so it isn't GC'd during accept

    def listen(self, port_no):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port_no))
        s.listen(1)
        self._server_sock = s           # keep reference
        conn, _ = s.accept()
        self._sock = conn

    def connect(self, ip, port_no):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port_no))
        self._sock = s

    def recv(self):
        """Read one newline-terminated base64 line; return decoded str (or None on EOF)."""
        try:
            line = b''
            while True:
                c = self._sock.recv(1)
                if not c:           # remote closed
                    return None
                if c == b'\n':
                    break
                line += c
            if not line:
                return None
            return base64.b64decode(line).decode('utf-8')
        except Exception:
            return None

    def send(self, data):
        """Encode data (str or bytes) as base64 and send as a newline-terminated line."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        encoded = base64.b64encode(data) + b'\n'
        self._sock.sendall(encoded)
