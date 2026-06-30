from __future__ import annotations

import socket
import threading
import time

from oauth_cli_kit.server import _OAuthServer


def test_shutdown_is_not_blocked_by_idle_browser_connection() -> None:
    server = _OAuthServer(("127.0.0.1", 0), expected_state="state")
    serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
    serve_thread.start()

    sock = socket.create_connection(server.server_address, timeout=2)
    try:
        # Give the server time to accept the connection. A non-threaded HTTPServer
        # blocks inside the request handler here and never observes shutdown().
        time.sleep(0.1)
        shutdown_thread = threading.Thread(target=server.shutdown, daemon=True)
        shutdown_thread.start()
        shutdown_thread.join(timeout=1)
        assert not shutdown_thread.is_alive()
    finally:
        sock.close()
        server.server_close()


def test_error_responses_close_http11_connections() -> None:
    server = _OAuthServer(("127.0.0.1", 0), expected_state="state")
    serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
    serve_thread.start()

    try:
        with socket.create_connection(server.server_address, timeout=2) as sock:
            sock.sendall(
                b"GET /favicon.ico HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n"
            )
            response = sock.recv(4096)

        assert b"404" in response
        assert b"Content-Length: 9" in response
        assert b"Connection: close" in response
    finally:
        server.shutdown()
        server.server_close()
