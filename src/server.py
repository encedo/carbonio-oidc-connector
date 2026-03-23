#!/usr/bin/env python3
"""
Carbonio OIDC Connector - Entry point.
"""

import http.server
import json
import logging
import logging.handlers
import os
import signal
import socketserver
import sys
import threading
from urllib.parse import urlparse

# Ensure src/ directory is on path when running directly
sys.path.insert(0, os.path.dirname(__file__))

import config as cfg
import session
import oidc
import callback
import jwks

VERSION = "1.0.0"

_server_config = {}


def setup_logging(log_file: str, log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Stderr handler — always on
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(fmt)
    root.addHandler(stderr_handler)

    # File handler — best effort (may fail before log dir exists on dev machine)
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as e:
        root.warning("Cannot open log file %s: %s — logging to stderr only", log_file, e)


logger = logging.getLogger(__name__)


class OIDCHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        routes = {
            "/oidc/health": self._handle_health,
            "/oidc/authorize": self._handle_authorize,
            "/oidc/callback": self._handle_callback,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_json(404, {"error": "not_found"})

    def _handle_health(self):
        self._send_json(200, {"status": "ok", "version": VERSION})

    def _handle_authorize(self):
        oidc.handle_authorize(self, _server_config)

    def _handle_callback(self):
        callback.handle_callback(self, _server_config)

    def _send_json(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        logger.info("%s - %s", self.address_string(), format % args)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    # Logging starts before config load so we capture config errors too
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

    config = cfg.load_config()

    # Replace basic config with proper handlers (file + stderr)
    logging.getLogger().handlers.clear()
    setup_logging(
        config.get("log_file", "/var/log/carbonio-oidc.log"),
        config.get("log_level", "INFO"),
    )

    global _server_config
    _server_config = config

    # Initialize session store
    session.init(config.get("session_ttl_seconds", 300))

    # Kick off OIDC discovery in background — JWKS prefetch triggered from within discovery
    cfg.start_discovery_background(config)

    host = config["host"]
    port = int(config["port"])
    server = ThreadingHTTPServer((host, port), OIDCHandler)

    def _shutdown(signum, frame):
        logger.info("Received signal %s — shutting down", signum)
        t = threading.Thread(target=server.shutdown, daemon=True)
        t.start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("carbonio-oidc-connector %s listening on %s:%s", VERSION, host, port)
    server.serve_forever()
    logger.info("Server stopped.")


if __name__ == "__main__":
    main()
