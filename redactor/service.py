
"""Provide a streaming HTTP API for redacting NDJSON traffic logs."""

import argparse
import io
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .cli import process_stream
from .engine import RedactionEngine
from .rules import load_and_validate_rules


class LimitedInput:
    """Limit HTTP body reads to the declared Content-Length."""

    def __init__(self, source, length):
        """Store the input stream and the number of unread body bytes."""
        self.source = source
        self.remaining = length

    def readline(self, size=-1):
        """Read the next line without crossing the request-body boundary."""
        if self.remaining == 0:
            return b""

        # Never read beyond Content-Length, even when the underlying
        # connection remains open for additional HTTP requests.
        if size < 0:
            size = self.remaining
        else:
            size = min(size, self.remaining)

        data = self.source.readline(size)
        self.remaining -= len(data)

        if not data and self.remaining:
            raise OSError("Incomplete request body")

        return data


class ChunkedOutput:
    """Write redacted records using HTTP chunked transfer encoding."""

    def __init__(self, output):
        """Store the HTTP response stream used to send chunks."""
        self.output = output

    def write(self, data):
        """Send a non-empty byte sequence as one HTTP response chunk."""
        if not data:
            return

        self.output.write(
            f"{len(data):X}\r\n".encode("ascii")
        )
        self.output.write(data)
        self.output.write(b"\r\n")
        self.output.flush()

    def finish(self):
        """Send the terminating zero-length chunk to complete the response."""
        self.output.write(b"0\r\n\r\n")
        self.output.flush()


class RedactionHTTPServer(ThreadingHTTPServer):
    """Serve concurrent HTTP requests with shared, validated rule settings."""

    daemon_threads = True

    def __init__(self, address, handler, rules):
        """Initialize the HTTP server with its redaction configuration."""
        self.rules = rules
        super().__init__(address, handler)


class RedactionHandler(BaseHTTPRequestHandler):
    """Handle health checks and streamed NDJSON redaction requests."""

    protocol_version = "HTTP/1.1"

    def send_json(self, status, data):
        """Return a JSON response with an HTTP status and safe headers."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        """Return health status for /health or 404 for unknown paths."""
        if self.path == "/health":
            self.send_json(200, b'{"status":"ok"}')
        else:
            self.send_json(404, b'{"error":"not_found"}')

    def do_POST(self):
        """Validate and redact an NDJSON request using streamed output."""
        if self.path != "/redact":
            self.send_json(404, b'{"error":"not_found"}')
            self.close_connection = True
            return

        # Fail closed if configuration is unavailable.
        if not getattr(self.server, "rules", None):
            self.send_json(
                503,
                b'{"error":"service_unavailable"}'
            )
            self.close_connection = True
            return

        # We support length-delimited requests.
        # Unsupported transfer encodings are rejected safely.
        if self.headers.get("Transfer-Encoding"):
            self.send_json(
                400,
                b'{"error":"unsupported_transfer_encoding"}'
            )
            self.close_connection = True
            return

        length_header = self.headers.get("Content-Length")

        if length_header is None:
            self.send_json(
                411,
                b'{"error":"content_length_required"}'
            )
            self.close_connection = True
            return

        try:
            length = int(length_header)

            if length < 0:
                raise ValueError()

            # Use a separate engine per request to avoid sharing mutable
            # redaction counters between concurrent HTTP requests.
            engine = RedactionEngine(self.server.rules)

        except (ValueError, TypeError):
            self.send_json(
                503,
                b'{"error":"service_unavailable"}'
            )
            self.close_connection = True
            return

        source = LimitedInput(self.rfile, length)

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/x-ndjson; charset=utf-8"
        )
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        # Stream redacted records as HTTP chunks instead of buffering
        # the entire response in memory.
        output = ChunkedOutput(self.wfile)
        diagnostics = io.StringIO()

        try:
            process_stream(
                source,
                output,
                diagnostics,
                engine,
            )

            output.finish()

        except (OSError, ValueError, TypeError):
            # The response may have started already.
            # Never fall back to original, unredacted traffic.
            self.close_connection = True

        finally:
            # Do not keep a connection open with unread body bytes.
            self.close_connection = True

    def log_message(self, format, *args):
        """Suppress default HTTP request logs to reduce sensitive-data exposure."""
        pass


def create_server(host="127.0.0.1", port=8080, rules_path="rules.yaml"):
    """Validate rules and construct the HTTP server before accepting traffic."""
    rules = load_and_validate_rules(rules_path)

    # Construct the engine to verify configuration at startup.
    RedactionEngine(rules)

    return RedactionHTTPServer(
        (host, port),
        RedactionHandler,
        rules,
    )


def main(argv=None):
    """Parse command-line options and run the HTTP server until shutdown."""
    parser = argparse.ArgumentParser(
        description="Streaming HTTP redaction service"
    )

    parser.add_argument(
        "--rules",
        default="rules.yaml",
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
    )

    args = parser.parse_args(argv)

    try:
        server = create_server(
            args.host,
            args.port,
            args.rules,
        )

    except (OSError, ValueError, TypeError):
        print(
            "Unable to start service with valid rules",
            file=sys.stderr,
        )
        return 2

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
