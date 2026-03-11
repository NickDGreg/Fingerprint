import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

FIXTURE_HTML = """<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Fixture Site</title>
    <link rel=\"icon\" href=\"/favicon.ico\" />
    <link rel=\"stylesheet\" href=\"/static/style.css\" />
    <script src=\"/static/app.js\"></script>
    <script src=\"https://example.com/external.js\"></script>
    <script>
      window.ga=\"UA-12345678-1\";
      window.ga4=\"G-1A2B3C4D\";
      window.gtm=\"GTM-ABCDE1\";
      fbq('init','1234567890');
    </script>
  </head>
  <body>
    <h1>Fixture Site</h1>
    <img src=\"/static/logo.png\" alt=\"logo\" />
  </body>
</html>
"""

FIXTURE_JS = b"console.log('fixture');\n"
FIXTURE_CSS = b"body { background: #fff; }\n"
FIXTURE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x0aIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\x0d\n-\xb4"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
FIXTURE_FAVICON = (
    b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x04\x00"
    b"\x28\x01\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x10\x00\x00\x00"
    b"\x20\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        del format, args
        return None

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/plain",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path == "/favicon.ico":
            self._send(
                200,
                FIXTURE_FAVICON,
                "image/x-icon",
                {"Cache-Control": "no-store"},
            )
            return
        if self.path == "/static/app.js":
            self._send(200, FIXTURE_JS, "application/javascript")
            return
        if self.path == "/static/style.css":
            self._send(200, FIXTURE_CSS, "text/css")
            return
        if self.path == "/static/logo.png":
            self._send(200, FIXTURE_PNG, "image/png")
            return
        if self.path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow:\n", "text/plain")
            return
        if self.path == "/sitemap.xml":
            self._send(
                200,
                b'<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>',
                "application/xml",
            )
            return
        if self.path == "/":
            self._send(
                200,
                FIXTURE_HTML.encode("utf-8"),
                "text/html; charset=utf-8",
                {"X-Test-Header": "fixture"},
            )
            return
        self._send(404, b"not found", "text/plain")


class FixtureServer:
    def __init__(
        self,
        server: ThreadingHTTPServer,
        thread: threading.Thread,
    ) -> None:
        self._server = server
        self._thread = thread

    @property
    def base_url(self) -> str:
        host = self._server.server_address[0]
        port = self._server.server_address[1]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def start_fixture_server(host: str = "127.0.0.1", port: int = 0) -> FixtureServer:
    server = ThreadingHTTPServer((host, port), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return FixtureServer(server, thread)
