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

# Minimal PNG bytes (not a full valid image, but deterministic bytes for hashing)
FIXTURE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x0aIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\x0d\n-\xb4"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

# Minimal ICO bytes for favicon hashing
FIXTURE_FAVICON = (
    b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x04\x00"
    b"\x28\x01\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x10\x00\x00\x00"
    b"\x20\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status, body, content_type="text/plain", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return None

        if self.path == "/favicon.ico":
            return self._send(
                200, FIXTURE_FAVICON, "image/x-icon", {"Cache-Control": "no-store"}
            )

        if self.path == "/static/app.js":
            return self._send(200, FIXTURE_JS, "application/javascript")

        if self.path == "/static/style.css":
            return self._send(200, FIXTURE_CSS, "text/css")

        if self.path == "/static/logo.png":
            return self._send(200, FIXTURE_PNG, "image/png")

        if self.path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow:\n", "text/plain")

        if self.path == "/sitemap.xml":
            return self._send(
                200,
                b'<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>',
                "application/xml",
            )

        if self.path == "/":
            return self._send(
                200,
                FIXTURE_HTML.encode("utf-8"),
                "text/html; charset=utf-8",
                {"X-Test-Header": "fixture"},
            )

        return self._send(404, b"not found", "text/plain")


class FixtureServer:
    def __init__(self, server, thread):
        self._server = server
        self._thread = thread

    @property
    def base_url(self):
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def close(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def start_fixture_server(host="127.0.0.1", port=0):
    server = ThreadingHTTPServer((host, port), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return FixtureServer(server, thread)
