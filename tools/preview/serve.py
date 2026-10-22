#!/usr/bin/env python3
"""Local preview of website/ with reload on save. Local only, never in CI.

Serves website/ on 127.0.0.1 and injects a small script into every HTML page
that polls /__changed and reloads when any file under website/ is saved. The
site uses root-relative paths (/assets/...), so it must be served from
website/ as the document root; opening the file directly will not style it.

    python3 tools/preview/serve.py [--port 8000]
"""

import argparse
import functools
import http.server
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2] / "website"

RELOAD = b"""<script>
(() => {
  let seen = null;
  setInterval(async () => {
    try {
      const v = await (await fetch("/__changed", {cache: "no-store"})).text();
      if (seen !== null && v !== seen) location.reload();
      seen = v;
    } catch (e) { /* server stopped; keep the page as it is */ }
  }, 700);
})();
</script>
"""


def latest_mtime() -> str:
    return str(max((p.stat().st_mtime_ns for p in ROOT.rglob("*") if p.is_file()), default=0))


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:
        if self.path == "/__changed":
            self._send(latest_mtime().encode(), "text/plain")
            return
        path = pathlib.Path(self.translate_path(self.path))
        if path.is_dir():
            path = path / "index.html"
        if path.suffix == ".html" and path.is_file():
            html = path.read_bytes()
            html = html.replace(b"</body>", RELOAD + b"</body>", 1)
            self._send(html, "text/html; charset=utf-8")
            return
        super().do_GET()

    def _send(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8000)
    port = ap.parse_args().port
    handler = functools.partial(Handler, directory=str(ROOT))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        print(f"Serving {ROOT} at http://127.0.0.1:{port}/ (reloads on save, Ctrl-C to stop)")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
