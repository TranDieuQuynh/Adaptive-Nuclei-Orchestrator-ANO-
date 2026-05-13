from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.lower()
        query = urllib.parse.parse_qs(parsed.query)

        content_type = "text/html"
        if path == "/rest/user/login":
            body = (
                "<html><body>"
                "<form action='/rest/user/login' method='post'>"
                "<input name='email'>"
                "<input type='password' name='password'>"
                "</form>"
                "</body></html>"
            )
        elif path == "/rest/products/search":
            search_term = query.get("q", [""])[0]
            body = json.dumps({"query": search_term, "results": []})
            content_type = "application/json"
        elif path == "/api/products":
            body = json.dumps([{"id": 1, "name": "juice"}])
            content_type = "application/json"
        elif path == "/openapi.json":
            body = json.dumps(
                {
                    "openapi": "3.0.1",
                    "info": {"title": "demo", "version": "1.0.0"},
                    "paths": {"/api/products": {"get": {"responses": {"200": {"description": "ok"}}}}},
                }
            )
            content_type = "application/json"
        elif path == "/swagger-ui":
            body = "<html><body>swagger ui</body></html>"
        else:
            body = "<html><body>ok</body></html>"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 3000), Handler)
    server.serve_forever()
