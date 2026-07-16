from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"jsonrpc":"2.0","result":"ok","id":1}')


HTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
