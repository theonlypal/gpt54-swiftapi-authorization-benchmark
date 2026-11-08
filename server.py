"""Agent-facing HTTP surface: execution only, loopback only, no operator endpoint."""
import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from gate import Gate, canonical, loads


def make_server(gate, port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != '/':
                self.send_error(404)
                return
            data = b'''<!doctype html><title>SwiftAPI local protected notice</title>
<h1>Local protected notice</h1><label>Exact request JSON <textarea id="request"></textarea></label>
<button id="execute">Submit</button><pre id="result"></pre>
<script>document.querySelector('#execute').onclick=async()=>{
 const r=await fetch('/execute',{method:'POST',headers:{'Content-Type':'application/json'},
 body:document.querySelector('#request').value});
 document.querySelector('#result').textContent=await r.text();};</script>'''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            allowed_origin = 'http://127.0.0.1:' + str(self.server.server_port)
            if self.path != '/execute' or self.headers.get('Origin') not in [None, allowed_origin]:
                self.send_error(403)
                return
            try:
                self.connection.settimeout(5)
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('Chunked input denied')
                size = int(self.headers.get('Content-Length', '-1'))
                if not 0 < size <= 32768:
                    raise ValueError('Request size denied')
                data = self.rfile.read(size)
                if len(data) != size:
                    raise ValueError('Truncated input')
                out = canonical(gate.execute(loads(data)))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)
            except Exception:
                self.send_error(400, 'Request rejected; no retry')
    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--root', required=True, type=Path)
    p.add_argument('--port', default=8766, type=int)
    args = p.parse_args()
    make_server(Gate(args.root), args.port).serve_forever()
