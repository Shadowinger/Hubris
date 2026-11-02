"""Streamable HTTP MCP server for the e2e suite. Prints its port on stdout, counts what it sees under GET /stats."""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
  {"name":"peek","description":"Read something","inputSchema":{"type":"object","properties":{"what":{"type":"string"}}},"annotations":{"readOnlyHint":True}},
  {"name":"shell","description":"Run a shell command","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}},
]
STATS = {"requests":0, "sessions":0, "deletes":0, "headers_seen":0, "bad_session":0}
SESSION = {"id": None}
lock = threading.Lock()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/stats": return self._json(200, STATS)
        self.send_response(405); self.end_headers()
    def do_DELETE(self):
        with lock: STATS["deletes"] += 1
        self.send_response(200); self.end_headers()
    def do_POST(self):
        with lock:
            STATS["requests"] += 1
            if self.headers.get("X-Test") == "1": STATS["headers_seen"] += 1
        n = int(self.headers.get("Content-Length", "0")); m = json.loads(self.rfile.read(n))
        meth, mid = m.get("method"), m.get("id")
        if meth == "initialize":
            with lock: STATS["sessions"] += 1; SESSION["id"] = "sess-%d" % STATS["sessions"]
            return self._json(200, {"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"echo-http","version":"0.1"}}}, {"Mcp-Session-Id": SESSION["id"]})
        if self.headers.get("Mcp-Session-Id") != SESSION["id"]:
            with lock: STATS["bad_session"] += 1
            self.send_response(404); self.end_headers(); return
        if mid is None:
            self.send_response(202); self.end_headers(); return
        if meth == "tools/list":
            data = json.dumps({"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS}})
            body = (": hello\n\nevent: message\ndata: %s\n\n" % data).encode()
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if meth == "tools/call":
            p = m["params"]
            return self._json(200, {"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"echo:%s:%s" % (p["name"], json.dumps(p.get("arguments")))}]}})
        self._json(200, {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"nope"}})

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
