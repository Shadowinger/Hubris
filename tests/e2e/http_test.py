"""Remote (Streamable HTTP) bridge through a published Hubris binary: cold start, cache hit, lazy connect, session end."""
import json, os, subprocess, sys, tempfile, time, urllib.request
BIN = sys.argv[1]
os.environ["HUBRIS_HOME"] = tempfile.mkdtemp(prefix="hubris-http-")  # own state: the control suite leaves a config.json behind
HERE = os.path.dirname(os.path.abspath(__file__))
failures = 0
def check(cond, msg):
    global failures
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond: failures += 1

srv = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "http_echo_server.py")], stdout=subprocess.PIPE, text=True)
port = int(srv.stdout.readline().strip())
URL = f"http://127.0.0.1:{port}/mcp"
def stats(): return json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/stats"))

def run_hub():
    return subprocess.Popen([BIN, "--stdio", "--compact", "--no-control", f"--bridge=web:{URL}", "X-Test: 1"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
def rpc(hub, obj):
    hub.stdin.write(json.dumps(obj) + "\n"); hub.stdin.flush()
    while True:
        line = hub.stdout.readline()
        if not line: sys.exit("hub closed stdout")
        m = json.loads(line)
        if "method" not in m: return m
def start(hub):
    rpc(hub, {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"http-test","version":"1"}}})
    hub.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub.stdin.flush()
def status(hub, i): return rpc(hub, {"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":"hub_status"}})["result"]["content"][0]["text"]
def stop(hub):
    hub.stdin.close(); hub.wait(timeout=15)

try:
    # ---- first run: nothing cached, the hub connects at startup to list the tools
    hub = run_hub(); start(hub)
    s = stats()
    check(s["sessions"] == 1 and s["headers_seen"] == s["requests"] >= 3, f"cold start: one session opened, every request carries the configured header ({s})")
    t = status(hub, 2)
    check("bridges=1 (1 running)" in t and "toolcache=hits 0/miss 1" in t, "hub_status: remote bridge connected, cache miss")
    r = rpc(hub, {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"web__peek","arguments":{"what":"x"}}}})
    check(r["result"]["content"][0]["text"].startswith("echo:peek"), "call through the remote bridge answered")
    r = rpc(hub, {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"web__shell","arguments":{"cmd":"rm -rf /"}}}})
    check(r["result"].get("isError") and "SAFE MODE" in r["result"]["content"][0]["text"], "Safe mode scans remote tool arguments too")
    stop(hub)
    check(stats()["deletes"] == 1, "hub exit ends the session (DELETE)")

    # ---- second run: definitions from SQLite, no HTTP until the first call
    before = stats()["requests"]
    hub = run_hub(); start(hub)
    t = status(hub, 2)
    check("bridges=1 (0 running)" in t and "toolcache=hits 1/miss 0" in t and stats()["requests"] == before, "second run: tools from cache, remote server not contacted")
    lst = rpc(hub, {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mcp_search_tools","arguments":{"query":"peek"}}})
    check("web__peek" in lst["result"]["content"][0]["text"] and stats()["requests"] == before, "search finds the cached remote tool without a request")
    r = rpc(hub, {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"web__peek","arguments":{"what":"lazy"}}})
    s = stats()
    check(r["result"]["content"][0]["text"].startswith("echo:peek") and s["sessions"] == 2, "first call opened the session and answered")
    check("bridges=1 (1 running)" in status(hub, 5), "bridge reported running after the lazy connect")
    stop(hub)
    err = hub.stderr.read()
    check("connected to" in err and "via http" in err, "hub log names the transport")
finally:
    srv.kill()
print(f"\n{'FAILED' if failures else 'OK'} http e2e ({failures} failure(s))")
sys.exit(1 if failures else 0)
