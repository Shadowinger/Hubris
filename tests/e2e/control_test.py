"""End-to-end control-plane test: starts Hubris with a bridge, drives MCP over stdio and the control socket."""
import json, os, socket, subprocess, sys, threading, time, glob

HERE = os.path.dirname(os.path.abspath(__file__))
ECHO = os.path.join(HERE, "echo_server.py")
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "src", "Hubris", "bin", "Release", "net10.0", "osx-arm64", "publish", "Hubris")
HOME = os.environ.get("HUBRIS_HOME") or os.path.expanduser("~/.hubris")
RUN = os.environ.get("HUBRIS_RUNTIME_DIR") or os.path.join(HOME, "run")
os.chdir(os.path.join(HERE, "..", ".."))  # git_smart_status below runs in the repo
# "--child-flag" proves bridge arguments starting with "--" reach the child instead of being parsed as Hubris options (audit #8)
hub = subprocess.Popen([BIN, "--stdio", "--compact", "--approval-timeout=5", f"--bridge=py:python3", ECHO, "--child-flag"],
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
pid = hub.pid
stderr_lines = []
threading.Thread(target=lambda: [stderr_lines.append(l.rstrip()) for l in hub.stderr], daemon=True).start()

def rpc(obj, want_id=True):
    hub.stdin.write(json.dumps(obj) + "\n"); hub.stdin.flush()
    notes = []
    while True:
        line = hub.stdout.readline()
        if not line: raise SystemExit("hub closed stdout")
        m = json.loads(line)
        if "method" in m: notes.append(m["method"]); continue
        return m, notes

ok = True
def check(cond, msg):
    global ok
    print(("PASS " if cond else "FAIL ") + msg)
    ok = ok and cond

# --- MCP init
init, _ = rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ctl-test","version":"1"}}})
check(init["result"]["serverInfo"]["name"] == "Hubris", "initialize")
hub.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub.stdin.flush()

# --- audit #1: a malformed notification must not kill the server
hub.stdin.write('{"jsonrpc":"2.0","method":"notifications/cancelled","params":"oops"}\n'); hub.stdin.flush()
pong, _ = rpc({"jsonrpc":"2.0","id":100,"method":"ping"})
check(pong.get("result") == {}, "malformed notifications/cancelled is ignored, ping still answered")

# --- audit #4: fs_read_head is bounded
res, _ = rpc({"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"fs_read_head","arguments":{"path":"/dev/zero"}}}})
check(res["result"].get("isError") and "Binary file" in res["result"]["content"][0]["text"], "fs_read_head on /dev/zero returns an error instead of hanging")
import tempfile
big = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False); big.write("y" * 3_000_000 + "\nsecond\n"); big.close()
t0 = time.time()
res, _ = rpc({"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"fs_read_head","arguments":{"path":big.name,"lines":2,"maxLineLength":50}}})
body = res["result"]["content"][0]["text"]
check(not res["result"].get("isError") and len(body) < 400 and time.time()-t0 < 2, f"3 MB single line is cut to the budget ({len(body)} chars)")
os.unlink(big.name)

# --- audit #6: DLP keeps phone numbers, masks valid birth numbers
ph = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False); ph.write("tel: 777123456\nrc 850612/1228\nid 8506121229\n"); ph.close()
res, _ = rpc({"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"fs_read_head","arguments":{"path":ph.name}}})
body = res["result"]["content"][0]["text"]
check("777123456" in body and "8506121229" in body and "850612/1228" not in body, "DLP masks only numbers that pass the mod-11 rule")
os.unlink(ph.name)

# --- discovery + socket
desc_path = os.path.join(RUN, f"{pid}.json")
for _ in range(50):
    if os.path.exists(desc_path): break
    time.sleep(0.05)
desc = json.load(open(desc_path))
check(desc["pid"] == pid and desc["compact"] is True, f"descriptor written: {desc_path}")
check(desc.get("client") == "ctl-test 1", f"descriptor has client name: {desc.get('client')}")

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect(desc["socket"])
f = sock.makefile("r"); seq = [0]
def recv(until_type, timeout=6):
    sock.settimeout(timeout); got = []
    while True:
        m = json.loads(f.readline()); got.append(m)
        if m["type"] == until_type: return m, got
def send(obj):
    seq[0] += 1; obj["reqId"] = seq[0]; sock.sendall((json.dumps(obj) + "\n").encode()); return seq[0]

hello, _ = recv("hello")
names = [t["name"] for t in hello["tools"]]
check(hello["mode"] == "Safe" and "py__shell" in names and "mcp_execute_tool" in names, f"hello: mode={hello['mode']} tools={len(names)}")
visible = [t["name"] for t in hello["tools"] if t["visible"]]
check(sorted(visible) == ["hub_status", "mcp_execute_tool", "mcp_search_tools"], f"compact visible set: {sorted(visible)}")

# --- approval: deny
def call_async(rid, name, args):
    hub.stdin.write(json.dumps({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}}) + "\n"); hub.stdin.flush()
def read_response(rid):
    while True:
        m = json.loads(hub.stdout.readline())
        if m.get("id") == rid: return m

# --- audit #11: a bridge's readOnlyHint does not skip the scan
call_async(9, "py__peek", {"what": "rm -rf /"})
req, _ = recv("approval_request")
check(req["tool"] == "py__peek" and req["risk"] == "ReadOnly", "bridged read-only tool with dangerous args still needs approval")
send({"type":"deny","approvalId":req["approvalId"]}); recv("ack"); read_response(9)

call_async(10, "py__shell", {"cmd": "rm -rf /tmp/x"})
req, _ = recv("approval_request")
check(req["tool"] == "py__shell" and "rm -rf" in req["reason"], f"approval_request arrived: {req['approvalId']}")
send({"type":"deny","approvalId":req["approvalId"]}); recv("ack")
res = read_response(10)
check(res["result"]["isError"] and "Denied by the user" in res["result"]["content"][0]["text"], "deny -> isError with reason")

# --- approval: approve
call_async(11, "py__shell", {"cmd": "rm -rf /tmp/y"})
req, _ = recv("approval_request")
send({"type":"approve","approvalId":req["approvalId"]}); recv("ack")
res = read_response(11)
check(not res["result"].get("isError") and res["result"]["content"][0]["text"].startswith("echo:shell"), "approve -> executed on bridge")
ev, _ = recv("tool_call")
check(ev["outcome"] == "approved", f"tool_call event outcome={ev['outcome']}")

# --- approval: timeout (5s)
t0 = time.time(); call_async(12, "py__nuke", {})
recv("approval_request")
res = read_response(12)
check(res["result"]["isError"] and "No decision within" in res["result"]["content"][0]["text"] and 4 < time.time()-t0 < 8, f"timeout -> blocked after {time.time()-t0:.1f}s")

# --- runtime mode switch
send({"type":"set_mode","mode":"bypass"}); mc, _ = recv("mode_changed")
check(mc["mode"] == "Bypass", "set_mode bypass -> mode_changed")
call_async(13, "py__nuke", {}); res = read_response(13)
check(not res["result"].get("isError"), "bypass: destructive tool runs without approval")
send({"type":"set_mode","mode":"safe"}); recv("mode_changed")

# --- mcp_execute_tool proxy + unlock + list_changed
res, notes = rpc({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"git_smart_status","arguments":{"cwd":os.getcwd()}}}})
check(not res["result"].get("isError") and "branch=" in res["result"]["content"][0]["text"], "mcp_execute_tool runs locked git_smart_status")
check("notifications/tools/list_changed" in notes, f"proxy execution unlocked target -> list_changed sent ({notes})")
lst, _ = rpc({"jsonrpc":"2.0","id":21,"method":"tools/list"})
check("git_smart_status" in [t["name"] for t in lst["result"]["tools"]], "git_smart_status now in tools/list")

# proxy must not bypass policy
call_async(22, "mcp_execute_tool", {"toolName":"py__shell","arguments":{"cmd":"rm -rf /tmp/z"}})
req, _ = recv("approval_request")
check(req["tool"] == "py__shell", "proxy call still goes through approval gate")
send({"type":"deny","approvalId":req["approvalId"]}); recv("ack"); read_response(22)

res, _ = rpc({"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"mcp_execute_tool"}}})
check(res["result"]["isError"] and "cannot invoke itself" in res["result"]["content"][0]["text"], "proxy self-call rejected")

# --- reveal from UI
send({"type":"reveal","tool":"fs_read_head"}); ack, got = recv("ack")
check(ack["ok"] and any(g["type"] == "tools_changed" for g in got), "reveal command -> tools_changed event")
lst, notes = rpc({"jsonrpc":"2.0","id":24,"method":"tools/list"})
check("fs_read_head" in [t["name"] for t in lst["result"]["tools"]], "revealed tool visible to MCP client")

# --- lock (relock) from UI: hides fs_read_head again + list_changed to the MCP client
send({"type":"lock","tool":"fs_read_head"}); ack, got = recv("ack")
tc = [g for g in got if g["type"] == "tools_changed"]
check(ack["ok"] and tc and not [t for t in tc[-1]["tools"] if t["name"] == "fs_read_head"][0]["visible"], "lock command -> tools_changed with tool hidden")
lst, notes = rpc({"jsonrpc":"2.0","id":25,"method":"tools/list"})
check("fs_read_head" not in [t["name"] for t in lst["result"]["tools"]], "locked tool gone from tools/list")
send({"type":"lock","tool":"hub_status"}); ack, _ = recv("ack")
check(ack["ok"] is False and "pinned" in ack["error"], "locking a pinned tool is refused")
tools_now = tc[-1]["tools"]
check(all(t["tokens"] > 0 for t in tools_now), f"every ToolInfo carries a token estimate ({[t['tokens'] for t in tools_now]})")

# --- status + hub_status
send({"type":"get_status"}); st, _ = recv("status")
check(st["activeTools"] == 4 and 0 < st["activeTokens"] < st["totalTokens"], f"status context meter: {st['activeTools']}/{st['toolCount']} tools ~{st['activeTokens']}/{st['totalTokens']} tok")
check(st["clients"] == 1 and st["blocked"] >= 3 and st["toolCount"] == 8 and st["cacheMisses"] == 1 and st["bridgesRunning"] == 1, f"status: clients={st['clients']} blocked={st['blocked']} tools={st['toolCount']} cacheMisses={st['cacheMisses']}")
res, _ = rpc({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"hub_status"}})
text = res["result"]["content"][0]["text"]
check("control=1 client(s)" in text and "context=4/8 tools" in text, "hub_status reports control client + context meter")
check("toolcache=hits 0/miss 1 entries 1" in text and "bridges=1 (1 running)" in text, f"first run: tool cache miss, bridge spawned at startup")

# --- audit #7: closing the last UI fails waiting approvals at once
call_async(40, "py__shell", {"cmd": "rm -rf /tmp/w"})
recv("approval_request")
t0 = time.time(); f.close(); sock.shutdown(socket.SHUT_RDWR); sock.close()  # makefile keeps the fd alive until closed too
res = read_response(40)
check(res["result"]["isError"] and time.time()-t0 < 2 and "UI disconnected" in res["result"]["content"][0]["text"], f"pending approval failed {time.time()-t0:.1f}s after UI disconnect")
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect(desc["socket"]); f = sock.makefile("r"); recv("hello")

# --- audit #9: a crashed bridge stops advertising its tools
import signal
for line in subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True, text=True).stdout.splitlines():
    if "echo_server.py" in line and "--stdio" not in line:  # the child only; the hub's own command line also names the script
        os.kill(int(line.split()[0]), signal.SIGKILL)
tc, _ = recv("tools_changed", timeout=10)
check(not [t for t in tc["tools"] if t["name"].startswith("py__")], "bridge exit -> tools_changed without py__ tools")
lst, _ = rpc({"jsonrpc":"2.0","id":41,"method":"tools/list"})
check(not [t for t in lst["result"]["tools"] if t["name"].startswith("py__")], "tools/list no longer contains bridge tools")

# --- shutdown via control
send({"type":"shutdown"})
try: hub.wait(timeout=10)
except subprocess.TimeoutExpired: hub.kill(); check(False, "hub exited on shutdown command")
else: check(hub.returncode == 0, f"hub exited on shutdown command (code {hub.returncode})")
time.sleep(0.3)
check(not os.path.exists(desc_path) and not os.path.exists(desc["socket"]), "descriptor and socket removed at exit")
orphans = subprocess.run(["pgrep","-f",ECHO], capture_output=True, text=True).stdout.strip()
check(orphans == "", f"no orphan bridge process ({orphans or 'none'})")

# ===================================================================== second run: cache hit, lazy spawn
hub2 = subprocess.Popen([BIN, "--stdio", "--compact", "--approval-timeout=5", f"--bridge=py:python3", ECHO, "--child-flag"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
err2 = []
threading.Thread(target=lambda: [err2.append(l.rstrip()) for l in hub2.stderr], daemon=True).start()
def rpc2(obj):
    hub2.stdin.write(json.dumps(obj) + "\n"); hub2.stdin.flush()
    while True:
        m = json.loads(hub2.stdout.readline())
        if "method" not in m: return m
rpc2({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ctl-test-2","version":"1"}}})
hub2.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub2.stdin.flush()
t = rpc2({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hub_status"}})["result"]["content"][0]["text"]
check("toolcache=hits 1/miss 0" in t and "bridges=1 (0 running)" in t and "tools=8" in t, "second run: tools listed from cache, bridge process NOT started")
children = [l for l in subprocess.run(["ps","-ax","-o","command="], capture_output=True, text=True).stdout.splitlines() if "echo_server.py" in l and "--stdio" not in l]
check(not children, "no echo_server child before the first bridged call")
r = rpc2({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"py__peek","arguments":{"what":"lazy"}}}})
check(r["result"]["content"][0]["text"].startswith("echo:peek"), "first bridged call spawned the child and answered")
t = rpc2({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hub_status"}})["result"]["content"][0]["text"]
check("bridges=1 (1 running)" in t, "bridge running after the lazy start")
# clear_cache over the control socket: entries dropped and rebuilt, tools still present
d2 = os.path.join(RUN, f"{hub2.pid}.json")
desc2 = json.load(open(d2))
s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s2.connect(desc2["socket"]); f2 = s2.makefile("r")
def recv2(t_):
    while True:
        m = json.loads(f2.readline())
        if m["type"] == t_: return m
recv2("hello")
s2.sendall((json.dumps({"type":"clear_cache","reqId":1}) + "\n").encode()); ack2 = recv2("ack")
st2 = None
s2.sendall((json.dumps({"type":"get_status","reqId":2}) + "\n").encode()); st2 = recv2("status")
check(ack2["ok"] and st2["cacheSize"] == 1 and st2["bridgesRunning"] == 1, f"clear_cache re-listed and re-cached the bridge (entries={st2['cacheSize']})")
lst2 = rpc2({"jsonrpc":"2.0","id":5,"method":"tools/list"})
f2.close(); s2.close()
hub2.stdin.close(); hub2.wait(timeout=30)
check(hub2.returncode == 0, "second hub exited cleanly on EOF")

print("\n--- hub stderr (tail):"); print("\n".join(stderr_lines[-14:]))
sys.exit(0 if ok else 1)
