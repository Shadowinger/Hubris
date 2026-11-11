"""End-to-end control-plane test: starts Hubris with a bridge, drives MCP over stdio and the control socket."""
import json, os, socket, subprocess, sys, threading, time, glob

HERE = os.path.dirname(os.path.abspath(__file__))
ECHO = os.path.join(HERE, "echo_server.py")
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "src", "Hubris", "bin", "Release", "net10.0", "osx-arm64", "publish", "Hubris")
HOME = os.environ.get("HUBRIS_HOME") or os.path.expanduser("~/.hubris")
RUN = os.environ.get("HUBRIS_RUNTIME_DIR") or os.path.join(HOME, "run")
os.chdir(os.path.join(HERE, "..", ".."))  # git_smart_status below runs in the repo
# "--child-flag" proves bridge arguments starting with "--" reach the child instead of being parsed as Hubris options (audit #8)
hub = subprocess.Popen([BIN, "--stdio", "--compact", "--control-trust-all", "--approval-timeout=5", f"--bridge=py:python3", ECHO, "--child-flag"],
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

# --- resources and prompts pass through the bridge, routed by uri / prefix
rl, _ = rpc({"jsonrpc":"2.0","id":90,"method":"resources/list"})
check([r["uri"] for r in rl["result"]["resources"]] == ["py://hello"], "resources/list aggregates the bridge's resources")
rt, _ = rpc({"jsonrpc":"2.0","id":91,"method":"resources/templates/list"})
check(rt["result"]["resourceTemplates"][0]["uriTemplate"] == "py://item/{id}", "resources/templates/list passes templates through")
rr, _ = rpc({"jsonrpc":"2.0","id":92,"method":"resources/read","params":{"uri":"py://item/7"}})
check(rr["result"]["contents"][0]["text"].startswith("resource:py://item/7") and "token=***" in rr["result"]["contents"][0]["text"], "resources/read routed by template prefix, DLP applied")
rx, _ = rpc({"jsonrpc":"2.0","id":93,"method":"resources/read","params":{"uri":"nope://x"}})
check(rx.get("error", {}).get("code") == -32002, "unknown resource -> -32002")
pl, _ = rpc({"jsonrpc":"2.0","id":94,"method":"prompts/list"})
check([p["name"] for p in pl["result"]["prompts"]] == ["py__greet"], "prompts/list carries the bridge prefix")
pg, _ = rpc({"jsonrpc":"2.0","id":95,"method":"prompts/get","params":{"name":"py__greet","arguments":{"who":"hub"}}})
check(pg["result"]["messages"][0]["content"]["text"] == "hi hub", "prompts/get strips the prefix and forwards arguments")
pg, _ = rpc({"jsonrpc":"2.0","id":96,"method":"prompts/get","params":{"name":"py__greet","arguments":{"who":"token=abcdef0123456789abcdef"}}})
check("abcdef0123456789abcdef" not in pg["result"]["messages"][0]["content"]["text"], "prompts/get masks secrets like tool results")

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

# --- approval: remember the decision (allow-list) for a declared-destructive tool, then forget it
call_async(14, "py__nuke", {"target": "r1"})
req, _ = recv("approval_request")
send({"type":"approve","approvalId":req["approvalId"],"remember":True}); recv("ack"); read_response(14); recv("tool_call")
# a second call must run straight through with NO approval_request (held calls block for 5s before isError)
t0 = time.time(); call_async(15, "py__nuke", {"target": "r1"}); res = read_response(15)
check(not res["result"].get("isError") and time.time()-t0 < 2, "approve+remember -> next call of the destructive tool runs without an approval_request")
check(recv("tool_call")[0]["outcome"] == "approved", "remembered call emits an approved tool_call")
# a remembered allow on a *mutating* tool never covers an argument-pattern hit: it still asks
call_async(17, "py__shell", {"cmd": "rm -rf /tmp/r2"})
req17, _ = recv("approval_request")
send({"type":"approve","approvalId":req17["approvalId"],"remember":True}); recv("ack"); read_response(17); recv("tool_call")
call_async(18, "py__shell", {"cmd": "rm -rf /tmp/r2"})
req18, _ = recv("approval_request")
check(req18["tool"] == "py__shell", "remembered allow does not waive a destructive-pattern hit: asked again")
send({"type":"deny","approvalId":req18["approvalId"]}); recv("ack"); read_response(18); recv("tool_call")
send({"type":"forget","tool":"py__shell"}); recv("ack")
# forget -> the destructive tool is held for approval again
send({"type":"forget","tool":"py__nuke"}); recv("ack")
call_async(16, "py__nuke", {"target": "r1"})
req, _ = recv("approval_request")
check(req["tool"] == "py__nuke", "forget -> tool is held for approval again")
send({"type":"deny","approvalId":req["approvalId"]}); recv("ack"); read_response(16)

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
# --- auto mode: declared-destructive tools run, dangerous arguments go back to the model, the 4th block in a row asks
send({"type":"set_mode","mode":"auto"}); mc, _ = recv("mode_changed")
check(mc["mode"] == "Auto", "set_mode auto -> mode_changed")
call_async(130, "py__nuke", {}); res = read_response(130)
check(not res["result"].get("isError"), "auto: a tool that only declares destructiveHint runs without approval")
blocked = []
for i in range(3):
    call_async(131 + i, "py__shell", {"cmd": "git push --force"}); blocked.append(read_response(131 + i))
check(all(b["result"]["isError"] and "[AUTO MODE BLOCKED]" in b["result"]["content"][0]["text"] and "destructive git" in b["result"]["content"][0]["text"] for b in blocked),
      "auto: three dangerous calls return the matched rule at once, no approval request")
call_async(134, "py__shell", {"cmd": "git push --force"})
req134, _ = recv("approval_request")
check(req134["tool"] == "py__shell", "auto: after 3 blocks in a row the next one waits for approval")
send({"type":"approve","approvalId":req134["approvalId"]}); recv("ack"); res = read_response(134)
check(not res["result"].get("isError"), "auto: the approved call ran")
call_async(135, "py__shell", {"cmd": "git push --force"}); res = read_response(135)
check(res["result"]["isError"] and "[AUTO MODE BLOCKED]" in res["result"]["content"][0]["text"], "auto: the approval resumed auto mode (blocked again without asking)")
# --- a critical-path removal is held in every mode, bypass included
send({"type":"set_mode","mode":"bypass"}); recv("mode_changed")
call_async(136, "py__shell", {"cmd": "rm -rf ~"})
req136, _ = recv("approval_request")
check("BLOCKED IN EVERY MODE" in req136.get("reason", ""), "bypass: rm -rf ~ still waits for approval")
send({"type":"deny","approvalId":req136["approvalId"]}); recv("ack"); read_response(136)
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

# --- a crashed bridge keeps its tools and is started again by the next call
import signal
for line in subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True, text=True).stdout.splitlines():
    if ECHO in line and "--child-flag" in line and "--stdio" not in line:  # only *our* child; the hub's own command line also names the script
        os.kill(int(line.split()[0]), signal.SIGKILL)
time.sleep(0.6)
send({"type":"list_tools"}); tc, _ = recv("tools_changed", timeout=10)
check([t for t in tc["tools"] if t["name"].startswith("py__")], "bridge exit -> its tools stay listed")
call_async(41, "py__peek", {"what": "back"}); res = read_response(41)
check(res["result"]["content"][0]["text"].startswith("echo:peek"), "the next call started the crashed bridge again")

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
hub2 = subprocess.Popen([BIN, "--stdio", "--compact", "--control-trust-all", "--approval-timeout=5", f"--bridge=py:python3", ECHO, "--child-flag"],
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
rl2 = rpc2({"jsonrpc":"2.0","id":21,"method":"resources/list"})
check([r["uri"] for r in rl2["result"]["resources"]] == ["py://hello"] and "resources=1+1 prompts=1" in t, "second run: resources and prompts served from the cache, no child needed")
children = [l for l in subprocess.run(["ps","-ax","-o","command="], capture_output=True, text=True).stdout.splitlines() if ECHO in l and "--child-flag" in l and "--stdio" not in l]
check(not children, "no echo_server child before the first bridged call")
rn = rpc2({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"py__nuke","arguments":{}}}})
tn = rn["result"]["content"][0]["text"]
children = [l for l in subprocess.run(["ps","-ax","-o","command="], capture_output=True, text=True).stdout.splitlines() if ECHO in l and "--child-flag" in l and "--stdio" not in l]
check(rn["result"].get("isError") and "Risk=Destructive" in tn and not children, "cached destructive tool is blocked by Safe mode without spawning the bridge")
r = rpc2({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"py__peek","arguments":{"what":"lazy"}}}})
check(r["result"]["content"][0]["text"].startswith("echo:peek"), "first bridged call spawned the child and answered")
t = rpc2({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hub_status"}})["result"]["content"][0]["text"]
check("bridges=1 (1 running)" in t, "bridge running after the lazy start")
# the child dies: its tools stay and the next call starts a new one
kids = subprocess.run(["pgrep", "-P", str(hub2.pid)], capture_output=True, text=True).stdout.split()
for k in kids: os.kill(int(k), 9)
time.sleep(0.6)
r = rpc2({"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"py__peek","arguments":{"what":"again"}}})
check(len(kids) == 1 and r["result"]["content"][0]["text"].startswith("echo:peek"), "a bridge child that was killed is started again by the next call")
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
# clear_cache for one bridge (what the desktop sends to the other hubs after a sign-in), and for a name nobody has
s2.sendall((json.dumps({"type":"clear_cache","reqId":3,"bridge":"py"}) + "\n").encode()); ack3 = recv2("ack")
s2.sendall((json.dumps({"type":"clear_cache","reqId":4,"bridge":"nope"}) + "\n").encode()); ack4 = recv2("ack")
s2.sendall((json.dumps({"type":"get_status","reqId":5}) + "\n").encode()); st3 = recv2("status")
check(ack3["ok"] and ack4["ok"] and st3["cacheSize"] == 1 and st3["bridgesRunning"] == 1, "clear_cache with a bridge name re-lists that bridge and ignores an unknown one")
f2.close(); s2.close()
hub2.stdin.close(); hub2.wait(timeout=30)
check(hub2.returncode == 0, "second hub exited cleanly on EOF")

# ===================================================================== third run: no CLI bridge, config.json + reload_config
cfg_path = os.path.join(HOME, "config.json")
json.dump({"bridges": []}, open(cfg_path, "w"))
hub3 = subprocess.Popen([BIN, "--stdio", "--compact", "--control-trust-all"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
threading.Thread(target=lambda: [l for l in hub3.stderr], daemon=True).start()
def rpc3(obj):
    hub3.stdin.write(json.dumps(obj) + "\n"); hub3.stdin.flush()
    notes = []
    while True:
        m = json.loads(hub3.stdout.readline())
        if "method" in m: notes.append(m["method"]); continue
        return m, notes
rpc3({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ctl-test-3","version":"1"}}})
hub3.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub3.stdin.flush()
t, _ = rpc3({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hub_status"}})
check("bridges=0" in t["result"]["content"][0]["text"], "third run starts with no bridges")
json.dump({"bridges": [{"name": "py", "command": "python3", "args": [ECHO, "--child-flag"], "env": {"DEMO_KEY": "1"}}]}, open(cfg_path, "w"))
d3 = json.load(open(os.path.join(RUN, f"{hub3.pid}.json")))
s3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s3.connect(d3["socket"]); f3 = s3.makefile("r")
def recv3(t_):
    while True:
        m = json.loads(f3.readline())
        if m["type"] == t_: return m
recv3("hello")
s3.sendall((json.dumps({"type":"reload_config","reqId":1}) + "\n").encode())
tc3 = recv3("tools_changed"); ack3 = recv3("ack")
check(ack3["ok"] and ack3.get("bridges") == ["py"] and any(t_["name"] == "py__peek" for t_ in tc3["tools"]), "reload_config added the bridge from config.json and pushed tools_changed")
lst3, notes3 = rpc3({"jsonrpc":"2.0","id":3,"method":"tools/list"})
check(not any(t_["name"].startswith("py__") for t_ in lst3["result"]["tools"]) and "notifications/tools/list_changed" in notes3 + [], "compact: new bridge tools are on-demand, list_changed was pushed")
r3, _ = rpc3({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mcp_execute_tool","arguments":{"toolName":"py__peek","arguments":{"what":"cfg"}}}})
check(r3["result"]["content"][0]["text"].startswith("echo:peek"), "bridge from config.json answers")
s3.sendall((json.dumps({"type":"reload_config","reqId":2}) + "\n").encode()); ack3b = recv3("ack")
check(ack3b["ok"] and not ack3b.get("bridges"), "second reload adds nothing (idempotent)")
s3.sendall((json.dumps({"type":"cache_maintain","reqId":3}) + "\n").encode()); ack3c = recv3("ack")
check(ack3c["ok"], "cache_maintain ran VACUUM/ANALYZE/REINDEX")
f3.close(); s3.close(); hub3.stdin.close(); hub3.wait(timeout=30)
check(hub3.returncode == 0, "third hub exited cleanly")

# ===================================================================== fourth run: without --control-trust-all a plain process may not steer the hub
hub4 = subprocess.Popen([BIN, "--stdio", "--compact"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
hub4.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ctl-test-4","version":"1"}}}) + "\n"); hub4.stdin.flush()
while "method" in json.loads(hub4.stdout.readline()): pass
time.sleep(0.3)
desc4 = json.load(open(os.path.join(RUN, f"{hub4.pid}.json")))
s4 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s4.connect(desc4["socket"]); f4 = s4.makefile("r")
while json.loads(f4.readline())["type"] != "hello": pass
s4.sendall((json.dumps({"type":"set_mode","mode":"bypass","reqId":1}) + "\n").encode())
while True:
    ack4 = json.loads(f4.readline())
    if ack4["type"] == "ack": break
check(ack4["ok"] is False and "desktop app" in ack4["error"], f"set_mode from a non-desktop process is refused: {ack4['error'][:60]}")
s4.sendall((json.dumps({"type":"get_status","reqId":2}) + "\n").encode())
while True:
    st4 = json.loads(f4.readline())
    if st4["type"] == "status": break
check(st4["mode"] == "Safe", "mode unchanged after the refused command")
f4.close(); s4.close(); hub4.stdin.close(); hub4.wait(timeout=30)

# ===================================================================== fifth run: idle unlocked tools are hidden again
hub5 = subprocess.Popen([BIN, "--stdio", "--compact", "--no-control", "--auto-lock=2"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
notes5 = []
def rpc5(obj):
    hub5.stdin.write(json.dumps(obj) + "\n"); hub5.stdin.flush()
    while True:
        m = json.loads(hub5.stdout.readline())
        if "method" in m: notes5.append(m["method"]); continue
        return m
rpc5({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ctl-test-5","version":"1"}}})
hub5.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub5.stdin.flush()
rpc5({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mcp_search_tools","arguments":{"query":"git"}}})
names5 = [t["name"] for t in rpc5({"jsonrpc":"2.0","id":3,"method":"tools/list"})["result"]["tools"]]
check("git_smart_status" in names5, "search unlocked git_smart_status")
time.sleep(3.5)
names5b = [t["name"] for t in rpc5({"jsonrpc":"2.0","id":4,"method":"tools/list"})["result"]["tools"]]
check("git_smart_status" not in names5b and notes5.count("notifications/tools/list_changed") >= 2, f"auto-lock hid it again after 2 s idle and sent list_changed ({notes5.count('notifications/tools/list_changed')} notifications)")
hub5.stdin.close(); hub5.wait(timeout=30)

print("\n--- hub stderr (tail):"); print("\n".join(stderr_lines[-14:]))
sys.exit(0 if ok else 1)
