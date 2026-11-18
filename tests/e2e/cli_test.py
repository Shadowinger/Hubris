"""End-to-end test of the commands (status, tools, watch, mode, approve, deny, bridge): they are run as a person would run them, against real hubs."""
import json, os, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
ECHO = os.path.join(HERE, "echo_server.py")
BIN = sys.argv[1]

ok = True
def check(cond, msg):
    global ok
    print(("PASS " if cond else "FAIL ") + msg)
    ok = ok and cond

def start(*flags, name):
    hub = subprocess.Popen([BIN, "--stdio", "--compact", "--approval-timeout=20", *flags, "--bridge=py:python3", ECHO],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    hub.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":name,"version":"1"}}}) + "\n"); hub.stdin.flush()
    hub.stdout.readline()
    hub.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n"); hub.stdin.flush()
    return hub

def call(hub, rid, name, args):
    hub.stdin.write(json.dumps({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}}) + "\n"); hub.stdin.flush()
def response(hub, rid):
    while True:
        m = json.loads(hub.stdout.readline())
        if m.get("id") == rid: return m

def cli(*args, env=None):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout, r.stderr

open_hub = start("--control-trust-all", name="cli-test")   # takes commands from any local process
shut_hub = start(name="cli-shut")                           # the default: only the desktop app may change it
for _ in range(100):
    code, out, _ = cli("status")
    if f"hub {open_hub.pid} · cli-test 1" in out and f"hub {shut_hub.pid} · cli-shut 1" in out: break
    time.sleep(0.1)

# --- status and tools
check(code == 0 and f"hub {open_hub.pid} · cli-test 1 · Safe mode" in out and f"hub {shut_hub.pid} · cli-shut 1 · Safe mode" in out, "status lists both hubs with client and mode")
check("3 of 8 tools listed" in out and "1 configured" in out, "status shows the context cost and the bridges")
code, out, _ = cli("status", f"--pid={shut_hub.pid}")
check(code == 0 and f"hub {shut_hub.pid}" in out and f"hub {open_hub.pid}" not in out, "--pid picks one hub")
code, out, _ = cli("tools", "py__", f"--pid={open_hub.pid}")
check(code == 0 and "py__shell" in out and "hidden" in out and "hub_status" not in out and "3 tools" in out, "tools filters by name and says what is hidden")
code, out, _ = cli("status", "--pid=1")
check(code == 0 and "hub 1 is not running" in out, "status for a pid that is not a hub says so")

# --- watch sees the approval request; approve from another process lets the call through
watch = subprocess.Popen([BIN, "watch", f"--pid={open_hub.pid}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
seen = []
threading.Thread(target=lambda: [seen.append(l.rstrip()) for l in watch.stdout], daemon=True).start()
def saw(text, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        for l in seen:
            if text in l: return l
        time.sleep(0.05)
    return None
check(saw("hub       cli-test 1 · Safe mode") is not None, "watch greets with the hub it follows")

call(open_hub, 10, "py__shell", {"cmd": "rm -rf /tmp/x"})
line = saw("approval  ")
approval = line.split()[3] if line else ""
check(approval.startswith(f"{open_hub.pid}-") and "py__shell" in line, f"watch shows the waiting call and its id ({approval})")
code, out, _ = cli("status", f"--pid={open_hub.pid}")
check(f"waiting   {approval}  py__shell" in out, "status lists the waiting approval")
code, out, _ = cli("approve", approval)
res = response(open_hub, 10)
check(code == 0 and "approved" in out and not res["result"].get("isError") and res["result"]["content"][0]["text"].startswith("echo:shell"), "approve -> the call ran")
check(saw(f"resolved  {approval}  py__shell  approved") is not None and saw("call      py__shell  ") is not None, "watch shows the decision and the call")

call(open_hub, 11, "py__shell", {"cmd": "rm -rf /tmp/y"})
second = f"{open_hub.pid}-{int(approval.split('-')[1]) + 1}"
check(saw(f"approval  {second}  py__shell") is not None, "the next waiting call gets the next id")
code, out, _ = cli("deny", second)
res = response(open_hub, 11)
check(code == 0 and res["result"].get("isError") and "Denied by the user" in res["result"]["content"][0]["text"], "deny -> the call is refused with the reason")
code, _, err = cli("approve", approval)
check(code == 1 and "no pending approval" in err, "an approval that is already decided is reported, exit code 1")
code, _, err = cli("approve", "nonsense")
check(code == 2 and "not an approval id" in err, "an id that is not one is a usage error")

# --- mode
code, out, _ = cli("mode", "auto", f"--pid={open_hub.pid}")
check(code == 0 and "Auto mode" in out and saw("mode      Auto") is not None, "mode auto switches the hub; watch shows it")
code, out, err = cli("mode", "bypass")
check(code == 1 and f"hub {open_hub.pid}: Bypass mode" in out and f"hub {shut_hub.pid}: refused" in err and "desktop app" in err,
      "mode to every hub: the one that trusts local processes switches, the default one refuses, exit code 1")
code, out, _ = cli("status")
check(f"hub {open_hub.pid} · cli-test 1 · Bypass mode" in out and f"hub {shut_hub.pid} · cli-shut 1 · Safe mode" in out, "status confirms: only the trusting hub changed")
code, _, _ = cli("mode", "nonsense")
check(code == 2, "an unknown mode is a usage error")

# a hub that refuses commands from here must not hold a blocked call for an approval nobody can give
t0 = time.time()
call(shut_hub, 20, "py__shell", {"cmd": "rm -rf /tmp/z"})
res = response(shut_hub, 20)
check(res["result"].get("isError") and "SAFE MODE BLOCKED" in res["result"]["content"][0]["text"] and time.time() - t0 < 5, "the default hub blocks at once: a command-line listener is not somebody who can approve")

# --- watch ends when its hub does
open_hub.stdin.close(); open_hub.wait(timeout=30)
try: watch.wait(timeout=10)
except subprocess.TimeoutExpired: watch.kill(); check(False, "watch --pid ends when the hub exits")
else: check(any(l.endswith("closed") for l in seen), "watch --pid ends when the hub exits and says it closed")
shut_hub.stdin.close(); shut_hub.wait(timeout=30)
code, out, _ = cli("status")
check(code == 0 and "no hub is running" in out, "status with no hub says so")

# --- bridge: its own home, so the config of the other suites is not touched
env = dict(os.environ, HUBRIS_HOME=tempfile.mkdtemp())
code, out, _ = cli("bridge", "list", env=env)
check(code == 0 and "no bridges" in out, "bridge list on an empty config")
code, out, _ = cli("bridge", "add", "py", "python3", ECHO, "--verbose", env=env)
check(code == 0 and "added 'py'" in out, "bridge add")
code, out, _ = cli("bridge", "list", env=env)
check(code == 0 and out.startswith("py  stdio  python3 ") and "--verbose" in out, "bridge list shows it with the child's own --verbose")
hub = subprocess.Popen([BIN, "--stdio", "--no-control"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
hub.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"cli-test","version":"1"}}}) + "\n"); hub.stdin.flush()
hub.stdout.readline()
hub.stdin.write(json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/list"}) + "\n"); hub.stdin.flush()
check("py__peek" in [t["name"] for t in response(hub, 2)["result"]["tools"]], "a hub started afterwards serves the bridge that was added")
hub.stdin.close(); hub.wait(timeout=30)
code, _, err = cli("bridge", "add", "py", "other", env=env)
check(code == 1 and "already" in err, "bridge add refuses a name that is taken")
code, out, _ = cli("bridge", "remove", "py", env=env)
check(code == 0 and "removed 'py'" in out and "no bridges" in cli("bridge", "list", env=env)[1], "bridge remove")
code, _, err = cli("bridge", "frobnicate", env=env)
check(code == 2 and "usage" in err, "an unknown bridge command is a usage error")

sys.exit(0 if ok else 1)
