"""Paced MCP client: sends one request, waits for its response (printing any notifications), then the next."""
import json, subprocess, sys
reqfile, cmd = sys.argv[1], sys.argv[2:]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
for raw in open(reqfile):
    raw = raw.strip()
    if not raw: continue
    p.stdin.write(raw + "\n"); p.stdin.flush()
    want = None
    try: want = json.loads(raw).get("id", None)
    except ValueError: pass
    if "id" not in raw and want is None: continue  # notification: nothing to wait for
    while True:
        line = p.stdout.readline()
        if not line: sys.exit("server closed stdout early")
        sys.stdout.write(line)
        m = json.loads(line)
        if "method" in m: continue  # server notification
        if m.get("id") == want or (want is None and m.get("id") is None): break
p.stdin.close(); p.wait(timeout=30)
sys.stderr.write(p.stderr.read())
