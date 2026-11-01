import sys, json
def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
tools = [
  {"name":"shell","description":"Run a shell command","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}},
  {"name":"nuke","description":"Delete everything","inputSchema":{"type":"object","properties":{}},"annotations":{"destructiveHint":True}},
  {"name":"peek","description":"Read something","inputSchema":{"type":"object","properties":{"what":{"type":"string"}}},"annotations":{"readOnlyHint":True}},
]
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    m=json.loads(line)
    meth=m.get("method"); mid=m.get("id")
    if meth=="initialize":
        send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":m["params"]["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"echo-py","version":"0.1"}}})
    elif meth=="tools/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"tools":tools}})
    elif meth=="tools/call":
        p=m["params"]; sys.stderr.write("child executing %s\n" % p["name"]); sys.stderr.flush()
        send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"echo:%s:%s" % (p["name"], json.dumps(p.get("arguments")))}]}})
    elif mid is not None:
        send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"nope"}})
