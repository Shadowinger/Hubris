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
        send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":m["params"]["protocolVersion"],"capabilities":{"tools":{},"resources":{},"prompts":{}},"serverInfo":{"name":"echo-py","version":"0.1"}}})
    elif meth=="resources/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"resources":[{"uri":"py://hello","name":"hello","mimeType":"text/plain"}]}})
    elif meth=="resources/templates/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"resourceTemplates":[{"uriTemplate":"py://item/{id}","name":"item"}]}})
    elif meth=="resources/read":
        u=m["params"]["uri"]; send({"jsonrpc":"2.0","id":mid,"result":{"contents":[{"uri":u,"mimeType":"text/plain","text":"resource:%s token=abc123xyz" % u}]}})
    elif meth=="prompts/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"prompts":[{"name":"greet","arguments":[{"name":"who","required":True}]}]}})
    elif meth=="prompts/get":
        send({"jsonrpc":"2.0","id":mid,"result":{"messages":[{"role":"user","content":{"type":"text","text":"hi %s" % m["params"].get("arguments",{}).get("who","")}}]}})
    elif meth=="tools/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"tools":tools}})
    elif meth=="tools/call":
        p=m["params"]; sys.stderr.write("child executing %s\n" % p["name"]); sys.stderr.flush()
        send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"echo:%s:%s" % (p["name"], json.dumps(p.get("arguments")))}]}})
    elif mid is not None:
        send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"nope"}})
