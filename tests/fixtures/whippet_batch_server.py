"""Portable NDJSON peer for testing HARP transport without Kali or Whippet installed."""
import json
import os
from pathlib import Path
import sys
import time

root, token, behavior = sys.argv[1:4]
Path(root, ".fake-" + token + ".pid").write_text(str(os.getpid()))
session = "test-" + token
print("collector diagnostic", file=sys.stderr, flush=True)
print(json.dumps({"schema_version": 1, "protocol_version": 2 if behavior == "bad-ready" else 1,
                  "event": "ready", "session_id": session,
                  "modes": ["triage", "handoff", "ping", "shutdown", "node", "objects"],
                  "max_request_characters": 65536}), flush=True)
index = 0
for line in sys.stdin:
    request = json.loads(line)
    if behavior == "timeout":
        time.sleep(60)
    if behavior == "eof":
        break
    if behavior == "malformed":
        print("broken-json", flush=True)
        continue
    index += 1
    response = {"schema_version": 1, "id": request["id"], "mode": request["mode"],
                "batch": {"session_id": session, "request_index": index, "elapsed_ms": .01},
                "warnings": [], "unresolved_nodes": 0,
                "result": {"status": "ready", "items": [{"source": "USER", "target": "SVC", "type": "GenericAll"}],
                           "total": 1, "offset": 0, "next_offset": None, "truncated": False}}
    if request["mode"] == "handoff":
        response["result"] = {"lead": {"source": "USER", "target": "SVC", "proof": [{"edge": "GenericAll"}]},
                              "assessment": {"live_access": {"status": "unverified"},
                                             "unverified_prerequisites": ["Check effective right"]},
                              "coverage": {"profile": "supported"}, "total_leads": 1,
                              "next_lead_index": None}
    if request.get("node") == "MISSING":
        response.pop("result")
        response["error"] = "Unknown node"
    if behavior == "bad-id":
        response["id"] = "wrong"
    if behavior == "bad-index":
        response["batch"]["request_index"] += 1
    if behavior == "oversize":
        response["result"]["huge"] = "x" * 10000
    print(json.dumps(response), flush=True)
