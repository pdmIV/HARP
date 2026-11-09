# Managed Whippet batch queries

HARP implements Whippet 0.7+'s NDJSON protocol directly, using its independently
installed pipx executable. No Whippet Python dependency is added to HARP.
Readiness protocol 1 and report schema 1 are required.
Whippet 0.8's `handoff` mode is available when the readiness mode list advertises it.

## Model entry points

Codex calls the `whippet_query` MCP tool with these arguments:

```json
{"session":"runs/SESSION","inputs":["bloodhound.zip"],"request":{"mode":"triage","node":"USER@LAB.HTB","limit":3}}
```

Hosted oracles delegate query objectives to the proxy. The proxy can return this
action instead of a shell command:

```json
{"thought":"Inspect the current account's collected ACL leads","whippet_query":{"inputs":["bloodhound.zip"],"request":{"mode":"findings","query":"acl-control","principal":"USER@LAB.HTB","limit":3}},"done":false}
```

After triage, request one complete Whippet 0.8 lead with
`{"mode":"handoff","node":"USER@LAB.HTB","query":"acl-control","lead_index":0}`.
The `assessment.live_access` state is unverified offline; retain its proof,
coverage, prerequisites and next verification question. An empty route's
`route_diagnostic` does not invalidate earlier findings. HARP does not expose
Whippet's trusted-host live overlay to models.

The shared instruction card teaches both routes. Queries count against proxy
step/model budgets and use the normal observation/context-compaction paths.
Oracle queries are disabled in proxy-only mode. No batch process starts during
recon, on unrelated targets, or before capture files are supplied.

Supply 1 through 32 explicit regular files, including optional Certipy JSON.
Paths are resolved inside the selected Kali runtime and must remain under its
session workspace after resolving symlinks. Directories are not accepted.
Both models receive the exact `workspace` in their context. Put collector output
there and reuse the captures. A path or query validation rejection executes no
graph query: the proxy receives feedback and one correction opportunity before
handing the problem back to the oracle. It does not require `refresh` or a switch
to CLI. Runtime/transport failures still stop and require explicit review.
HARP hashes the files inside Kali before each query. Unchanged inputs reuse one
process/graph; changed content or input paths close the old process and start a
fresh graph before executing the new query. Requests run as the session user,
with argument arrays rather than interpolated shell commands.

Identical successful requests reuse a bounded in-process response cache for that
capture snapshot. Cache hits retain the original response ID, proof and paging,
add `harp_cache.reused`, and log `whippet_batch_cache_hit`; they do not send another
query to Whippet. Errors and liveness pings are not cached. Changed capture content,
new inputs or explicit refresh retire the cache along with the graph. Recent query
arguments and report references are included in `whippet_query_history` so models
can reuse evidence or ask for one handoff/page instead of repeating broad queries.

One-shot Whippet commands preceded by shell setup such as `cd ... && whippet ...`
also use structured report storage and whole-item compaction when their output
contains a complete report. Host-side report references are not Kali paths.

Modes: `summary`, `triage`, `objects`, `findings`, `node`, `search`, `memberships`,
`members`, `users`, `reachable`, `path`, `routes`, `ranked-paths`, `explain`,
`gpo-scope`, `trust-path`, `catalog`, and `ping`, subject to advertised server modes.
Ranked paths require Whippet's optional NetworkX dependency. Prefer bounded
collections, projected properties, and supported-profile routes. Conditional
leads remain unverified and must retain their proof and prerequisites.

## Transport and lifecycle

HARP starts `whippet CAPTURES --batch --batch-ready` inside its selected runtime.
Startup has a 60-second deadline. Query response wait is capped at the session
command timeout or 60 seconds, whichever is smaller. Requests receive unique
HARP-generated IDs. Every response must match its request ID, Whippet session ID,
and increasing request index. Only one query may be in flight.

Responses are limited to 8 MiB of JSON characters, independently of the smaller
model context allowance. Stderr is drained separately into a bounded diagnostic
buffer. Full requests/responses, snapshot checks, readiness, timings, response
bytes, errors, cleanup and exit enter HARP's event log. Responses use the existing
SHA-256 report storage and structured compaction. Context events record result
text included in model requests; model usage events retain total token costs.

Query errors leave the process usable. Timeout, EOF, malformed JSON, incompatible
handshake or correlation mismatch closes it and stops the proxy with an oracle
help request. There is no automatic retry or runtime fallback. After reviewing
the error, set `refresh: true` in the MCP tool arguments or proxy query action
to start a new process. Missing batch support records an instruction to use the
existing one-shot CLI or installed alternatives.

A session manifest prevents another HARP launcher from silently starting a second
connection. Explicit refresh retires the old connection through the selected
runtime. Connections persist across delegations in hosted-oracle/MCP processes;
standalone Python invocations close them on normal exit. No Kali service is
installed. Older session records without batch capability metadata are checked
again when the proxy or hosted oracle next runs.

Cancellation/session finish closes stdin for graceful EOF, then verifies
runtime-side exit using a process marker and Linux PID/start-time identity. Hung
process groups are terminated as the same Kali user. HARP does not infer cleanup
from the Windows launcher exiting. Failed cleanup retains its manifest and
reports an error. Session finish requires verified cleanup before removing the
Docker runtime. Abrupt host termination can leave a runtime process; explicit
refresh or session finish uses the saved marker to clean it up.

## Verification and limits

Run `python -m unittest discover -s tests -v`. Batch transport tests use a real
synthetic subprocess to exercise reuse, protocol correlation, query-error
recovery, cancellation, timeouts, oversized responses and cleanup. They check
selected-runtime argument construction and compile the Linux lifecycle scripts.
They do not establish live WSL/Docker process cleanup or an HTB solve.

Batch reuse reduces graph-loading overhead. Focused queries and property
projection reduce model input. Measure both with completion rate and missed leads
before claiming end-to-end savings. Hashing captures before each query also has
a cost that should be included in evaluation.
