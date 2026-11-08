# Oracle web research (experimental)

Enable **Z.AI web search (experimental)** in **Oracle model**, directly beneath adaptive reasoning, and save the oracle settings. It defaults off and applies only to new sessions. Existing sessions retain their captured configuration. Research supports Codex via MCP and hosted Z.AI, OpenAI, and NVIDIA NIM oracles; the search provider is always Z.AI `search-prime`, using the existing imported Z.AI key or `ZAI_API_KEY`. Account entitlement and search billing must be verified separately from model access.

The setting is `oracle.web_search_enabled`, a JSON boolean. Disabled sessions never use these research tools. Enabling search does not make it automatic: the oracle must identify a specific missing fact that could change the next action. Ordinary reconnaissance and commands continue without research calls. The proxy can request oracle help for a documentation gap but has no independent search allowance in this first implementation. Unsloth server-side tools remain disabled.

## Limits and context

| Control | Enforced behavior |
| --- | --- |
| Research task | One focused query, up to three returned sources |
| Source reads | At most two distinct source IDs per task, including failed attempts |
| Session limit | Four search attempts, including failures; unlimited execution does not remove this cap |
| Search timeout | 20 seconds; response limited to 128 KiB |
| Source retrieval | Selected Kali transport, 25-second outer timeout, 2 MB response limit, at most three redirects |
| Retained extracted source | Up to 2,000,000 characters within the existing 2 MB response limit; truncation explicitly recorded |
| Returned source excerpt | Up to 6,000 characters, with extracted-text line references |
| Hosted oracle research context | At most 9,000 serialized characters; older tasks reduced to an index |
| Proxy research context | At most 3,000 serialized characters; may be omitted further during prompt compaction |
| MCP research replies | At most 6,000 serialized characters; cached searches do not resend previous document reads |
| Hosted research decisions | 16 per session, tracked separately from normal execution cycles and preserved across resumes |

These are character limits, not exact tokenizer counts. HARP uses lexical matching to select relevant passages. No additional routing, extraction, or summarization model is invoked. Research actions use the normal oracle planning response; each search or read requires another oracle turn to apply the result. Research decisions consume the separate 16-turn research allowance rather than the normal execution-cycle budget. All model calls and their inference costs remain in the oracle ledger. Older logs without the separate research-turn event retain their original cycle accounting.

Search queries are cached after case and whitespace normalization. Source reads are cached by source ID, with extracted documents additionally cached by URL within the session. Successful and failed attempts are reserved on disk before external work and survive resumes. No TTL, automatic refresh, retry, alternate provider, or query broadening is applied. An interrupted attempt retains its reservation and is not rerun automatically. Repeated or rejected hosted research actions return feedback so the oracle can continue with evidence or report a specific blocker. If the oracle keeps requesting research after exhausting its 16-turn allowance, it stops with `research_no_progress`; legitimate execution remains available when the oracle selects it. A process crash can leave `.research_lock`; review the stopped process before manually removing that lock. Session-local caching avoids sharing sensitive research or stale documents between unrelated runs.

## Oracle interface

Codex uses `web_search(session, query, reason)` and `read_source(session, source_id, reason)`. Each reason must identify the information needed and why it matters. Only source IDs returned by the current session's search may be read.

Hosted oracles return a standalone research decision through their existing JSON response:

```json
{
  "plan": "Check the documented prerequisites before selecting a route",
  "objective": "",
  "stop": false,
  "research": {
    "query": "ExampleProduct 2.0 authentication documentation",
    "reason": "Confirm whether this route requires an authenticated session"
  }
}
```

To read a result, replace the query with `"source_id":"ID returned by search"`. Do not combine research with a terminal command, implementation, delegation objective, or stop decision. Full source URLs remain in the research registry and event log; model context uses compact source IDs and site names. The next ordinary delegation should reference the useful findings and their source IDs.

## Continuing an important chain

Search and source-fetch limits restrict further internet access, not the entire assessment. An exhausted task/source budget returns `research_feedback` to the hosted oracle without automatically ending its execution loop. It can use retained evidence, delegate verification, choose another valid action within remaining limits, or explain the actual missing prerequisite. Codex receives the tool error directly and can make the same decision. These limits do not authorize additional searches merely because the model labels them important.

An excerpt is not the complete exploit or document. After a successful source read, request a bounded contiguous page of the retained extracted text when prerequisite steps or code are missing:

```json
{"source_id":"SOURCE_ID","offset":0,"reason":"Read the full prerequisite sequence before using the published implementation"}
```

Codex passes `offset` as an optional argument to `read_source`; hosted oracles use this object as their standalone `research` action. `offset` is a zero-based character position in retained extracted text. Follow the exact returned `next_offset`, or seek a specific character position, until the important section is complete. Pages have a bounded serialized size, include the source hash and total character count, and consume no additional network fetch or source slot. The requested page is prioritized in hosted oracle context; proxy context can still omit it explicitly to fit the proxy budget. The oracle should supply a complete implementation through the existing handoff when necessary. Do not execute fragments assembled from incomplete excerpts.

Full retained text now extends beyond the old 80,000-character cutoff up to the existing response-size limit. `source_truncated`, `context_omissions`, and pagination markers disclose incomplete coverage. Existing cached documents created under the old cutoff remain truncated and are not silently refetched. Oversized or unsupported sources, real execution budgets, operator stop, root approvals, and repeated unproductive behavior can still block a chain. These safeguards remain in effect.

## Runtime and evidence

Search API requests originate in HARP's provider layer. Document reads run a bounded standard-library helper through the session's selected Kali transport: WSL, native Kali, or Docker. The helper uses no root access and executes no downloaded code. It checks public destinations on every redirect, rejects local/lab addresses, and pins the validated destination address for the connection. It supports HTML, plain text, and JSON. It removes common HTML navigation and script/style content, preserves code indentation, and extracts relevant lines. It does not render JavaScript, handle PDFs, or acquire an executable PoC. Relevant source code may be read as text; actual code acquisition and execution remain separate terminal tasks subject to the existing controls.

The selected runtime needs internet access for source reads. An isolated Docker runtime can search via HARP's provider layer but cannot necessarily fetch the sources; HARP reports that failure without changing runtimes or network settings.

Research is stored separately from target observations in `research.json` and `research_sources/`. Entries retain query/reason, source IDs and URLs, timestamps, source hashes, excerpts, errors, and truncation. Hashes describe the retrieved response bytes; line references describe the retained extracted text. Source claims are never automatically registered as verified artifacts, credentials, or flags. Target output and external pages remain untrusted, including any instructions embedded in them.

Query checks reject IP addresses, common key/flag patterns, HTB identifiers, discovered lab hostnames, and exact recorded credential/flag values. Known HTB walkthrough results are filtered by title and URL. These checks are heuristics, not a guarantee against secret disclosure or walkthrough contamination. The oracle must use public product/version/CVE details, not recovered secrets or box names.

The live event stream and saved replay display research starts, results, failures, and cache reuse. `research.json` records operation counts, latency, and returned characters. Session views also expose separate research usage counts. Search charges remain **unknown**, not zero, and are not added to model-token cost estimates. This version does not fetch an account balance or infer billed search rates. Search and source reads do not count as target terminal steps or human tactical intervention.

## Verification and evaluation

Run:

```bash
python3 -m unittest discover -s tests -p test_research.py
node tests/test_web_ui.js
```

Tests use synthetic documents and mocked provider/transport responses. They cover the opt-in gate, request format, hosted continuation, configuration persistence, caching, durable budgets, failure handling, public-source checks, excerpt limits, and UI placement. They make no paid Z.AI calls. Live account access, real-site extraction quality, and solve-rate effects require a separate experiment.

Compare enabled and disabled runs on matching target snapshots, model settings, and budgets. Record verified success, total oracle/proxy tokens, research requests, source reads, cache hits, time, failures, and known search charges separately. Search may add inference turns and cost even when it helps solve a box; do not assume it saves tokens until measured.
