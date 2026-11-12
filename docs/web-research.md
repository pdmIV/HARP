# Oracle web research (experimental)

For query regressions, HTTP failure tests and live replays of sanitized log examples, see [CVE API validation](cve-api-validation.md). Offline results and live retrieval results are reported separately.

Enable **Web research (experimental)** in **Oracle model**, directly beneath adaptive reasoning, and save the oracle settings. It defaults off and applies only to new sessions. Existing sessions retain their captured configuration. Research supports Codex via MCP and hosted Z.AI, OpenAI, and NVIDIA NIM oracles. Explicit CVE discovery uses the official [CVE Search API](https://search.cve.org/api-docs/) without an API key; general web research uses Z.AI `search-prime` with the imported Z.AI key or `ZAI_API_KEY`. General-search entitlement and billing are separate from model access.

The setting is `oracle.web_search_enabled`, a JSON boolean. Disabled sessions never use these research tools. Enabling search does not make it automatic: the oracle must identify a specific missing fact that could change the next action. Ordinary reconnaissance and commands continue without research calls. The proxy can request oracle help for a documentation gap but has no independent search allowance in this first implementation. Unsloth server-side tools remain disabled.

## CVE discovery, date and goal relevance

Enabled sessions expose `research_profile` with the runtime's UTC date, current year, previous three years, assessment objective and reported product versions. The date is computed when research context/requests are built rather than hardcoded to a release year or taken from a model's training cutoff. Reported versions can be partial or ambiguous; the profile does not certify a package release.

The oracle should explicitly consider CVE and vendor-advisory discovery when a relevant exposed capability raises a vulnerability question. General mechanism documentation alone is not an advisory review. A standalone request can use:

```json
{"product":"ExampleProduct","feature":"document handler","alternatives":["document processing"],"kind":"cve","reason":"Find an advisory for the observed processing capability"}
```

`kind:cve` routes to `POST https://search.cve.org/webSearch` with up to three records, sorted by relevancy, and no date or severity filter. Prefer a short canonical `product` plus one or two distinctive mechanism/configuration words in `feature`; fields allow at most four words and two evidence-supported alternatives. HARP sends flat AND-matched keywords such as `ExampleProduct document handler`. The product and primary feature words are required, without exact adjacency. Alternatives inform the one permitted relaxation rather than an OR expression. Avoid access qualifiers, generic advisory prose, years, severity and guessed versions in discovery terms; evaluate those prerequisites after retrieval. General research still uses `query`. Legacy CVE strings are flat literal keywords without inferred products or automatic refinement. Boolean operators are rejected as input; punctuation tokens such as `C++` or `%J` in structured fields are individually quoted. See the official [raw-query contract](https://github.com/CVEProject/CVE-Search-API#raw-query-endpoint). Although the current upstream documentation describes Boolean syntax, the operator's two-round live capture returned 502 for the generated OR shapes across Samba, OpenSSH and Log4j while simple controls succeeded. Production therefore uses the proven simpler format. Metadata mentioning phrases does not by itself diagnose a malformed query.

After a successful structured query with exactly zero total matches, HARP may relax once to the product plus one supplied feature word, such as `ExampleProduct document`. It prefers the word occurring in the most distinct feature/alternative phrases, breaking ties by input order, and selects a query distinct from the primary. This never invents a synonym, emits an OR expression or becomes a product-only scan. Each attempt is a separate durable task with its own shared-budget reservation, source IDs and event log. The refinement consumes a second search slot but no extra oracle decision. It does not run after positive results, failed/malformed requests, an identical refinement, operator stop or exhaustion. Two empty results do not trigger further variation. Interrupted reservations and completed refinements are reused on resume rather than reissued. Equivalent legacy and structured wire queries share cached results; attaching a structured plan to a previously completed legacy zero permits only its normal bounded refinement, without repeating the primary. The event stream exposes `research_query_refined`, and returned context includes `wire_query`, `refinement_of` and `refinement_status`. Broadening is this single explicit exception to the no-rephrasing rule; it never switches providers. A 502 is a provider failure, not an empty result or evidence against a vulnerability. The oracle receives feedback to consider an explicit general documentation request or a discriminating prerequisite check; HARP does not silently retry or switch providers.

`year_scope` remains a candidate-assessment preference informed by the runtime year, not an API date filter. Known CVE-ID lookups default to `any`; changing only this preference reuses cached results. Prefer current-year candidates when relevance and applicability are comparable, while retaining older applicable CVEs. A focused general web search can resolve a remaining date/version-specific question.

The adapter accepts both direct CVE Records and OpenSearch `_source` wrappers. It retains descriptions, affected-version ranges/default status, source-attributed CVSS scores, publication dates, response metadata and total-hit counts. Three returned records are a bounded discovery page, not exhaustive coverage. Published records are candidates; rejected records are skipped. A CVE's identifier year is not proof of its publication date, affected version or current applicability.

Full CVE Records delivered in the search response are preserved as hashed source snapshots. Reading a returned record uses that snapshot without another network fetch, still consuming one of the task's two distinct source-read slots. Bounded advisory references receive their own source IDs; the oracle can explicitly read one through the normal Kali public-source reader. Reference pages are never crawled automatically. Conflicting CNA/ADP severity scores retain attribution instead of being silently merged or maximized.

Both providers share the four-search session limit, including failures, with three results and two source reads per task. The one structured zero-result refinement uses another of those four slots. HTTP failures, malformed/unsuccessful responses, redirects, unavailable endpoints and over-size responses fail explicitly without retry or paid-provider fallback. The oracle may choose a separately logged general search for a specific remaining fact. Both structured fields and compiled queries pass the target/secret checks.

Prefer vendor advisories, CVE records and NVD. Read affected/fixed branches, configuration and distribution backport information. Rank impact by the current goal and verified access rather than a fixed CVSS threshold:

| Current need | Potentially relevant impact | Lower priority without an enabling connection |
| --- | --- | --- |
| Initial access | Reachable execution, authentication bypass, credential disclosure | Local escalation requiring a foothold not yet obtained |
| Privilege escalation after user access | Applicable local escalation or protected-data access | Unrelated client-side issues |
| Resolve an access prerequisite | Disclosure that supplies a needed credential or configuration fact | Availability-only impact during a flag-capture assessment |

For a selected CVE, `check.research_basis.advisory_assessment` carries `cve_id`, `affected_versions`, `version_match` (`confirmed`, `unknown`, `contradicted`), `severity` (source score or `unknown`), `required_access`, `required_access_state` (`available`, `missing`, `unknown`), `goal_impact`, `goal_relevance` (`direct`, `enabling`, `none`, `unknown`) and `unmet_prerequisites`. These are model assessments, including the declared version match, and never verified target facts.

HARP audits whether the CVE ID occurred in a cited source that was actually read. It labels irrelevant, version-mismatched or access-blocked candidates `deprioritize`, unresolved candidates `verify_prerequisites`, and otherwise `candidate_for_verification`. A high score cannot override those conditions. The audit does not certify exploitation, execute a test or add an approval requirement.

## Oracle query selection and candidate review

Research context includes `query_selection_guidance`. The oracle compares its proposed phrases before issuing the first request, preferring source-supported configuration/consumption mechanisms, then confirmed processing capabilities, over broad resource labels. It chooses the primary `feature` itself. Model-suggested mechanisms remain hypotheses, and alternatives are not secretly queried following a positive response. No expected CVE IDs or product-specific term mappings are injected into query selection.

An existing oracle decision may include optional local audit metadata in `check.query_selection`:

```json
{"basis":"configuration","rationale":"This processing parameter is more discriminating than the resource name","source_ids":["RETURNED_SOURCE_ID"]}
```

`basis` is `configuration`, `mechanism`, `capability`, or `resource`. HARP logs the chosen primary, rationale, unused alternatives, whether cited sources were read, and warnings about resource-level or long AND queries. Missing audit metadata does not trigger an extra routing turn or reject an otherwise valid search. These fields are never sent to the public search provider.

The oracle can attach up to three `check.candidate_assessments` to an existing read, check or stop decision:

```json
[{"source_id":"RETURNED_SOURCE_ID","cve_id":"CVE-2099-12345",
  "mechanism_match":"matches","version_match":"unknown","goal_relevance":"direct",
  "required_access_state":"available","rationale":"The mechanism could advance the goal, but the packaged branch is unknown",
  "unmet_prerequisites":["Verify the effective configuration"],
  "next_verification":"Read the affected versions, then check one configuration prerequisite"}]
```

The example ID is synthetic. The actual CVE must be linked to that returned result or a successful source read. Assessments are persisted in `research.json` and exposed through `candidate_review`; duplicates need not be restated. They remain unverified model assessments and never enter the target capability ledger as confirmed facts.

The review card prioritizes mechanism/version/access/goal suitability ahead of severity or publication year. Contradicted mechanisms or versions, unavailable access and irrelevant impact receive `deprioritize`; unresolved fields and prerequisites stay explicit. A summary assessment can request `read_source`. Once that source is read, the card requests reassessment rather than silently promoting the earlier summary judgment. A fully assessed, sourced candidate is only `candidate_for_verification`, not verified exploitation. Candidate coverage remains incomplete when any returned candidate is unassessed; rejecting all returned candidates means `no_suitable_returned_candidate`, not no vulnerability in the product. The card includes omitted-candidate counts, and source-read context preserves bounded CVE mentions as unverified leads.

Invalid optional assessment metadata receives local feedback without forcing a full replan. Query and candidate audits accompany existing model decisions and add no model/provider calls. The selected advisory still uses `check.research_basis.advisory_assessment` for the source-to-test handoff. Four searches, two source reads per task, the separate 16-turn research allowance and the zero-result-only refinement rule remain unchanged.

Hosted search deduplication applies to search attempts, not cached text navigation. A `find` rejected before the first fetch can succeed after the source is read. Repeated cached reads/finds never refetch the URL or consume another source slot; a cached basic read preserves a previously delivered page for that same source. Invalid local requests no longer acknowledge a checkpoint before they are accepted. The oracle should stop navigating once it has the prerequisite and test details.

## Limits and context

| Control | Enforced behavior |
| --- | --- |
| Research task | One focused query, up to three returned sources |
| Source reads | At most two distinct source IDs per task, including failed attempts |
| Session limit | Four search attempts, including failures; unlimited execution does not remove this cap |
| Search timeout | 20 seconds; response limited to 128 KiB |
| Official CVE search | 20 seconds; at most three records and a 1 MiB response; no redirects or automatic paging |
| Source retrieval | Selected Kali transport, 25-second outer timeout, 2 MB response limit, at most three redirects |
| Retained extracted source | Up to 2,000,000 characters within the existing 2 MB response limit; truncation explicitly recorded |
| Returned source excerpt | Up to 6,000 characters, with extracted-text line references |
| Hosted oracle research context | At most 9,000 serialized characters; older tasks reduced to an index |
| Proxy research context | At most 3,000 serialized characters; may be omitted further during prompt compaction |
| MCP research replies | At most 6,000 serialized characters; cached searches do not resend previous document reads |
| Hosted research decisions | 16 per session, tracked separately from normal execution cycles and preserved across resumes |

These are character limits, not exact tokenizer counts. HARP uses lexical matching to select passages. No additional routing, extraction or summarization model is invoked. Research uses the normal oracle planning response; a search/read result is applied on the next oracle turn. A deterministic zero-result refinement does not add a model turn. Research decisions use the separate 16-turn allowance rather than the execution-cycle budget, while both search attempts still consume task slots. All inference costs remain in the oracle ledger.

Search caches are separated by provider and actual wire query, normalized for case/whitespace; each adapter fixes its endpoint, sorting and page size. Literal legacy input cannot collide with an equivalent-looking compiled Boolean expression. Source reads are cached by source ID and URL. Attempts are reserved before external work and survive resumes. No automatic refresh, failed-request retry or alternate provider is used. The one planned zero-result refinement is linked to its initial task before external work. Snapshots are retained for session reproducibility, not as a fresh global CVE mirror. Rejected research returns feedback without terminating viable execution. A process crash can leave `.research_lock`; review the stopped process before manually removing it.

## Oracle interface

Codex uses `web_search(session, reason=..., kind="cve", product=..., feature=..., alternatives=[...])`; general/legacy queries still use `query`. Structured fields and `query` are mutually exclusive. `year_scope` is optional. Source reads use `read_source(session, source_id, reason)`. Each reason identifies the missing information and its impact on the next step. Only source IDs returned by the session may be read.

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

For section navigation after a successful read, prefer an exact phrase search over a guessed offset:

```json
{"source_id":"SOURCE_ID","find":"Affected versions","match_index":0,"reason":"Locate the applicability section before selecting a test"}
```

`find` is a case-insensitive literal phrase, not a regular expression. The optional zero-based `match_index` selects an occurrence (0 through 63); replies include actual match offsets, short previews and a contiguous source page. `find` and `offset` are mutually exclusive. Phrase lookup uses cached text with no new provider request or source slot. Continue with `next_offset` for complete code, or choose another listed occurrence when the first is a table of contents. Hosted deduplication distinguishes different phrases and occurrences. Stop navigating once the needed prerequisite and test are available.

## Runtime and evidence

Search API requests originate in HARP's provider layer. CVE records already delivered by the official API are read from preserved snapshots. Other document reads run a bounded standard-library helper through the selected Kali transport: WSL, native Kali or Docker. The helper uses no root access and executes no downloaded code. It checks public destinations on every redirect, rejects local/lab addresses, and pins the validated destination address for the connection. It supports HTML, plain text and JSON, preserves code indentation, and extracts relevant lines. It does not render JavaScript, handle PDFs or acquire an executable PoC. Code acquisition and execution remain separate terminal tasks subject to the existing controls.

The selected runtime needs internet access for uncached source/reference reads. An isolated runtime can search through HARP's provider layer and read delivered CVE snapshots but may not fetch referenced pages; HARP reports that failure without changing runtimes or network settings.

Research is stored separately from target observations in `research.json` and `research_sources/`. Entries retain query/reason, source IDs and URLs, timestamps, source hashes, excerpts, errors, and truncation. Hashes describe the retrieved response bytes; line references describe the retained extracted text. Source claims are never automatically registered as verified artifacts, credentials, or flags. Target output and external pages remain untrusted, including any instructions embedded in them.

Query checks reject IP addresses, common key/flag patterns, HTB identifiers, discovered lab hostnames, and exact recorded credential/flag values. Known HTB walkthrough results are filtered by title and URL. These checks are heuristics, not a guarantee against secret disclosure or walkthrough contamination. The oracle must use public product/version/CVE details, not recovered secrets or box names.

The dashboard reports whether research is disabled, enabled but unused, in progress, completed, failed or interrupted. Replay reconstructs that state. Events and `research.json` retain provider identity, operation counts, latency, results and cache reuse. Usage exposes separate CVE/general search counts, source reads and actual source network requests; reading an API-delivered CVE snapshot increases reads without increasing network fetches. General-search charges remain **unknown** and are not added to model-token cost estimates. HARP does not fetch balances or infer billed rates. Research does not count as target terminal steps or human tactical intervention.

## Verification and evaluation

`tests/fixtures/cve_query_cases.json` contains public cross-product CVE examples plus a marked synthetic wording case. Expected IDs are test/evaluation data only and never enter oracle prompts or production queries. From a source checkout, score saved captures without calling a provider:

```bash
python scripts/evaluate_cve_queries.py --responses captures.jsonl --output query-evaluation.json
```

Each JSONL row has `case`, `attempts` (one or two saved research-task objects, optionally including their measured `seconds`) and optional `inference_cost_usd`. The report shows first-query/final hit-at-three rates, expected rank, known unrelated hits, search counts, latency, supplied inference cost and missing cases. Missing costs/timing stay unknown. Use matching saved baseline/new captures for a measured comparison; synthetic tests and this offline scorer do not demonstrate live retrieval quality or solve-rate gains by themselves.

Run:

```bash
python3 -m unittest discover -s tests -p test_research.py
node tests/test_web_ui.js
```

Tests use synthetic documents and mocked provider/transport responses. They cover the opt-in gate, request format, hosted continuation, configuration persistence, caching, durable budgets, failure handling, public-source checks, excerpt limits, and UI placement. They make no paid Z.AI calls. Live account access, real-site extraction quality, and solve-rate effects require a separate experiment.

Compare enabled and disabled runs on matching target snapshots, model settings, and budgets. Record verified success, total oracle/proxy tokens, research requests, source reads, cache hits, time, failures, and known search charges separately. Search may add inference turns and cost even when it helps solve a box; do not assume it saves tokens until measured.

## Evidence-based planning

Research-specific prompting and context are supplied only when the saved session toggle is enabled. When enabled, the oracle is encouraged to investigate a focused public vulnerability or configuration question raised by observed service capabilities before falling back to generic credential guessing. Research remains optional and subject to the existing budgets; no box names, intended solutions, CVE identifiers, or walkthrough queries are embedded in planning guidance. Disabled sessions continue to use target evidence and local tool documentation without research context or provider calls.

New hosted sessions expose a capability-derived research opportunity when research is enabled. `decision_checkpoint` marks a specific moment to choose research or a local prerequisite check. It first asks for a harmless submission check when a printer is merely exposed, then favors a focused mechanism search once submission succeeds. The choice and later check outcome are retained in the session and shown in the event stream. An inconclusive local check can reopen the choice once; a failed search is not a negative target result. The checkpoint is guidance, not an automatic paid request or an execution block. The oracle can record `check.research_decision` explaining a better retained-source or local check. Unknown versions do not prevent advisory research about the reachable operation.

After a source read, the oracle should translate the relevant passage into `check.research_basis`: source IDs, controlled input, execution sink, configuration prerequisites and one observable test. HARP records whether the cited sources were actually read and whether those fields are complete. This audit does not verify an external claim; the target check must still confirm applicability. Codex-as-oracle sees the same checkpoint through `inspect_session`. See [capability planning](capability-planning.md).
