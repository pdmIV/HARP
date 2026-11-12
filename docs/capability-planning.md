# Capability-based planning and scoped outcomes

HARP retains a source-linked capability ledger alongside raw terminal output. It separates authentication, resource permissions, exposed operations, protocol errors and local tool errors. A denied share does not invalidate another resource's successful operation. Expected denials are findings, not a global `null_auth_denied` stop. Historical events with that stop reason are labeled as legacy stops in the dashboard.

Each parsed outcome records host, principal, resource, operation, status, evidence reference and a bounded exact output excerpt. Unknown scope stays unspecified. The adapters recognize common SMB/RPC, Nmap and HTTP results; unfamiliar formats remain available as raw observations. Automatic extraction is deliberately conservative and is not a complete protocol parser or proof of exploitability. Source pages and model hypotheses never become terminal-confirmed capabilities.

The dashboard's **Attack Surface** tab, directly below Artifacts, shows open services, scoped capability outcomes, and prerequisite checks. Reconnaissance product and version findings appear with their service rather than being repeated as operations. The oracle/proxy context also exposes the ledger. Saved replay derives the tab from observations available at that point, without reading future evidence into earlier frames or modifying a saved session. The summary can omit older findings to stay bounded; the tab states how many were omitted and points to Verbose activity for the full terminal record.

## New-session planning contract

New sessions capture `planning_protocol: 2`. Hosted oracles provide a concise `check` for each continuing decision. Older saved sessions retain compatibility with their earlier decision contract; the new guidance and scoped outcomes still apply. A stop decision does not require a check.

```json
{
  "plan": "Test the prerequisite exposed by the observed capability",
  "objective": "Perform one bounded prerequisite check",
  "stop": false,
  "check": {
    "action": "validate_hypothesis",
    "hypothesis": "The exposed operation may depend on an unsafe configuration",
    "fact": "feature.configuration",
    "resource": "service",
    "principal": "anonymous",
    "evidence": [{"observation": 1, "quote": "exact retained output"}],
    "expected_positive": "The configuration prerequisite is observed",
    "expected_negative": "This prerequisite remains unconfirmed"
  }
}
```

Actions are `enumerate`, `fingerprint`, `validate_hypothesis` and `credential_validation`. `research` is advertised only when the session's saved research toggle is enabled. Evidence references use one-based terminal observation indexes and exact quotes, or a one-based `recon` index. The schema validates references and execution intent; it does not certify the oracle's hypothesis or request private reasoning.

Repeated checks for the same action/fact/resource/principal need `retry_reason` describing changed evidence or a specific transport limitation. Only executed checks consume the fingerprint effort budget. Two fingerprint checks without an observed release leave the fact `not_observable` **through the attempted probes**, rather than absent or patched. Other capability checks remain available. Keep stable fact and resource names across equivalent tools. Different access or a genuinely different evidence source should be described explicitly rather than relabeling the same probe.

With research enabled, confirmed reachable capabilities produce a research opportunity card. A high-priority `decision_checkpoint` also appears when an exposed operation needs a choice between a focused public fact and a discriminating local prerequisite check. An exposed printer first favors a harmless submission check. A confirmed submission moves the checkpoint to the print mechanism and favors research before payload crafting. Successful source reads create a source-to-test checkpoint. The oracle can choose a better local check and briefly explain that choice in `check.research_decision`; HARP records the choice without blocking it. A missing exact version does not block product/capability/advisory research. Existing query privacy, source caching and research budgets remain in force. Disabled sessions receive neither card nor research-specific instructions, and cannot call the provider. Evidence quotes are checked against recorded terminal output after ANSI color codes are removed, so display formatting cannot invalidate an otherwise exact quote.

Each executed check now records a scoped `observed_outcome`: positive, negative, tool error, transport error, or inconclusive, with source-linked output when the parser can classify it. An unsuccessful local check can reopen the research choice once; a tool or callback failure is not proof that the target lacks a prerequisite. Successful SMB print submission is recognized even when `smbclient -c` contains semicolon-separated commands. A previously confirmed submission supersedes the lower-priority exposed-printer checkpoint for the same resource.

After a source read, `check.research_basis` can carry `source_ids`, `controlled_input`, `execution_sink`, `configuration_prerequisites`, and `observable_test`. HARP audits that the cited source was read and records whether the fields are complete. This audit does not turn the source into target evidence or prevent an otherwise valid check. Verify the claimed prerequisite in the selected target runtime before treating it as applicable.

If three successive hosted-oracle plans fail strategy validation while a research opportunity and research allowance remain, HARP gives the oracle one explicit step-back turn before stopping. The feedback asks it to reconsider the exposed capability and unknown prerequisites, choose one focused public research action if a missing fact could change the next step, or repair the evidence-backed local check. A fourth invalid plan still stops the run. This recovery does not automatically spend a search or override the operator stop and execution budgets.

Credential validation is an explicit action with terminal-cited candidates and a small total attempt cap. Incidental words in plans, prohibitions such as “do not spray passwords,” and unused empty credential metadata do not make another action a credential test. Recognizable password-file execution still requires candidate evidence. This is a planning guard, not a security sandbox for arbitrary shell programs.

Rejected strategy events retain the public structured decision and validation reason so failures can be audited. They do not retain the provider's private reasoning text.

## Execution and progress

Timing and callback checks must identify the observation path. A fast submission acknowledgement is not automatically a measurement of backend completion. Without evidence of synchronous processing or a visible backend result, no delay means only no delay observed for those inputs. Likewise, callback silence requires a verified delivery/listener path before it can support a negative conclusion. HARP preserves a limitation note on non-positive hypothesis checks and keeps unclassified no-signal results inconclusive. It does not turn a proxy interpretation into a verified absence of vulnerability. A client upload message does not prove internal server filenames or shell quoting; UDP `open|filtered` is inconclusive.

Use one discriminating check instead of bundling unrelated enumeration. Reuse complete output already in context and respect reported file lengths when requesting another slice. Adaptive-effort recommendations use high for ordinary enumeration, source navigation and switching capability after a negative test. Max is reserved for a specific unresolved conflict, complex implementation/debugging or interacting prerequisites; lack of success alone is not an escalation criterion. This changes recommendation guidance, not a fixed operator-selected effort or the existing adaptive floor.

The default interpreter remains `/bin/sh`. A command action or oracle implementation may explicitly select `"shell":"bash"`. HARP wraps it in a logged `/bin/bash` heredoc and checks the body with `bash -n`; the default path uses `sh -n`. Bash availability is determined by those normal runtime checks, with no silent interpreter fallback. The selected shell's parser decides syntax validity. When an active array substitution is found, HARP additionally tests a fixed, unset array variable in the runtime's `sh`; the proposed command never runs during this check. A supporting `sh` implementation may proceed. Single-quoted literals, comments, escaped expressions and quoted heredoc data do not trigger it. Other Bash-like text patterns remain repair hints, not vetoes or reasons to change the interpreter. A proxy must include the shell selector in its JSON action; mentioning Bash in prose does not select it. Syntax-check failures require correction and cannot be approved through tactical command review, even when another review warning exists. Three consecutive validation failures return control to the oracle without consuming command execution steps. Preflight is not a complete shell interpreter; options, tools and other expansions can still fail at runtime. Scope validation and exact root approval still apply to the complete logged command.

Generated shell helpers must use distinct inner/outer heredoc delimiters. HARP rejects the recognized collision before writing or launching the helper. Use simple local staging names, supply unusual remote filenames separately, and verify an input exists before upload. Local creation/upload errors remain tool errors even when a trailing command returns zero; the proxy receives corrective feedback before its next action. Callback silence after such a failure is not negative target evidence.

Oracle descriptive check fields and `research_decision` accept up to 4096 characters without truncation. Aim for about 500 to keep context small. Resource and principal fields remain limited to 500. Oversized-field feedback names the field, observed length and limit and asks for a focused correction instead of a different plan. `recon_coverage` separately supplies startup port ranges, completion and evidence provenance to both models and survives recon-cache reuse. Completed full TCP coverage should be reused unless a specific gap, changed route/access or scan failure justifies another sweep.

Prefer separate operations. For compound scripts, literal `=== headings ===` let HARP associate results with the corresponding command section. Capture output to a file, save the operation's exit code immediately, and display the output afterward. A final `echo`, `cat` or `tee` status is not the operation's status. Ambiguous composite output retains unknown scope rather than inventing authentication conclusions.

Progress counts distinct scoped outcomes. Resubmitting an already accepted job, changing log headings, reprinting retained scan output, and changing elapsed counters are not new capabilities. For formats without an adapter, stable content fingerprints remain a fallback; this is not a universal semantic understanding of arbitrary output. Existing step, model-call, failed-command, repeated-command and operator-stop protections remain active.

## Planning evaluations

`tests/fixtures/planning_cases.json` contains synthetic cases for hidden versions, mixed outcomes, local client banners, HTTP permission denials, research disabled, exhausted fingerprint effort, negative credential wording, and the transition from exposed printer to confirmed submission. No box name, intended CVE or walkthrough is used as a planning answer.

Feed saved decisions from any oracle/model into the offline evaluator:

```text
python scripts/evaluate_planning.py --responses decisions.jsonl --output evaluation.json
```

Each input line contains `{"case":"case ID","decision":{...}}`. The evaluator checks the planning contract, citations, capability retention, checkpoint timing, explained local choices, allowed next-action classes and toggle isolation. It reports missing cases. It never starts a target runtime or calls a model/search provider. Scores measure these decision contracts, not actual model solve rates or successful exploitation; real model comparisons require separately generated responses under matching settings.
