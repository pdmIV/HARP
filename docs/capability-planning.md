# Capability-based planning and scoped outcomes

HARP retains a source-linked capability ledger alongside raw terminal output. It separates authentication, resource permissions, exposed operations, protocol errors and local tool errors. A denied share does not invalidate another resource's successful operation. Expected denials are findings, not a global `null_auth_denied` stop. Historical events with that stop reason are labeled as legacy stops in the dashboard.

Each parsed outcome records host, principal, resource, operation, status, evidence reference and a bounded exact output excerpt. Unknown scope stays unspecified. The adapters recognize common SMB/RPC, Nmap and HTTP results; unfamiliar formats remain available as raw observations. Automatic extraction is deliberately conservative and is not a complete protocol parser or proof of exploitability. Source pages and model hypotheses never become terminal-confirmed capabilities.

The dashboard's **Observed capabilities and prerequisites** panel and the oracle/proxy context expose the ledger. Saved replay derives it from observations available at that point, without reading future evidence into earlier frames or modifying a saved session.

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

With research enabled, confirmed reachable capabilities produce a research opportunity card. The oracle must choose research or provide `check.research_decision` explaining why a retained source or local check is better. A missing exact version does not block product/capability/advisory research. Existing query privacy, source caching and research budgets remain in force. Disabled sessions receive neither this card nor research-specific instructions, and cannot call the provider.

Credential validation is an explicit action with terminal-cited candidates and a small total attempt cap. Incidental words in plans, prohibitions such as “do not spray passwords,” and unused empty credential metadata do not make another action a credential test. Recognizable password-file execution still requires candidate evidence. This is a planning guard, not a security sandbox for arbitrary shell programs.

Rejected strategy events retain the public structured decision and validation reason so failures can be audited. They do not retain the provider's private reasoning text.

## Execution and progress

The default interpreter remains `/bin/sh`. A command action or oracle implementation may explicitly select `"shell":"bash"`. HARP wraps it in a logged `/bin/bash` heredoc and checks the body with `bash -n`; the default path uses `sh -n`. Bash availability is determined by those normal runtime checks, with no silent interpreter fallback. Common Bash-only constructs in an unwrapped POSIX command are returned for correction before execution. Scope validation and exact root approval still apply to the complete logged command.

Prefer separate operations. For compound scripts, literal `=== headings ===` let HARP associate results with the corresponding command section. Capture output to a file, save the operation's exit code immediately, and display the output afterward. A final `echo`, `cat` or `tee` status is not the operation's status. Ambiguous composite output retains unknown scope rather than inventing authentication conclusions.

Progress counts distinct scoped outcomes. Resubmitting an already accepted job, changing log headings, reprinting retained scan output, and changing elapsed counters are not new capabilities. For formats without an adapter, stable content fingerprints remain a fallback; this is not a universal semantic understanding of arbitrary output. Existing step, model-call, failed-command, repeated-command and operator-stop protections remain active.

## Planning evaluations

`tests/fixtures/planning_cases.json` contains synthetic cases for hidden versions, mixed outcomes, local client banners, HTTP permission denials, research disabled, exhausted fingerprint effort, and negative credential wording. No box name, intended CVE or walkthrough is used as a planning answer.

Feed saved decisions from any oracle/model into the offline evaluator:

```text
python scripts/evaluate_planning.py --responses decisions.jsonl --output evaluation.json
```

Each input line contains `{"case":"case ID","decision":{...}}`. The evaluator checks the planning contract, citations, capability retention, allowed next-action classes and toggle isolation. It reports missing cases. It never starts a target runtime or calls a model/search provider. Scores measure these decision contracts, not actual model solve rates or successful exploitation; real model comparisons require separately generated responses under matching settings.
