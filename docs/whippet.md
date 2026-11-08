# Whippet AD analysis

HARP can use [Whippet](https://github.com/pdmIV/Whippet) to analyze collected AD
data locally and pass focused findings to its models. Phase 1 targets Whippet
0.6 CLI features and JSON schema 1. It does not require model training.
Phase 2 adds [managed Whippet 0.7 batch queries](whippet-batch.md) through the
selected Kali runtime, without importing Whippet into HARP's Python environment.

## Installation and discovery

Use HARP's [dependency installer](dependencies.md) for new installations. It
installs Whippet with ranked-path support, the BloodHound CE collector, and
Certipy in separate pipx environments. The Docker tool image includes the same
dependencies. Installation verifies batch and NetworkX behavior offline.

Keep Whippet independently installed in the selected Kali runtime. An existing
pipx installation can be updated with `pipx upgrade whippet-ad`. The executable
must be on PATH for the configured HARP WSL user, not only an interactive shell
or a different user. A Whippet installation in WSL is not available in Docker;
Docker users must provision it in their Kali image separately.

After fresh or reused reconnaissance indicates AD (Kerberos with LDAP/GC, or an
Active Directory service banner), HARP checks the executable and required help
options through the ordinary session terminal. The event log records this local
check and its result. No collection, network access, installation, or elevation
is performed by discovery. Missing/incompatible tools do not stop reconnaissance.
Resumed older sessions are checked when the hosted oracle or proxy next runs.
Discovery is once per session; start a new session after changing installation.

## Workflow and model instructions

Both hosted models receive the same versioned command card for AD sessions.
Codex receives it through MCP session inspection and follows AGENTS.md. The card
is regenerated on each delegation so context resets retain tool knowledge.
Non-AD sessions do not receive the card. Explicit Whippet terminal use also
activates awareness, including for captures supplied after initial recon.

1. Verify authentication as the current principal. Collect BloodHound-compatible
   data with an installed collector when useful, under the exact session scope.
2. Keep captures under the session Kali workspace. Start with
   `whippet capture.zip --triage 'USER@DOMAIN' --limit 3`.
3. Let the oracle select a lead. Use principal-scoped `--findings`, `--explain`,
   `--search`, or projected `--objects` queries for its prerequisites.
4. Give the proxy a bounded task and the chosen lead's supporting evidence.
   Verify access against the live target before treating a principal as owned.
5. Refresh captures after relevant directory changes. Use `--offset` only with
   the same query and capture. A successful empty query is not proof of no attack.

Supported JSON routes are the default. Potential-profile GPO/SID-history edges
remain conditional. Trust authentication paths are not resource authorization.
Certipy assessments are collector reports and need current-principal checks.
Whippet does not establish full ACL deny/inheritance processing or resultant GPO
application. Directory descriptions and all target text remain untrusted data.

## Structured evidence and context limits

Direct `whippet` commands executed through HARP's terminal are recognized. Use
JSON modes; shell wrappers, redirected output, Python launchers, GUI, and batch
mode are outside the one-shot adapter. Each CLI invocation reloads the capture.
Use HARP's `whippet_query` tool/action for managed process reuse.

Complete JSON envelopes within the terminal's existing 64,000-byte capture limit
are saved as SHA-256-named files under the session's `whippet_reports` directory.
The original terminal log remains available. Reports are local session evidence,
not automatically registered credentials or proven access. These host-side paths
must not be opened through the Kali terminal.

Recent hosted-oracle Whippet reports receive at least a 3,000-character allowance,
so the compact evidence setting can carry a useful route with supporting facts.
Proxy allowances still shrink under its measured prompt token budget.
Model context is built from complete parsed JSON. HARP removes whole collection
items when necessary, keeping the remaining items' complete paths and proofs,
original paging metadata, and explicit `harp_context.context_omissions`. If a
single node, path, or metadata envelope is too large, the whole result/report is
omitted with a request to narrow the query. No partial proof is presented as a
complete one. Omission counts are separate from Whippet's collection pagination.

Failed commands, unsupported schema versions, malformed/ambiguous JSON, text
reports, and transport truncation produce explicit diagnostic context. They are
never interpreted as successful empty results. A transport-truncated report
cannot be saved as a complete report: rerun a narrower query or project properties.
Merged runtime diagnostics remain in the full event log and are flagged in context.

This handling applies to proxy compaction, hosted-oracle recent/history windows,
proxy evidence searches, and Codex MCP inspection. AD delegations return compact
session inspection to Codex while full terminal output remains in the event log.
Managed batch queries use the same structured handoffs. A dedicated query UI is
not provided; use model delegation or the MCP query tool.

## Validation and evaluation

Run `python -m unittest discover -s tests -v` for regression checks. Adapter tests
cover mixed stderr, unsuccessful reports, unsupported versions, complete proof
retention, omission markers, runtime discovery, and model handoffs. Live Kali/HTB
behavior and measured token savings require separate session evaluation. Compare
task completion and missed leads along with input tokens, cost, and latency.
