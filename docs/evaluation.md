# Evaluation and limitations

[Home](../README.md) · [Setup](setup.md) · [Configuration](configuration.md) · [Running sessions](running-sessions.md) · [Host protection](host-protection.md) · [Evaluation](evaluation.md)

Run the same target snapshot and objective under three modes:

| Mode | Tactical controller | Tool access |
| --- | --- | --- |
| `frontier-only` | Codex | Direct terminal; local delegation disabled |
| `local-only` | Selected proxy model | Delegation; direct Codex terminal disabled |
| `hybrid` | Selected oracle delegates and reviews | Oracle and proxy terminal paths |

The deterministic scan is identical in all modes. Fix the time limit, command limit, model quantization, context budget, and starting target state before comparing runs. Repeat each target and mode, and record target OS, difficulty, and a predeclared success criterion. Verify success outside the model's self report, then call `mark_success` immediately with a short evidence description or a hash. `finish_session` stops the clock and removes Kali. `mark_human_intervention` is for tactical hints only; approving a root command does not trigger it.

The Kali worker stays nonroot and drops all Linux capabilities except `NET_RAW`. Nmap receives that capability through its file capability so SYN scans work without running the worker as root. Docker mode refreshes the cached worker image when the Dockerfile changes or the image is missing.

Each session stores elapsed time, time to verified success, success before human tactical intervention, proxy input and output tokens reported by the selected provider, model latency, proxy step count, oracle action count, root approval count, and sampled Kali memory. `python harp.py report` prints one JSON record per run. Codex plan token usage is left **unknown** unless you enter a trustworthy count with `record_oracle_usage`; HARP cannot infer plan usage or a marginal subscription price from its tool calls. Proxy token usage is marked incomplete if the selected provider omits usage fields. Sampled Kali memory does not include an Unsloth server's RAM or VRAM; record those separately for the final report.

## Current limits

- The demo target is a harmless HTTP service, not a penetration testing benchmark. The Windows lab workflow uses the general terminal and included protocol tools; one target run does not establish broad reliability across Windows environments.
- Root command approval depends on the Codex MCP tool policy loading in the Codex session. Inspect the approval prompt before using it. HARP's CLI refuses root commands.
- Obsidian integration is Markdown export plus bounded keyword retrieval. A full retrieval study and automatic vault synchronization are future experiments.
- There is no automatic Codex plan token or local GPU power measurement. Those fields must come from external measurements.
