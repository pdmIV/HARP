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

Each session stores elapsed time, wall time to verified success, active time to success excluding command-review waiting, review wait time, success before human tactical intervention, proxy input and output tokens reported by the selected provider, model latency, proxy step count, oracle action count, root approval count, and sampled Kali memory. `python harp.py report` prints one JSON record per run. A command review does not consume a proxy step or count as tactical human help. Use active time when comparing model performance; retain wall time for operational accounting. Codex plan token usage is left **unknown** unless you enter a trustworthy count with `record_oracle_usage`; HARP cannot infer plan usage or a marginal subscription price from its tool calls. Proxy token usage is marked incomplete if the selected provider omits usage fields. Sampled Kali memory does not include an Unsloth server's RAM or VRAM; record those separately for the final report.

## Adaptive reasoning: preliminary Cicada results

An initial comparison on the authorized Hack The Box Cicada lab observed lower oracle token consumption and model latency with adaptive reasoning. Both runs recovered `user.txt` and `root.txt`, verified from terminal file-reading results. This is a comparison of two observed runs, not a controlled estimate of the feature's causal effect.

Both used Z.AI `glm-5.3` as oracle and `glm-5.3-flash` as proxy in Hybrid mode with Kali WSL. The proxy stayed at high effort. Oracle evidence depth was detailed, temperature was 1, top-p was 0.95, and the oracle reply cap was 65,536 tokens in both runs. The baseline used fixed max effort. The adaptive run started at high and accepted the proxy's recommendation for each subsequent oracle request, defaulting to high when no recommendation was available.

| Measure | Fixed max | Adaptive | Observed reduction |
| --- | ---: | ---: | ---: |
| Oracle calls with recorded usage | 9 | 8 | 1 call |
| Oracle input tokens | 79,690 | 61,143 | 23.3% |
| Oracle output tokens | 53,208 | 18,473 | 65.3% |
| Total oracle tokens | 132,898 | 79,616 | 40.1% |
| Cumulative recorded oracle request time | 846.15 s | 246.38 s | 70.9% |
| Proxy input + output tokens | 283,721 | 279,462 | 1.5% |
| Combined oracle + proxy tokens | 416,619 | 359,078 | 13.8% |
| Wall time to evidence for both flags | 25m 30.92s | 10m 38.27s | 58.3% |
| Verified flags | Both | Both | Same observed outcome |

### What the adaptive run demonstrated

The oracle used high for seven calls and max for one. Five proxy handoff replies supplied valid effort recommendations: four high and one max. Three calls used the high fallback, including the initial recon review and continuations without a final recommendation. The final max recommendation was applied to the next oracle request before the run completed successfully.

The recommendation was included in the proxy's existing JSON response. No separate routing inference request was made. This avoids another request and its duplicated context processing; the added prompt instruction and response field still consume some tokens. The observed total-token saving was 53,282 on the oracle and 57,541 across both models. Token reductions are not equivalent to billed-dollar savings, because input, cached input, output, and package allowances can have different accounting.

### Evidence and limits

The source sessions are `20261107-183134-ba6eec` (fixed max) and `20261107-233455-f84285` (adaptive). Measurements come from each saved session's provider-usage ledger and timestamped event log. The [published fixed-max case study](case-studies/cicada-2026-11-07/README.md) provides the baseline evidence. Raw evidence from the adaptive session remains in the local run directory; this summary does not publish its credentials or flag values.

The adaptive run reused cached reconnaissance, taking 2.79 seconds rather than 103.17 seconds. The runs followed different command sequences and used different versions of HARP, including updated flag detection and completion handling. Each recorded one oracle error followed by a manual resume. In the adaptive run, an approved multiline command was rejected by the terminal transport; two malformed proxy replies recovered automatically. That command-format error has since been addressed by returning unexecutable formats to the proxy for bounded correction before approval. The fix was not active during this measurement.

Cumulative oracle request time measures recorded request latency, not provider compute alone. Wall time also includes reconnaissance, execution, approvals, and manual resume delays. Neither the measured speedup nor all token differences can be attributed solely to reasoning effort. One successful adaptive run does not establish equal success rates, generalization, or optimal routing.

For a controlled follow-up, compare repeated fixed-high, fixed-max, and adaptive runs using the same HARP version, target starting snapshot, reconnaissance policy, model settings, and budgets. Keep calibration targets separate from evaluation targets. Report verified success rate, total tokens across both models, oracle request latency, wall time, and errors/resumes. See [adaptive configuration](configuration.md#adaptive-oracle-reasoning-experimental) to enable the experiment.

## Current limits

- The demo target is a harmless HTTP service, not a penetration testing benchmark. The Windows lab workflow uses the general terminal and included protocol tools; one target run does not establish broad reliability across Windows environments.
- Root command approval depends on the Codex MCP tool policy loading in the Codex session. Inspect the approval prompt before using it. HARP's CLI refuses root commands.
- Obsidian integration is Markdown export plus bounded keyword retrieval. A full retrieval study and automatic vault synchronization are future experiments.
- There is no automatic Codex plan token or local GPU power measurement. Those fields must come from external measurements.

## Display estimates and measured comparisons

The dashboard can reprice saved usage after a session. It uses current prices only for the matching provider and model, and preserves the original configuration, ledger, and historical per-call estimates. The CLI report reads the recorded session costs. Record the rate source and price date when using dashboard estimates in a report. See [pricing configuration](configuration.md#prices-entered-after-a-session).

The dashboard's oracle-only estimate holds the recorded workload fixed: it retains oracle work and reprices proxy input, cached input, cache writes, and output at oracle rates. Estimated savings are the difference from the combined Hybrid cost, shown in dollars and as a percentage of the oracle-only estimate. This is a token-price comparison. A measured comparison requires separate oracle-only runs with the same target snapshot and objective, since model behavior, token counts, cache hits, and success rates may differ.

Replay reconstructs saved events without running target commands or requesting model output. It is useful for demonstrations and reviewing evidence. Replay elapsed time and accelerated playback speed are not measurements of a new assessment. Missing historical events or usage cannot be recovered through playback. The activity indicator distinguishes live sessions, saved final states, and recorded replay with a steady dot.
