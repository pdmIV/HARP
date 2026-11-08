# HARP

<div align="center"><img src=".gitbook/assets/harp-banner.png" alt="HARP - Hierarchical AI-Agent Penetration Testing" width="100%"></div>

<p align="center">
  <a href="https://peter-mora-iv.gitbook.io/harp-docs">https://peter-mora-iv.gitbook.io/harp-docs</a>
</p>

[Watch the HARP overview video](https://drive.google.com/file/d/1BAiDD7IASI5ddH3yrRy89OVPtSh359V4/view?usp=sharing)

HARP is a hierarchical AI-agent penetration-testing prototype for authorized labs. An oracle reviews deterministic reconnaissance and delegates objectives to a proxy model. HARP validates proposed commands, executes them through a logged Kali runtime, and records terminal evidence, artifacts, and outcomes. Hosted oracles can plan and delegate automatically; Codex operates through the HARP MCP tools.

For complex work, a hosted oracle can provide an exact implementation for the proxy to execute, and the proxy can request oracle help when it encounters a blocker. Z.AI GLM-5.3 and GLM-5.3-Flash sessions can use configurable oracle evidence depth and larger token ceilings; see [GLM configuration](docs/configuration.md#zai-api--glm) for practical starting settings.

An optional [adaptive reasoning experiment](docs/configuration.md#adaptive-oracle-reasoning-experimental) lets the proxy recommend high or max effort for the next hosted oracle request, without a separate routing call.

In an initial Cicada comparison, the adaptive run recovered both flags while using **40.1% fewer oracle tokens** and **13.8% fewer combined oracle + proxy tokens** than the earlier fixed-max run. Recorded oracle request time was **70.9% lower**. These are preliminary observations from two runs with different execution paths and reconnaissance reuse, not controlled benchmark results. See [measurements and limitations](docs/evaluation.md#adaptive-reasoning-preliminary-cicada-results).

## How Whippet helps HARP

For Active Directory labs, HARP integrates [Whippet](https://github.com/pdmIV/Whippet), a companion CLI for analyzing BloodHound-compatible collector output. Whippet answers focused questions about group membership, account permissions, and candidate privilege paths, then returns compact JSON. The large capture stays in Kali while HARP supplies the models with selected findings. This aims to reduce repeated input tokens, context pressure, and API cost during AD investigations.

The oracle uses principal-scoped triage to choose a lead. The proxy receives the relevant route, supporting facts, and one bounded verification task. Property selection, pagination, and structured context compaction control how much evidence enters each handoff. HARP preserves complete retained findings and their prerequisites, and marks omitted results and collection limitations. Shared tool instructions teach the models Whippet's custom interface without fine-tuning.

HARP's managed batch connection reuses one loaded graph across queries and starts a fresh graph when capture contents change. Process reuse targets graph-loading overhead; focused queries target model input size. Candidate paths remain leads that require live terminal verification. End-to-end token, latency, and solve-rate improvements still need controlled evaluation. See [Whippet AD analysis](docs/whippet.md) and [managed batch queries](docs/whippet-batch.md) for the workflow and implementation details.

## Supported configurations

| Component       | Options                                            |
| --------------- | -------------------------------------------------- |
| Oracle          | OpenAI API, Z.AI API, NVIDIA NIM, or Codex via MCP |
| Proxy model     | OpenAI API, Z.AI API, NVIDIA NIM, or local Unsloth |
| Kali runtime    | Existing Kali WSL or disposable Docker container   |
| Experiment mode | Hybrid, proxy only, or frontier only               |

## Getting started

1. Follow [Setup](docs/setup.md) and run the [dependency installer](docs/dependencies.md) for your Kali runtime. It includes Whippet, NetworkX, BloodHound CE's collector, Certipy, and HARP's existing tools.
2. Run `python harp_web.py` from the repository root.
3. Import credentials in **API Keys**, select models in **Oracle model** and **Proxy model**, and save your target and Kali runtime in **Configuration**.
4. Follow [Running sessions](docs/running-sessions.md) to start a run or connect Codex through MCP.

OpenAI and NVIDIA NIM pairings do not require a local GPU. Daybreak Blue requires API project access; selecting it in HARP does not grant that access.

## Documentation

| Guide                                            | Contents                                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| [Setup](docs/setup.md)                           | Prerequisites, WSL, Docker demo, Unsloth, and MCP setup                                               |
| [Install dependencies](docs/dependencies.md)     | WSL/Docker installers, Whippet and AD tools, offline checks, and revision selection                   |
| [Configuration](docs/configuration.md)           | Providers, model selection, API keys, limits, context, caching, costs, and access errors              |
| [Running sessions](docs/running-sessions.md)     | Hosted and Codex workflows, dashboard, CLI, reconnaissance, flags, artifacts, replay, and VPN routing |
| [Image evidence](docs/image-evidence.md)         | PNG/JPEG previews, oracle-directed GLM 5.3 Flash image input, and transcription verification          |
| [Whippet AD analysis](docs/whippet.md)           | Optional Kali CLI, model awareness, focused graph queries, and structured context limits              |
| [Whippet batch queries](docs/whippet-batch.md)   | Whippet 0.7 process reuse, protocol logging, capture refresh, and runtime cleanup                     |
| [Host protection](docs/host-protection.md)       | Runtime boundaries, command validation, and root approvals                                            |
| [Evaluation and limitations](docs/evaluation.md) | Experiment modes, recorded metrics, success verification, and prototype limits                        |
| [Operator guide](AGENTS.md)                      | Instructions for Codex operators                                                                      |

Finished sessions can be replayed from the dashboard with play/pause, speed controls, a seek timeline, and progressive evidence display. Replay uses saved logs without contacting the target or calling models. See [session replay](docs/running-sessions.md#replay-a-saved-session).

Overview also shows total oracle + proxy cost and estimated Hybrid savings in dollars and percent. Prices can be saved after a run. The oracle-only comparison holds recorded token counts and cache behavior fixed; see [cost estimates](docs/configuration.md#hybrid-cost-comparison).

## Evidence and scope

See the [Cicada case study](docs/case-studies/cicada-2026-11-07/) for a complete Hybrid run with oracle plans, proxy commands, terminal evidence, artifacts, and both lab flags.

Use HARP only against targets you are authorized to assess. Model claims are not proof of success. HARP records `user.txt` and `root.txt` flags from terminal evidence and preserves session logs for review. You can stop an active session or permanently delete a finished session and its logs in the command center. Completed reconnaissance is cached separately and reused for matching new sessions; a focused `.htb` hostname check can identify the same box at a new IP. Select **Refresh reconnaissance** to scan again. Root commands require approval.

WSL uses your existing distribution and does not provide Docker's isolation or resource limits. Read [Host protection](docs/host-protection.md) before choosing a runtime. Keep API keys out of Git. Review and explicitly authorize session evidence before publishing it, as with the linked case study.
