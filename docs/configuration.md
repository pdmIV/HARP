# Configuration

[Home](../README.md) · [Setup](setup.md) · [Configuration](configuration.md) · [Running sessions](running-sessions.md) · [Host protection](host-protection.md) · [Evaluation](evaluation.md)

## Application tabs

| Tab | Configuration |
| --- | --- |
| Oracle model | Planner provider, model, endpoint, access program, pricing, cache lifetime, and cycle/delegation limits |
| Proxy model | Worker provider, model, prompt/reply limits, and local Unsloth launch settings |
| API Keys | Encrypted imports for OpenAI, Z.AI, NVIDIA NIM, and Unsloth |
| Configuration | Authorized target, Kali runtime, network, scan ports, and resource limits |

Save model changes with **Save oracle** or **Save proxy**. Save target/runtime changes with **Save configuration**. Settings apply to new sessions; existing sessions retain their recorded configuration. The sidebar shows selections for new sessions.

## API keys

Use **API Keys** in the sidebar to manage OpenAI, Z.AI, NVIDIA NIM, and Unsloth credentials in one place. Select a provider in the shared import panel, paste its key (up to 4 KiB), and click the import button. The status panel on the right lists every provider: green for an encrypted saved key, amber for an active environment key, and red for a missing key. Status reflects key presence, not validated API access. Keys are encrypted with Windows DPAPI in the existing `.secrets` files, so keys already imported through Configuration or `set_unsloth_key.py` remain available. Environment variables take precedence. The tab shows only whether an encrypted key exists or an environment key is active; it never retrieves or displays saved key values. Saving a key does not change model or session configuration or send model requests. Model discovery remains available beside oracle and proxy selection. The model-comparison panel has been removed.

## Z.AI API / GLM

Import a standard Z.AI API key in **API Keys**, or set `ZAI_API_KEY`. The encrypted key is shared by oracle and proxy. Select **Z.AI API / GLM** in either model tab, load the documented presets, and choose `glm-5.3` or `glm-5.3-flash`. Presets do not verify your account access or billing. Save each role before starting a session.

HARP uses the standard endpoint `https://api.z.ai/api/paas/v4/chat/completions`. Coding Plan endpoints and subscription quotas are not used. Requests enable reasoning with selectable **Low**, **High**, or **Max** effort, defaulting to Low. Selecting Z.AI for the proxy raises a lower reply cap to 8,192 tokens. Z.AI oracle requests use 8,192 reply tokens from the command center. Reasoning consumes the reply budget, so increase the proxy cap if responses end before producing an action. Reasoning text is never interpreted as a command.

Enter token rates for each role to enable cost estimates. HARP records provider-reported input, output, and cached-input usage. Missing rates remain unknown. OpenAI access programs, explicit cache controls, and Unsloth server tools are not sent to Z.AI. All target actions continue through HARP's logged terminal, with the existing scope, approval, and flag-verification checks.

## OpenAI API and Daybreak Blue

In **API Keys**, paste an OpenAI project API key, then click **Import API key**. HARP encrypts the key with Windows DPAPI under `.secrets/openai.key`. It is never included in `harp.json` or session snapshots. `OPENAI_API_KEY`, if set, takes precedence over the imported key.

Choose **OpenAI API / Daybreak Blue** for the oracle in **Oracle model**, the proxy on the Proxy model page, or both. Set the HTTPS API base URL (default `https://api.openai.com/v1`), click **Load available models** or **Load proxy models**, choose from the dropdown, and save configuration. Each role has its own model, endpoint, and access program. Choose **Standard** when Daybreak is not required.

OpenAI requests use `/responses` with `access_programs.cyber: "daybreak_blue"`, `store: false`, and no provider-side execution tools. Daybreak requires an approved API project and model access. Model discovery lists IDs visible to the key, including models that may not support Responses or Daybreak. It does not prove Daybreak eligibility. See [OpenAI's Daybreak guide](https://developers.openai.com/api/docs/guides/daybreak).

For headless configuration, set either `oracle` or `local` to provider `openai`, with `model`, `base_url`, and `access_program` (`daybreak_blue` or `standard`). Existing token and cycle budgets still apply. Allow enough reply tokens for reasoning plus the visible JSON reply (4096 is a useful starting point). Hosted input token counts are estimates. OpenAI ignores the Unsloth/NIM temperature and thinking controls; model defaults apply.

## NVIDIA NIM

In **Oracle model**, choose **NVIDIA NIM API**, load and select a chat model from the dropdown, and import your NVIDIA key in **API Keys**. The key is encrypted for the current Windows account under `.secrets`; alternatively set `NVIDIA_API_KEY` in the HARP process environment. **Find available models** requests IDs from NVIDIA's model API and populates the model dropdown. See [NVIDIA's API catalog](https://build.nvidia.com/explore/discover) for model details. Model listing does not establish access or free usage for an individual key.

In **Proxy model**, choose **NVIDIA NIM API**, load models, and select a separate proxy model. The oracle and proxy can both use NIM, with independent model choices and the same saved API key. HARP sends each proxy step to NIM's chat API, then validates and runs any requested command through the selected Kali terminal. No Unsloth server is required for this pairing.

For `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`, the proxy's **Enable thinking mode** setting controls whether HARP requests reasoning or instruct mode. Reasoning requires at least 4,096 reply tokens; selecting it in the command center raises a lower cap to 8,192. Empty proxy replies receive one bounded retry. Repeated empty or malformed replies stop the delegation for oracle review. Three oracle delegations without a new terminal result stop the NIM loop for operator review, even when budgets are removed.


Start a Hybrid session in the command center. After deterministic reconnaissance, HARP runs the selected NIM oracle for at most `oracle.max_cycles` cycles, delegating at most `oracle.steps_per_cycle` proxy steps each time. After failed or repetitive proxy commands, invalid replies, or null SMB access denial, the oracle reviews the evidence and may issue a corrected delegation or one validated, read-only probe. Recovery cycles share the regular `oracle.max_cycles` session limit and have no separate cap. A rejected probe returns its validation reason to NIM for correction instead of ending the loop. If an active NIM session stops, **Resume oracle** continues its remaining cycle budget without repeating deterministic reconnaissance. Root requests, operator stops, exhausted budgets, and model API errors still stop the loop. The oracle never runs target commands outside the HARP terminal. Verified flag capture ends the session. The Codex MCP workflow remains available by selecting **Codex via MCP**.

For prototype runs, **Remove hosted oracle cycle and proxy step/model-call budgets** in **Oracle model** applies to new Hybrid sessions. The same choice on Overview applies when resuming a selected active hosted-oracle session, including one that has reached its old cycle limit. Repetition, failed-command, invalid-reply, root-approval, and operator-stop checks remain in effect. The oracle reconsiders new evidence each cycle; evidence-backed credentials are included in its compact context. A discovered password is not assumed to belong to a particular user until a login confirms it, and a confirmed account prompts renewed enumeration before a later path is chosen.

The command center logs **NIM planning** as soon as the oracle request starts and records response time when it returns. Mistral Large 4 can take well over a minute to produce a plan even with a compact prompt; HARP allows up to four minutes for its chat response. Docker mode rebuilds its Kali image only when its Dockerfile changes or the image is missing. WSL mode uses the installed Kali tools directly.

Choose **Existing Kali WSL** in Configuration to use your installed `kali-linux` tools, including `crackmapexec` and `nxc`. HARP runs commands through its logged terminal interface as the configured Kali user. Docker remains available for disposable sessions. Existing sessions keep their original runtime.



## Context management

The proxy model receives the target, objective, structured reconnaissance, bounded HTTP probes, the four most recent terminal results, previous command names, and a small set of durable notes. A new API call is made for each step, so the model does not need a growing conversation or KV cache. For Unsloth, HARP reads the server's reported context length and counts each request with its token-count endpoint. Hosted NIM, Z.AI, and OpenAI providers do not expose the Unsloth endpoints, so HARP uses the configured input cap and a conservative token estimate. All paths reserve output space and trim old excerpts if needed. `local.max_input_tokens` caps the prompt. Raw output stays in `events.jsonl`; the model sees capped excerpts. `Field Notes.md` is Obsidian readable and can be opened as a vault or copied into an existing one. Docker does not mount the notebook; WSL can access Windows mounts.

The worker may search earlier evidence with a `memory_query` action. Search results distinguish terminal evidence from **unverified model notes**. This is a simple keyword retrieval baseline, useful for testing whether persistent memory helps after context resets; it is not semantic retrieval yet.

For the hosted oracle, each request rebuilds context from the session log. It includes the structured startup reconnaissance, four recent terminal results, up to eight distinct older successful results, eight recent plan/delegation outcomes (including terminal failures and command rejection feedback), and eight evidence-backed artifacts. Older output is excerpted and the full log stays on disk. The plan history is a record of attempted approaches, while terminal results and verified artifacts are the evidence for deciding what to do next. This bounded context also survives an oracle restart or resume.

HARP stops an ordinary delegation on a repeated command, repeated output, three failed or empty commands, repeated or excessive memory searches, invalid model replies, a root request, or the configured step limit. The step limit and model-call cap apply afresh to each delegation; cumulative counts remain session statistics. Codex can inspect the stop reason and give a narrower task. The manual **Unbridled** option removes step, model-call, and repetition stops for that delegation while retaining operator stop, approval, and invalid-reply handling. Hosted **unlimited budget** removes oracle cycle and proxy step/model-call budgets for that session; its other stop checks still apply.

## Prompt caching and cost accounting

OpenAI oracle and proxy requests place fixed instructions and deterministic reconnaissance before changing objectives, feedback, and terminal observations. Evidence stays in user messages. Serialization and hashed cache routing keys remain stable as working context changes; oracle and proxy use separate keys. No dummy tokens or cache warmup requests are added.

For GPT-5.6 and later GPT families, HARP uses an explicit breakpoint after the stable prefix and explicit-only caching, so changing observations are not written to cache. The default cache lifetime is 30 minutes; each role can select 12 hours in the application. Older models use their native automatic caching without unsupported breakpoint or TTL parameters. Unknown/custom model IDs also use native defaults. Prefix length and model/API eligibility still determine whether caching occurs. OpenAI-compatible third-party endpoints must support these OpenAI parameters for recognized GPT models.

The dashboard and session logs report cached input tokens and cache-write tokens separately. Enter each role's ordinary-input, cached-input, cache-write, and output prices in USD per million tokens. Cache-write prices are the total write rate, not an additional surcharge. Missing prices for used token categories produce an unknown estimate, not zero. For legacy models that do not report cache writes, that category is zero. Estimates are before credits, discounts, or complimentary daily allowances and are not a billing statement. Update rates when switching models or cache lifetime. HARP does not infer free-token eligibility or organization-wide quota remaining from individual responses.

Context compaction still applies and can change a prefix. Caching does not retain omitted proxy history, expand the context window, or change HARP's target scope and command approvals.

## OpenAI access troubleshooting

OpenAI access errors are terminal for the current oracle operation; HARP does not silently change the selected access program or retry a rejected request. An `access_program_not_enabled` error requires checking API organization/project provisioning. Selecting Standard retains standard API policies and does not guarantee acceptance of a cybersecurity workflow. Error reporting preserves bounded error codes, parameter paths, and request IDs while withholding raw provider messages and response bodies. Live Daybreak eligibility and cache savings must be verified with the operator's own project; automated transport tests use mocked API responses.
