# Configuration

Use **Configuration → Configuration snapshots** to export saved settings from every tab to a portable JSON backup, preview a backup, and apply its settings. API keys are optional and excluded by default. Restore creates a recovery copy and requires sessions and HARP-managed models to be stopped. See [settings snapshots](settings-snapshots.md).

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

The **Oracle model** tab includes **Z.AI web search (experimental)** beneath adaptive reasoning. It defaults off. Set `oracle.web_search_enabled: true` to enable bounded public research for new sessions, using your existing Z.AI key regardless of oracle model provider. Search charges are separate from model inference. See [web research](web-research.md) for the one-search/two-read task budget, four-task session cap, caching, and source handling.

Use **API Keys** in the sidebar to manage OpenAI, Z.AI, NVIDIA NIM, and Unsloth credentials in one place. Select a provider in the shared import panel, paste its key (up to 4 KiB), and click the import button. The status panel on the right lists every provider: green for a saved key, amber for an active environment key, and red for a missing key. Status reflects key presence, not validated API access. Windows keys are encrypted with DPAPI in `.secrets`. Linux imports use unencrypted owner-only mode-600 files in a mode-700 `.secrets` directory. Reimport Windows keys when moving to Linux. The standalone Unsloth key-import script has been removed; use this tab or an environment variable. Environment variables take precedence. The tab shows only whether a saved key exists or an environment key is active; it never retrieves or displays saved key values. Saving a key does not change model or session configuration or send model requests. Model discovery remains available beside oracle and proxy selection. The model-comparison panel has been removed.

## Z.AI API / GLM

Import a standard Z.AI API key in **API Keys**, or set `ZAI_API_KEY`. The saved key is shared by oracle and proxy. Select **Z.AI API / GLM** in either model tab, load the documented presets, and choose `glm-5.3` or `glm-5.3-flash`. Presets do not verify your account access or billing. Save each role before starting a session.

The **Oracle model** and **Proxy model** tabs have independent **Temperature** and **Top P** fields for Z.AI. Newly selecting Z.AI starts them at `1` and `0.95`, respectively, following [Z.AI's GLM-5.3-Flash recommendation](https://docs.z.ai/guides/vlm/glm-5.3-flash). Set temperature from `0` to `2` and Top P above `0` through `1`, then save each role. HARP sends both values in that role's chat-completion requests. Existing saved values remain in place when HARP loads the configuration. Z.AI's [general parameter guide](https://docs.z.ai/guides/overview/concept-param) suggests changing one sampling parameter at a time when tuning. The OpenAI Responses integration continues to use model defaults because its reasoning models may reject these parameters.

HARP uses the standard endpoint `https://api.z.ai/api/paas/v4/chat/completions`. Coding Plan endpoints and subscription quotas are not used. Requests enable reasoning with selectable **Low**, **High**, or **Max** effort, defaulting to Low. Reasoning text is never interpreted as a command. Both GLM-5.3 models advertise a 1M-token context window and a 131,072-token maximum reply, but those are capacities rather than useful targets for every HARP call. HARP allows a Z.AI proxy input cap up to 900,000 tokens and reply cap up to 131,072, with a combined cap of 900,000 to leave room for token-estimate error and response overhead. The command center exposes a Z.AI oracle reply cap up to 131,072. Existing sessions keep their saved caps.

For a GLM-5.3 oracle with a GLM-5.3-Flash proxy, start with **Max** oracle reasoning and a 16,384-token oracle reply cap if you expect complex payload construction. Start the Flash proxy at **Low** reasoning with an 8,192-token reply cap for bounded execution; move it to **High** and 16,384 tokens if it frequently runs out of reasoning space. These are HARP-specific starting points, not provider defaults. Z.AI recommends **Max** reasoning for complex coding and for Flash generally. A larger reply cap is a ceiling, so a model that finishes early does not have to use it. Inspect provider finish reasons and actual token usage before raising caps again.

The oracle can author a complex implementation, including protocol details and exact code, then pass it to the proxy for bounded execution. A proxy that cannot confidently craft or repair a payload can request oracle help; the next oracle cycle receives that request and automatically expands compact evidence to detailed evidence. Implementation handoffs and executable commands have no HARP character cap. Complete multiline scripts and quoted heredocs are supported, so the models can write one complete file instead of spending calls on partial writes. Long or multiline commands travel over stdin in the selected Kali runtime, avoiding Windows command-line and Linux argument limits. Model context and output-token settings still apply. Commands still pass through HARP's target-scope, syntax and approval checks. The oracle's direct recovery probe remains limited to a read-only command, so complex action is executed by the proxy through the logged Kali terminal.

**Evidence depth** controls how much terminal history the hosted oracle receives each cycle: Compact includes four recent results with up to 1,200 characters each; Detailed includes twelve with up to 6,000 characters each; Extended includes thirty-two with up to 12,000 characters each. Use Compact for routine cycles and Detailed or Extended when the oracle needs to compare longer outputs or debug a complex path. These settings use the larger context window without replaying the entire session log or paying for it every turn. The proxy still receives a compact rebuilt prompt per step; increasing its input cap alone does not send more evidence. Its `memory_query` action can retrieve earlier evidence by keyword. HARP does not preserve Z.AI reasoning content across calls, so preserved thinking is not enabled.

Enter token rates for each role to enable cost estimates. HARP records provider-reported input, output, and cached-input usage. Missing rates remain unknown. OpenAI access programs, explicit cache controls, and Unsloth server tools are not sent to Z.AI. All target actions continue through HARP's logged terminal, with the existing scope, approval, and flag-verification checks.

## OpenAI API and Daybreak Blue

In **API Keys**, paste an OpenAI project API key, then click **Import API key**. HARP saves the key under `.secrets/openai.key` using Windows DPAPI or owner-only Linux file permissions. It is never included in `harp.json` or session snapshots. `OPENAI_API_KEY`, if set, takes precedence over the imported key.

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

**Command checks** in the Proxy model tab defaults to **Essential** for Z.AI and **Strict** for other providers. Essential checks command length, shell syntax, target scope, delegated SMB share, and root approval. Strict adds null-authentication and password-evidence checks plus smbclient usage guidance such as recursive-listing syntax and disabling interactive download prompts. A command-check issue opens a human review popup with the reason and exact command. Accepting runs it; denying returns feedback to the proxy. The review wait consumes no proxy step and is excluded from active time to success. A shell command that creates a local folder before invoking smbclient is parsed by command segment, so the folder's `mkdir -p` is never treated as an SMB password argument. Existing Z.AI sessions without an explicit setting use Essential after the HARP process restarts; other existing sessions remain Strict. Private pivot IPs are accepted when successful terminal evidence contains the address and the current oracle objective names it. An optional headless `authorized_scope` list can predeclare additional IPv4 addresses or bounded CIDRs.

The worker may search earlier evidence with a `memory_query` action. Search results distinguish terminal evidence from **unverified model notes**. This is a simple keyword retrieval baseline, useful for testing whether persistent memory helps after context resets; it is not semantic retrieval yet.

For the hosted oracle, each request rebuilds context from the session log. It includes the structured startup reconnaissance, the selected recent-result depth, up to eight distinct older successful results, eight recent plan/delegation outcomes (including terminal failures and command rejection feedback), and eight evidence-backed artifacts. Older output is excerpted and the full log stays on disk. The plan history is a record of attempted approaches, while terminal results and verified artifacts are the evidence for deciding what to do next. This bounded context also survives an oracle restart or resume.

HARP stops an ordinary delegation on a repeated command, repeated output, three failed or empty commands, repeated or excessive memory searches, invalid model replies, a root request, or the configured step limit. The step limit and model-call cap apply afresh to each delegation; cumulative counts remain session statistics. Codex can inspect the stop reason and give a narrower task. The manual **Unbridled** option removes step, model-call, and repetition stops for that delegation while retaining operator stop, approval, and invalid-reply handling. Hosted **unlimited budget** removes oracle cycle and proxy step/model-call budgets for that session; its other stop checks still apply.

## Prompt caching and cost accounting

OpenAI oracle and proxy requests place fixed instructions and deterministic reconnaissance before changing objectives, feedback, and terminal observations. Evidence stays in user messages. Serialization and hashed cache routing keys remain stable as working context changes; oracle and proxy use separate keys. No dummy tokens or cache warmup requests are added.

For GPT-5.6 and later GPT families, HARP uses an explicit breakpoint after the stable prefix and explicit-only caching, so changing observations are not written to cache. The default cache lifetime is 30 minutes; each role can select 12 hours in the application. Older models use their native automatic caching without unsupported breakpoint or TTL parameters. Unknown/custom model IDs also use native defaults. Prefix length and model/API eligibility still determine whether caching occurs. OpenAI-compatible third-party endpoints must support these OpenAI parameters for recognized GPT models.

The dashboard and session logs report cached input tokens and cache-write tokens separately. Enter each role's ordinary-input, cached-input, cache-write, and output prices in USD per million tokens. Cache-write prices are the total write rate, not an additional surcharge. Missing prices for used token categories produce an unknown estimate, not zero. For legacy models that do not report cache writes, that category is zero. Estimates are before credits, discounts, or complimentary daily allowances and are not a billing statement. Update rates when switching models or cache lifetime. HARP does not infer free-token eligibility or organization-wide quota remaining from individual responses.

Context compaction still applies and can change a prefix. Caching does not retain omitted proxy history, expand the context window, or change HARP's target scope and command approvals.

## OpenAI access troubleshooting

OpenAI access errors are terminal for the current oracle operation; HARP does not silently change the selected access program or retry a rejected request. An `access_program_not_enabled` error requires checking API organization/project provisioning. Selecting Standard retains standard API policies and does not guarantee acceptance of a cybersecurity workflow. Error reporting preserves bounded error codes, parameter paths, and request IDs while withholding raw provider messages and response bodies. Live Daybreak eligibility and cache savings must be verified with the operator's own project; automated transport tests use mocked API responses.

## Prices entered after a session

Overview recalculates estimates from saved token counts using current configured prices when the provider and model match the recorded session. This also applies to replay, using only the usage revealed so far. Save prices in the model settings and the next dashboard refresh applies them to existing sessions. No new session or model request is needed.

A recalculated estimate is labeled **at current configured prices**. The original configuration, per-call estimates, and event log remain unchanged. If the current configuration selects different models, HARP uses the session's saved rates or recorded estimates instead. Unknown usage or a missing price for a token category actually used keeps the estimate unavailable. Zero is a valid configured price. Estimates are before account credits or allowances.

## Hybrid cost comparison

Overview and replay show combined oracle and proxy cost, an oracle-only estimate, and estimated savings in dollars and percent. The comparison retains recorded oracle work and prices the proxy's recorded token counts at oracle rates, preserving ordinary input, cache reads, cache writes, and output separately. Percentage savings are `(oracle-only estimate - hybrid total) / oracle-only estimate * 100`.

This is a same-workload price comparison, not a measured oracle-only run. Actual oracle-only token usage, cache behavior, and task success may differ. Negative savings appear as extra cost and a higher-cost percentage. A zero oracle-only estimate has no defined percentage. Missing prices or usage keep the comparison unavailable, and non-Hybrid sessions show their total without hybrid savings. In replay, the comparison follows the usage revealed by the playhead.


## Adaptive oracle reasoning (experimental)

The [preliminary Cicada comparison](evaluation.md#adaptive-reasoning-preliminary-cicada-results) records the observed token and latency benefits, effort selections, and comparison limits.

In **Oracle model**, enable **Adaptive reasoning (experimental)** and save the oracle before starting a new Hybrid session. This is off by default. It supports Z.AI and supported OpenAI reasoning models, without changing Codex via MCP or NVIDIA NIM settings.

The first oracle request uses **high**. At the end of an objective, or when requesting oracle help, the proxy adds `recommended_oracle_effort` with `high` or `max` to its existing JSON reply. It recommends the effort needed for the next oracle decision, based on observed results. There is no separate routing request and the proxy's own effort stays unchanged.

Z.AI applies high/max directly. OpenAI maps a max recommendation to max for GPT-6 models and xhigh for GPT-5.2 through GPT-5.9; other OpenAI models are rejected when enabling this experiment. Model/account API support still needs live verification. OpenAI adaptive requests send `reasoning.effort`; fixed OpenAI requests retain their previous provider defaults. For Z.AI, disabling the toggle restores the fixed effort selected in the form.

Recommendations apply once. Missing, invalid, or truncated-response recommendations fall back to high, including after a delegation ends on a budget or repetition stop without a final recommendation. Starting a delegation clears any stale recommendation. A recommendation does not override stop conditions, scope checks, approvals, or success verification. The fixed effort setting is preserved while adaptive mode is enabled.

Proxy commands may include tabs and newlines. Forbidden control characters, including NUL, are returned to the proxy for formatting correction before command approval. After three consecutive format rejections, the delegation returns `command_validation_failed` for bounded oracle recovery. Syntax checks read complete scripts without executing them, and root requests preserve the full command for exact approval.

Z.AI responses stream reasoning and final content instead of waiting for an entire completion behind a fixed read timeout. Model read timeouts follow the effective effort selected for that request, including adaptive changes: low or unspecified gets 4 minutes, medium gets 6 minutes, high gets 10 minutes, and max/xhigh gets 20 minutes. This covers the initial wait and subsequent socket inactivity. An active Z.AI stream can continue for up to 30 minutes. The effort-based read allowance also applies to OpenAI and NVIDIA model transports; discovery and explicit benchmark timeouts retain their separate limits. HARP assembles the complete response, including the finish reason and usage, before accepting any action. An interrupted stream never becomes an executable partial reply. Hosted oracle timeouts or connection interruptions get up to two automatic transport retries within the same oracle cycle, separate from format retries. Stop requests cancel further retries. The activity log records these retries and marks interrupted-request token usage as unknown, since the provider may have billed work without returning usage. Persistent failures still stop the run. Unused optional oracle fields may be omitted or `null`; other invalid field types still require correction.

If the Z.AI proxy replies with prose or ambiguous JSON instead of one action, HARP issues a stricter JSON-only retry instruction at a lower temperature. It permits two bounded format retries, then returns control to the oracle if the third reply is still invalid. No terminal step is consumed by these retries, but the model calls and tokens are recorded. HARP does not execute an action extracted from ambiguous prose.

The activity log shows **Proxy effort recommendation** and **Oracle reasoning effort**, including the selection source. Saved oracle call records include `reasoning_effort`, `effort_source`, `adaptive_reasoning`, elapsed seconds, and normal token usage. Compare fixed high, fixed max, and adaptive runs on separate evaluation targets. This experiment does not establish savings or routing accuracy by itself.
