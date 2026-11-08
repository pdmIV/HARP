# Cicada: a HARP Hybrid case study

This case study records the fixed-max baseline. A later adaptive-effort run is compared with it in [Adaptive reasoning: preliminary Cicada results](../../evaluation.md#adaptive-reasoning-preliminary-cicada-results), including observed token reductions and the limits of that comparison.

HARP recovered both `user.txt` and `root.txt` from the authorized Hack The Box Cicada lab. GLM-5.3 chose bounded objectives and GLM-5.3-Flash executed commands through HARP's Kali WSL runtime. Successful terminal file reads provide the evidence for both flags.

This publication includes the lab flags, credentials, and document excerpts with the operator's permission. API keys and command-center access tokens are excluded. It is a historical record of one run, including unsuccessful commands and recovery, rather than a benchmark of general reliability.

## Read the run

- [Readable transcript](transcript.md): reconnaissance, oracle plans, delegated objectives, short proxy explanations, commands, terminal output, and stop reasons in chronological order.
- [Session snapshot](session.json): configuration, observations, usage, and reconciled outcome.
- [Event log](events.jsonl): machine-readable chronological events, including command reviews and recovery.
- [Artifact registry](artifacts.json): recovered lab credentials, source commands, and verified flags.

## Configuration and observed results

| Measure | Recorded value |
| --- | --- |
| Source session | `20261107-183134-ba6eec` |
| Started | November 7, 2026, 23:31:34 UTC |
| Target | Cicada / `cicada.htb` / `10.129.231.149` |
| Oracle | Z.AI `glm-5.3` |
| Proxy | Z.AI `glm-5.3-flash` |
| Mode / runtime | Hybrid / Kali WSL |
| Deterministic reconnaissance | 103.17 seconds |
| Delegations / proxy terminal commands | 8 / 30 |
| Recorded oracle / proxy model calls | 9 / 39 |
| Oracle input / output tokens | 79,690 / 53,208 |
| Proxy input / output tokens | 271,537 / 12,184 |
| Time from start to terminal evidence for both flags | 25 minutes 30.92 seconds |
| Recorded original session duration | 29 minutes 56 seconds |
| Command review waiting time | 37.59 seconds |
| Root approvals on the Kali runtime | 0 |
| Human tactical intervention | None recorded |
| Verified outcome | Both lab flags recovered |

Token totals are the recorded provider usage, not a count of terminal output. The log contains ten oracle request events and nine recorded oracle usage entries, including an API error and resume. Pricing was not configured completely, so this run does not establish a dollar cost. Command approvals are recorded separately from tactical intervention. Zero Kali root approvals does not describe the Windows target's access level.

## How the hierarchy operated

| Stage | Oracle objective and observed evidence |
| --- | --- |
| Deterministic recon | HARP enumerated exposed services and performed HTTP and SMB probes before asking the proxy to act. The results identified a Windows domain controller and an anonymously readable HR share. |
| Initial credential | The oracle directed the proxy to read the HR notice. Its default new-hire password became a candidate for limited validation against enumerated accounts. |
| First authenticated account | A bounded SMB validation identified `michael.wrightson`. Authenticated enumeration later exposed a password in `david.orelious`'s account description. |
| New share access | Validation as `david.orelious` exposed the DEV share. Its backup script contained credentials for `emily.oscars`. |
| User flag | The proxy validated the new credentials over SMB and WinRM, corrected the profile path, and read `user.txt`. The NetExec terminal result contains the flag value. |
| Privilege evidence | The oracle requested group and token enumeration. The output showed Backup Operators membership and enabled `SeBackupPrivilege`. |
| Root flag | After a direct read failed, the proxy used `robocopy /B` to copy `root.txt` into a readable location and read the copied file. The NetExec result contains the second flag value. |

The terminal transcript, rather than the model's final claim, substantiates each step. The run includes a delegation stopped after three unproductive commands, two invalid local replies, command reviews, and an oracle API error followed by resume. These are visible in the evidence instead of being removed from the example.

## Outcome reconciliation and fixes

The original flag detector accepted only a hexadecimal value on an otherwise empty line. NetExec prepended service, IP, port, and hostname columns, so neither successful flag read entered the Flags registry. One flag was instead nominated as a credential artifact. The original session was eventually stopped with an `unknown` outcome, even though both values were already present in terminal evidence.

Before publishing, the saved successful file-read results were reprocessed with support for NetExec's output format. Two flag artifacts were added, the outcome was corrected to success, and a `success_reconciled` event documented that retrospective verification. `success_at` and time to success use the original terminal event for the second flag. The original finish timestamp and duration remain intact. Newly registered artifact timestamps reflect reconciliation, not the earlier file-read times.

The accompanying fixes now recognize these prefixed results, end a delegation after the second verified flag, automatically finish the session, freeze its timer, and show a green celebration dialog. Artifact proposals are also checked after their accompanying command returns, so a matching result can appear without waiting for another model request. Existing evidence requirements still apply.

This export is for reading and analysis. It is not an instruction to replay historical commands, and publishing it does not start a HARP session.

## Retrospective cost estimate

Prices were entered after this run. The following display-time estimate uses the saved token usage and the subsequently configured prices. The original event log still contains the estimates, including unknown values, recorded during execution.

| Price per million tokens | Oracle | Proxy |
| --- | ---: | ---: |
| Ordinary input | $1.4 | $0.15 |
| Cached input | $0.26 | $0.03 |
| Cache writes | $0 | $0 |
| Output | $4.4 | $0.5 |

| Measure | Estimate |
| --- | ---: |
| Oracle | $0.331819 |
| Proxy | $0.045148 |
| Hybrid total | $0.376967 |
| Oracle-only at the same workload | $0.749675 |
| Hybrid savings | $0.372708 |
| Estimated percentage savings | 49.72% |

The oracle-only estimate retains recorded oracle work and reprices proxy work at oracle rates with the same token counts and cache mix. It does not measure a separate oracle-only run or establish billed costs after credits and allowances. See [cost comparison assumptions](../../configuration.md#hybrid-cost-comparison).
