"""Evidence-based planning and bounded progress checks; no target-specific knowledge."""
import hashlib
import re


GUIDANCE = """
Before choosing a path, compare the observed service capabilities, versions, access,
and configuration clues. Distinguish observations from hypotheses. Prefer a small
check that discriminates between plausible paths over repeating one assumption.
An inaccessible resource does not imply credentials are the only way forward.
Do not infer vulnerability from a product name or banner alone. A precise version
is optional evidence, not a prerequisite for considering a capability-based hypothesis.
Unknown and not_observable are not absent, patched, or contradicted. After at most
two fingerprint checks for a scoped fact, use reachable capabilities and behavioral
prerequisite checks. Client banners and protocol compatibility values are not server
package releases. RPC/signing/tool errors do not disprove another working operation.
For every continuing decision provide check:{action:one of allowed_check_actions,
hypothesis, fact, resource,
principal, evidence:[{observation:1,quote:"exact output"}] (or {recon:1}),
expected_positive, expected_negative}. Use a stable fact/resource/principal across
equivalent tools; for a repeated check state retry_reason explaining changed evidence
or a specific transport limitation. Record only a concise test rationale, not private
reasoning. The capability ledger contains observed output, not verified exploitability.
Do not use generic online password lists simply because an account was enumerated,
wordlists are installed, or no lockout was reported. No-lockout is a rate/lockout
constraint, not evidence for a weak password. Increasing a failed list is not a new
lead. Online credential validation uses check.action=credential_validation and
credential_test with candidates (each containing
value, observation, quote), max_attempts (1..20), and rationale. observation is the
one-based index into terminal observations, and quote must be an exact excerpt from
that observation's output containing the candidate. Test only those candidates,
within the stated total attempt cap, accounting for accounts/services and lockout.
Use the plan to state the evidence, hypothesis and next discriminating check; do not
provide private reasoning. After negative evidence, compare unexplored capabilities
and missing prerequisites before retrying. Read the installed tool's help when flags
or protocol support are uncertain; do not transfer flags between tools. Preserve the
tested command's exit status when piping output to a logger. Authentication failures
are evidence against candidates, and transport errors do not prove tested coverage.
Background-job polling is not new target evidence. Hand back to the oracle when a
job repeatedly yields only counters, failed authentication or transport errors.
"""

IMPLEMENTATION_MARKER = "\n\nOracle-authored implementation instructions:\n"

WORKER_GUIDANCE = """
Keep execution within the delegated objective and authentication limits. Do not add
generic password lists or enlarge a candidate set. If the objective lacks a password
candidate supported by target evidence, request oracle help before online guessing.
Check the installed tool's help when flags or protocol support are uncertain. Preserve
the tested command's exit status when logging through a pipeline. Failed logins and
transport errors are not successful coverage. Monitoring an existing job is not new
target evidence; request oracle review after repeated counters or transport errors.
Respect the command timeout; do not use longer sleeps or move a timed-out job into
the background merely to avoid a limit. Report any already-running job in the handoff.
The default shell is POSIX /bin/sh. If Bash syntax is essential, set shell:"bash"
on the command action; HARP logs an explicit Bash wrapper and checks it with Bash.
Prefer one operation per command. For a compound script print literal === headings ===
and each operation's exit code. Capture output to a file, save rc=$? immediately,
then display it. Never use a final echo, cat or tee exit code as the probe's status.
Access denied is scoped to its resource and operation; preserve other working capabilities.
"""


def task_text(objective):
    return objective.split(IMPLEMENTATION_MARKER, 1)[0]


def online_guessing(decision):
    # Plans discuss alternatives and prohibitions; they are not action intent.
    check = decision.get("check")
    declared = check.get("action") if isinstance(check, dict) else None
    text = str(decision.get("objective", ""))
    text = " ".join(part for part in re.split(r"[.;\n]", text)
                    if not re.search(r"\b(?:do not|don't|never|without|no password|no credential)\b", part, re.I))
    guessing = re.search(r"\b(?:spray(?:ing)?|brute[ -]?forc\w*|dictionary|wordlist|password[ -]list|password candidates?|credential guessing|common passwords?|\d[\d,]*[ -]candidates?)\b", text, re.I)
    online = re.search(r"\b(?:passwords?|credentials?|authentication|logins?|spray(?:ing)?)\b", text, re.I)
    offline = re.search(r"\b(?:offline|hashcat|john)\b", text, re.I)
    implementation = str(decision.get("implementation", ""))
    tool = re.search(r"\b(?:hydra|medusa|ncrack)\s+(?:[^\n]*?\s)?-P\s|\bpatator\s+[^\n]*password=FILE", implementation)
    password_file = re.search(r"\b(?:nxc|netexec|crackmapexec)\s[^\n]*\s-p\s+[\"']?(?:\$\{?(?:WL|WORDLIST|PASSWORDS)\b|[^\s\"']+\.txt\b)", implementation, re.I)
    return bool(declared == "credential_validation" or tool or password_file or
                (declared is None and guessing and online and not offline))


def credential_test_issue(decision, observations):
    """Validate candidate provenance, not model-written claims of evidence."""
    test = decision.get("credential_test")
    if not online_guessing(decision) and isinstance(test, dict) and not test.get("candidates"):
        decision.pop("credential_test", None)
        return None
    if test is None:
        return ("Online guessing needs observed password candidates; choose another evidence-gathering step or supply credential_test."
                if online_guessing(decision) else None)
    if not isinstance(test, dict) or not isinstance(test.get("rationale"), str) or not test["rationale"].strip():
        return "credential_test requires a rationale and observed candidates."
    cap = test.get("max_attempts")
    candidates = test.get("candidates")
    if type(cap) is not int or not 1 <= cap <= 20 or not isinstance(candidates, list) or not 1 <= len(candidates) <= cap:
        return "credential_test requires 1..20 total attempts and no more candidates than attempts."
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return "Each credential candidate requires value, observation and quote."
        index, value, quote = candidate.get("observation"), candidate.get("value"), candidate.get("quote")
        if (type(index) is not int or not 1 <= index <= len(observations) or
                not isinstance(value, str) or not value or len(value) > 700 or
                not isinstance(quote, str) or not quote or len(quote) > 1500 or
                value not in quote or quote not in str(observations[index - 1].get("output", ""))):
            return "Credential candidates must cite an exact terminal observation excerpt containing their value."
    return None


def poll_command(command):
    """Conservatively recognize monitoring commands, not running an assessment tool."""
    if re.search(r"(?:^|[;&|]\s*|\b(?:do|then)\s+)(?:timeout\s+\d+\s+)?(?:/[\w/.-]+/)?(?:nohup|nmap|curl|wget|smbclient|rpcclient|nxc|netexec|hydra|python\d*|bash)\s", command):
        return False
    return bool(re.search(r"\b(?:ps\s+-|pgrep\s|tail\s|wc\s+-l|sleep\s+\d)", command) or
                re.search(r"\b(?:cat|sed|head|grep)\s[^\n]*(?:enum|scan|probe|log|checks|report|output|ports)[\w.-]*\.(?:txt|log|json)\b", command))


def result_state(result):
    """Return useful/monitoring/error status without treating counters as evidence."""
    scoped = result.get("outcomes", [])
    if scoped and all(row.get("host") != "local" and row.get("status") in
                      ("confirmed", "denied", "unsupported") for row in scoped):
        return "evidence" if any(row["status"] == "confirmed" for row in scoped) else "finding"
    output = re.sub(r"\x1b\[[0-9;]*m", "", str(result.get("output", ""))).strip()
    lines = [line for line in output.splitlines() if line.strip()]
    error = re.compile(r"(?:\b(?:NT_)?STATUS_(?:LOGON_FAILURE|ACCESS_DENIED)|broken pipe|connection (?:reset|refused|timed out)|does not support SMBv1)", re.I)
    errors = sum(bool(error.search(line)) for line in lines)
    positive = re.search(r"(?m)^.*\[\+\].*(?:\\[^\s:]+:|authenticated|login success|Pwn3d)|\buid=\d+\(|^[a-fA-F0-9]{32}$", output)
    if positive and result.get("exit_code") == 0:
        return "evidence"
    # Counted errors in a poll's saved report also indicate a deteriorating job.
    counters = re.search(r"(?:Broken Pipe|transport[_ ]errors?)\s*[:=]\s*([1-9]\d*)", output, re.I)
    if result.get("exit_code") != 0 or not output or errors >= max(3, len(lines) * .7) or counters:
        return "error"
    if poll_command(str(result.get("command", ""))):
        return "monitoring"
    return "evidence"


def evidence_fingerprint(result):
    if result_state(result) != "evidence":
        return None
    lines = []
    for line in str(result.get("output", "")).splitlines():
        if re.search(r"(?i)^\s*(?:===|---|Client started|Starting Nmap|Nmap done|exit_code=|\[\d{4}\]|\d+\s+\d+:\d+)|\b(?:attempts?|elapsed|log lines|Broken Pipe)\s*[:=]", line):
            continue
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if line:
            lines.append(line)
    if not lines:
        return None
    return hashlib.sha256("\n".join(sorted(set(lines))).encode()).hexdigest()


def prepare_command(command, shell="sh"):
    if shell is None:
        shell = "sh"
    if shell not in ("sh", "bash"):
        raise ValueError('shell must be "sh" or "bash"')
    if shell == "sh":
        return command
    marker = "HARP_BASH_" + hashlib.sha256(command.encode()).hexdigest()[:16]
    while marker in command:
        marker += "X"
    return "/bin/bash <<'" + marker + "'\n" + command + "\n" + marker


def shell_issue(command):
    if re.match(r"\s*(?:/bin/)?bash\s", command):
        return None
    # A quoted script written by cat is data; its declared interpreter executes
    # it later. Single-quoted CLI arguments likewise do not expand in this shell.
    executable = re.sub(r"(?m)(\bcat[^\n]*<<\s*(['\"])(\w+)\2[^\n]*\n)[\s\S]*?^\3\s*$", r"\1\3", command)
    executable = re.sub(r"'[^']*'", "''", executable)
    if re.search(r"\$\{?PIPESTATUS\b|\[\[|\bdeclare\s+-[aA]|\bset\s+-[^\n;]*\bpipefail\b", executable):
        return 'Bash syntax is not valid for the default /bin/sh runtime. Set shell:"bash" or use POSIX exit-code handling.'
    return None


def syntax_probe(command):
    match = re.match(r"/bin/bash <<'(HARP_BASH_[A-Za-z0-9_]+)'\n([\s\S]*)\n\1$", command)
    shell, body = ("bash", match[2]) if match else ("sh", command)
    marker = "HARP_SYNTAX_" + hashlib.sha256(body.encode()).hexdigest()[:16]
    while marker in body:
        marker += "X"
    return shell + " -n <<'" + marker + "'\n" + body + "\n" + marker
