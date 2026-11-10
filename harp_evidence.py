"""Scoped, source-linked observations; model hypotheses never become verified facts."""
import hashlib
import json
import re
import shlex


STATES = {"confirmed": "confirmed", "denied": "contradicted", "unsupported": "unknown",
          "inconclusive": "unknown", "unknown": "unknown", "not_observable": "not_observable"}


def allowed_actions(session):
    actions = ["enumerate", "fingerprint", "validate_hypothesis", "credential_validation"]
    if session.get("config", {}).get("oracle", {}).get("web_search_enabled") is True:
        actions.append("research")
    return actions


def clean(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))


def scope(command, target):
    """Unknown scope stays unknown. Never attribute one section's error to another."""
    urls = re.findall(r"//([^/\s\"']+)/([^\s\"';]+)", command)
    addresses = set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", command))
    peer = next(iter(addresses)) if len(addresses) == 1 else (target if not addresses else "unspecified")
    host, resource = urls[0] if len(set(urls)) == 1 else (peer, "unspecified")
    host, resource = host.rsplit("@", 1)[-1], resource.split("?", 1)[0]
    if re.fullmatch(r"[^:]+:\d+", host):
        host, port = host.rsplit(":", 1)
        resource = "tcp:" + port + "/" + resource
    principal = "unknown"
    if re.search(r"(?:\s-N\b|\s-no-pass\b|\s-u\s+['\"]{2})", command):
        principal = "anonymous"
    user = re.search(r"\s-[Uu]\s+['\"]([^'\"]*)['\"]", command)
    if user:
        principal = user[1].split("%", 1)[0] or "anonymous"
    operation = "probe"
    if re.search(r"\b(?:enumprinters|enumports|enumjobs|srvinfo|rpcdump)\b", command):
        operation = "rpc.query"
    subcommand = re.search(r"\s-c\s+['\"]([^'\"]+)['\"]", command)
    if subcommand:
        verb = subcommand[1].split()[0].lower()
        operation = {"ls": "share.list", "dir": "share.list", "print": "printer.submit",
                     "get": "file.read", "queue": "printer.queue"}.get(verb, operation)
    return {"host": host, "principal": principal, "resource": resource, "operation": operation}


def sections(command, output):
    # Common oracle scripts mark operations with literal echo headings. Associate
    # only exact matching headings; ambiguous blocks retain unspecified scope.
    headings = list(re.finditer(r"(?m)^\s*echo\s+(['\"])(===.*?===)\1[^\n]*\n", command))
    commands = {match[2].strip(): command[match.end():headings[i + 1].start() if i + 1 < len(headings) else len(command)]
                for i, match in enumerate(headings)}
    current, lines = command, []
    for line in clean(output).splitlines():
        if commands and re.fullmatch(r"===\s+.+\s+===", line.strip()):
            if lines:
                yield current, lines
            current, lines = commands.get(line.strip(), ""), []
        else:
            lines.append(line)
    if lines:
        yield current, lines


def outcomes(result, target, observation):
    rows = []
    if not re.search(r"\b(?:smbclient|rpcclient|enum4linux(?:-ng)?|nmap|curl|ldapsearch|rpcdump|impacket-rpcdump|nxc|netexec)\b", result.get("command", "")):
        return rows
    def add(context, operation, status, quote, value=""):
        row = {**context, "operation": operation, "status": status, "state": STATES[status],
               "value": value[:160], "observation": observation, "quote": quote[:500], "source": "terminal"}
        row["id"] = hashlib.sha256(json.dumps([row[k] for k in
            ("host", "principal", "resource", "operation", "status", "value")]).encode()).hexdigest()[:16]
        if not any(old["id"] == row["id"] for old in rows):
            rows.append(row)
    for command, lines in sections(result.get("command", ""), result.get("output", "")):
        if not command:
            continue
        context = scope(command, target)
        signing_error = any(re.search(r"bad SMB\d.*signature|signature verification failed", line, re.I) for line in lines)
        share = context["resource"]
        for line in lines:
            found = re.search(r"Testing share\s+(\S+)", line)
            if found:
                share = found[1]
            row_scope = {**context, "resource": share}
            if re.search(r"Client started \(version", line, re.I):
                # Local client versions are diagnostics, not server fingerprints.
                continue
            if re.search(r"Bad substitution|syntax error|unrecognized arguments|command not found", line, re.I):
                add({**context, "host": "local"}, "tool.execution", "inconclusive", line)
            elif re.search(r"bad SMB\d.*signature|signature verification failed", line, re.I):
                add(context, "protocol.signing", "inconclusive", line)
            elif re.search(r"Connection refused|timed out|Broken Pipe|ept_s_not_registered", line, re.I):
                add(context, "protocol.connection", "inconclusive", line)
            elif re.search(r"session setup failed.*(?:LOGON_FAILURE|ACCESS_DENIED)", line, re.I):
                add(context, "session.authenticate", "denied", line)
            elif "Server allows authentication via username '' and password ''" in line:
                add({**context, "principal": "anonymous", "resource": "session"}, "session.authenticate", "confirmed", line)
            elif re.search(r"Mapping:\s*(OK|DENIED)", line, re.I):
                add(row_scope, "share.map", "denied" if "DENIED" in line else "confirmed", line)
                if "NOT SUPPORTED" in line:
                    add(row_scope, "share.list", "unsupported", line)
            elif re.search(r"putting file .+ as .+", line, re.I):
                if re.search(r"-c\s+['\"]print\s", command):
                    add(context, "printer.submit", "confirmed", line)
                elif re.search(r"-c\s+['\"]put\s", command):
                    add(context, "file.write", "confirmed", line)
            elif re.search(r"(?:NT_)?STATUS_ACCESS_DENIED", line):
                operation = "share.map" if "tree connect failed" in line else context["operation"]
                add(context, operation, "inconclusive" if signing_error else "denied", line)
            elif re.search(r"STATUS_NOT_SUPPORTED|Listing:\s*NOT SUPPORTED", line):
                add(context, context["operation"], "unsupported", line)
            elif re.search(r"\S+\s+Printer\s+", line):
                name = line.split()[0]
                add({**context, "resource": name}, "printer.exposed", "confirmed", line)
            elif re.search(r"(?:server version[:=]|Server=\[Samba)\s*\S*\d+\.\d+\.\d+", line, re.I):
                add({**context, "resource": "service"}, "server.version", "confirmed", line, line.strip())
            elif re.search(r"HTTP/\d(?:\.\d)?\s+(?:401|403)\b", line):
                add(context, "http.request", "denied", line)
            elif re.search(r"HTTP/\d(?:\.\d)?\s+2\d\d\b", line):
                add(context, "http.request", "confirmed", line)
    return rows


def sync(session):
    """Incremental and durable; old sessions are derived from retained observations."""
    observations = session.get("observations", [])
    ledger = session.setdefault("capability_ledger", {"cursor": 0, "revision": 0, "facts": {}, "seen": []})
    if ledger["cursor"] > len(observations):
        ledger.update(cursor=0, revision=0, facts={}, seen=[])
    for index, service in enumerate(session.get("recon", []), 1):
        if not service.get("product"):
            continue
        for operation, value, status in (("server.product", service["product"], "confirmed"),
                ("server.version", service.get("version", ""), "confirmed" if re.search(r"\d+\.\d+", service.get("version", "")) else "unknown")):
            identity = "recon:" + str(index) + ":" + operation
            if identity not in ledger["facts"]:
                ledger["facts"][identity] = {"id": identity, "host": session.get("target", "unknown"),
                    "principal": "unknown", "resource": "tcp:" + str(service.get("port")), "operation": operation,
                    "value": value, "status": status, "state": STATES[status], "source": "recon", "recon": index,
                    "quote": json.dumps(service), "observation": None}
                ledger["revision"] += 1
    for index in range(ledger["cursor"], len(observations)):
        result = observations[index]
        rows = outcomes(result, session.get("target", "unknown"), index + 1)
        result["outcomes"] = rows
        for row in rows:
            # Retain contradictory observations, rather than overwriting a success
            # with a later denial or a different principal's result.
            if row["id"] not in ledger["facts"]:
                ledger["revision"] += 1
            ledger["facts"][row["id"]] = row
        ledger["cursor"] = index + 1
    # Keep important capabilities and negatives across model-context compaction.
    if len(ledger["facts"]) > 160:
        ledger["facts"] = dict(list(ledger["facts"].items())[-160:])
    return ledger


def context(session, limit=32):
    ledger = sync(session)
    facts = list(ledger["facts"].values())
    # Prefer actionable successes, then recent scoped outcomes. Bounded and deduped.
    positives = [row for row in facts if row["status"] == "confirmed"][-12:]
    chosen = {row["id"]: row for row in positives + facts[-limit:]}
    return {"revision": ledger["revision"], "facts": list(chosen.values())[:limit],
            "omitted": max(0, len(facts) - min(limit, len(chosen))),
            "prerequisites": session.get("prerequisite_ledger", [])[-24:],
            "checks": session.get("assessment_history", [])[-8:]}


def progress(session, result):
    """Count newly scoped outcomes or stable content, not wrappers/log volume."""
    ledger = sync(session)
    from harp_strategy import evidence_fingerprint
    rows = result.get("outcomes")
    keys = [row["id"] for row in rows if row["host"] != "local" and row["status"] in
            ("confirmed", "denied", "unsupported")] if rows else [evidence_fingerprint(result)]
    new = [key for key in keys if key and key not in ledger["seen"]]
    ledger["seen"] = list(dict.fromkeys(ledger["seen"] + [key for key in keys if key]))[-1024:]
    return len(new)


def reference_issue(references, session):
    if not isinstance(references, list) or len(references) > 8:
        return "check.evidence must be a list of at most eight source references."
    for ref in references:
        if not isinstance(ref, dict):
            return "Each evidence reference must identify an observation and exact quote, or a recon index."
        if "recon" in ref:
            if type(ref["recon"]) is not int or not 1 <= ref["recon"] <= len(session.get("recon", [])):
                return "Unknown reconnaissance evidence index."
        else:
            index, quote = ref.get("observation"), ref.get("quote")
            if (type(index) is not int or not 1 <= index <= len(session.get("observations", [])) or
                    not isinstance(quote, str) or not quote or len(quote) > 1500 or
                    quote not in clean(session["observations"][index - 1].get("output", ""))):
                return "Check evidence must quote an exact retained terminal observation."
    return None


def check_issue(decision, session):
    check = decision.get("check")
    if check is None:
        return "A continuing decision requires a structured check; state its hypothesis, fact and expected outcomes." if session.get("planning_protocol", 1) >= 2 else None
    if not isinstance(check, dict):
        return "check must be an object."
    if check.get("action") not in allowed_actions(session):
        return "check.action must describe the proposed operation."
    if ("research" in decision) != (check["action"] == "research"):
        return "The declared check action must match the actual research or execution decision."
    for name in ("hypothesis", "fact", "resource", "principal", "expected_positive", "expected_negative"):
        if not isinstance(check.get(name), str) or not check[name].strip() or len(check[name]) > 500:
            return "check requires short hypothesis, fact, resource, principal and expected_positive/expected_negative strings."
    issue = reference_issue(check.get("evidence"), session)
    if issue:
        return issue
    if (session.get("observations") or session.get("recon")) and not check["evidence"]:
        return "Cite at least one observation or recon item supporting this check."
    prior = [row for row in session.get("assessment_history", []) if
             row.get("executed") is not False and all(row.get(key) == check.get(key) for key in ("action", "fact", "resource", "principal"))]
    reading_source = isinstance(decision.get("research"), dict) and "source_id" in decision["research"]
    if prior and not reading_source and not check.get("retry_reason"):
        return "This fact was already checked; explain what changed in check.retry_reason or choose another fact."
    if check["action"] == "fingerprint" and len(prior) >= 2:
        return "Fingerprint budget for this scoped fact is exhausted. Its value is not observable through attempted probes; choose a capability/prerequisite check instead."
    return None


def record_check(session, check):
    if not check:
        return
    session.setdefault("assessment_history", []).append({**check, "before_observation": len(session.get("observations", [])),
                                                         "interpretation": "unverified oracle hypothesis"})
    session["assessment_history"] = session["assessment_history"][-80:]


def finish_check(session, check):
    if not check:
        return
    entry = session["assessment_history"][-1]
    entry["executed"] = len(session.get("observations", [])) > entry["before_observation"]
    if not entry["executed"] or check.get("action") != "fingerprint":
        return
    ledger = sync(session)
    if any(row["operation"] == check["fact"] and row["status"] == "confirmed" and
           isinstance(row.get("observation"), int) and row["host"] == session["target"] and
           row["resource"] == check["resource"] and
           row["observation"] > session["assessment_history"][-1]["before_observation"]
           for row in ledger["facts"].values()):
        state = "confirmed"
    else:
        count = sum(row.get("executed") is not False and all(row.get(key) == check.get(key) for key in ("action", "fact", "resource", "principal"))
                    for row in session["assessment_history"])
        state = "not_observable" if count >= 2 else "unknown"
    row = {"host": session["target"], "fact": check["fact"], "resource": check["resource"],
           "principal": check["principal"], "state": state,
           "meaning": "Unknown is not absent, patched, or a reason to block other hypotheses."}
    previous = session.setdefault("prerequisite_ledger", [])
    session["prerequisite_ledger"] = [old for old in previous if not all(old.get(k) == row[k] for k in
        ("host", "fact", "resource", "principal"))] + [row]
