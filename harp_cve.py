"""Bounded keyword discovery against the official, unauthenticated CVE Search API."""
import hashlib
import json
import re
import urllib.error
import urllib.request

ENDPOINT = "https://search.cve.org/webSearch"
MAX_RESPONSE_BYTES = 1_048_576
TIMEOUT_SECONDS = 20


def query_plan(product, feature, alternatives=None):
    """Use the deployed API's working flat-keyword format, never Boolean groups."""
    def phrase(value, label, maximum):
        if (not isinstance(value, str) or not value.strip() or len(value) > maximum or
                not re.fullmatch(r"[\w%+. -]+", value, re.UNICODE)):
            raise ValueError(f"CVE {label} must be a short public literal without query operators")
        value = " ".join(value.split())
        if len(value.split()) > 4 or not re.search(r"\w", value):
            raise ValueError(f"CVE {label} must contain one through four words")
        if any(word.upper() in ("AND", "OR", "NOT") for word in value.split()):
            raise ValueError(f"CVE {label} must not contain Boolean operators")
        return value

    product = phrase(product, "product", 80)
    feature = phrase(feature, "feature", 60)
    alternatives = [] if alternatives is None else alternatives
    if not isinstance(alternatives, list) or len(alternatives) > 2:
        raise ValueError("CVE alternatives must be a list of at most two literal phrases")
    phrases = [feature]
    for value in alternatives:
        value = phrase(value, "alternative", 60)
        if value.casefold() not in {item.casefold() for item in phrases}:
            phrases.append(value)
    primary = _keywords(product + " " + feature)
    # Prefer a word repeated across distinct evidence-supported phrases. Ties
    # preserve input order. This supplies one bounded relaxation without an OR
    # expression, invented synonyms, model routing or a product-only query.
    counts, words = {}, []
    for value in phrases:
        for word in dict.fromkeys(word.casefold() for word in value.split()):
            if word not in counts:
                words.append(word)
            counts[word] = counts.get(word, 0) + 1
    candidates = sorted(words, key=lambda word: -counts[word])
    refinement = next((_keywords(product + " " + word) for word in candidates
                       if _keywords(product + " " + word).casefold() != primary.casefold() and
                       word not in {part.casefold() for part in product.split()}), None)
    return {"fields": {"product": product, "feature": feature, "alternatives": phrases[1:]},
            "primary": primary, "refinement": refinement, "encoding": "flat-keywords-v1"}


def _keywords(value):
    """Flat AND-matched words, with literal quoting only for punctuation tokens."""
    words = list(dict.fromkeys(value.split()))
    return " ".join(json.dumps(word, ensure_ascii=False) if re.search(r"[+%]", word) else word for word in words)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def request_body(query, *, refine=False):
    if isinstance(query, dict):
        if set(query) - {"product", "feature", "alternatives"}:
            raise ValueError("CVE structured query accepts only product, feature and alternatives")
        plan = query_plan(query.get("product"), query.get("feature"), query.get("alternatives"))
        wire = plan["refinement"] if refine else plan["primary"]
        if wire is None:
            raise ValueError("CVE query has no distinct bounded refinement")
        return {"query": wire, "sort": {"property": "relevancy", "order": "desc"}, "from": 0, "size": 3}
    if refine:
        raise ValueError("CVE refinement requires structured fields")
    if not isinstance(query, str) or len(query) > 300:
        raise ValueError("CVE search requires at most 300 characters of focused public keywords")
    words = re.findall(r"[\w.-]+", query, re.UNICODE)
    if not words:
        raise ValueError("CVE search requires at most 300 characters of focused public keywords")
    if any(word.upper() in ("AND", "OR", "NOT") for word in words):
        raise ValueError("Legacy CVE queries require literal keywords, not Boolean expressions")
    return {"query": _keywords(" ".join(words)),
            "sort": {"property": "relevancy", "order": "desc"}, "from": 0, "size": 3}


def search(query, *, refine=False):
    return _search_request(request_body(query, refine=refine))


def _search_request(body):
    """Shared transport; validation tools can replay an exact historical body."""
    req = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "HARP-CVE-Research/1.0"}, method="POST")
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=TIMEOUT_SECONDS) as response:
            if getattr(response, "status", 200) != 200:
                raise RuntimeError(f"CVE Search API returned unexpected HTTP {response.status}")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            headers = getattr(response, "headers", {})
            length = headers.get("Content-Length")
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(f"CVE Search API returned HTTP {status}; no automatic retry or fallback") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("CVE Search API response exceeds 1 MiB")
    if length is not None and (not str(length).strip().isdigit() or int(length) != len(raw)):
        raise RuntimeError("CVE Search API returned an incomplete or invalid HTTP body")
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeError("CVE Search API returned invalid JSON") from None
    metadata = report.get("searchMetadata") if isinstance(report, dict) else None
    if (not isinstance(metadata, dict) or metadata.get("searchStatus") != "ok" or
            not isinstance(metadata.get("errors"), list) or metadata["errors"] or
            not isinstance(report.get("data"), list) or type(report.get("resultsTotal")) is not int or
            report["resultsTotal"] < 0 or
            len(report["data"]) != min(report["resultsTotal"], body["size"])):
        raise RuntimeError("CVE Search API returned an unsuccessful or invalid result envelope")
    return report


def records(report):
    """Normalize hit wrappers and retain source-attributed scores, never applicability."""
    rows = []
    for hit in report["data"][:3]:
        record = hit.get("_source", hit) if isinstance(hit, dict) else None
        if not isinstance(record, dict):
            raise RuntimeError("CVE Search API returned an invalid record")
        meta, containers = record.get("cveMetadata"), record.get("containers")
        if not isinstance(meta, dict) or not isinstance(containers, dict):
            raise RuntimeError("CVE Search API record is missing metadata or containers")
        identity = meta.get("cveId", "")
        if not isinstance(identity, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identity):
            raise RuntimeError("CVE Search API record has an invalid CVE ID")
        if meta.get("state") != "PUBLISHED":
            continue
        cna = containers.get("cna")
        if not isinstance(cna, dict):
            raise RuntimeError("CVE Search API record has no CNA container")
        description = next((row.get("value", "") for row in cna.get("descriptions", [])
                            if isinstance(row, dict) and str(row.get("lang", "")).startswith("en")), "")
        scores = []
        contributors = [cna] + (containers.get("adp") or [])[:8]
        for contributor in contributors:
            if not isinstance(contributor, dict):
                continue
            provider = contributor.get("providerMetadata") or {}
            for metric in contributor.get("metrics", []):
                if not isinstance(metric, dict):
                    continue
                for kind in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    value = metric.get(kind)
                    if isinstance(value, dict):
                        scores.append({"source": str(provider.get("shortName") or provider.get("orgId") or "unknown")[:100],
                                       "version": str(value.get("version", "unknown"))[:20],
                                       "score": value.get("baseScore"), "severity": str(value.get("baseSeverity", "unknown"))[:30],
                                       "vector": str(value.get("vectorString", ""))[:160]})
        # Full records remain available for an explicit read; these are discovery summaries.
        affected = []
        for item in cna.get("affected", [])[:2]:
            if not isinstance(item, dict):
                continue
            affected.append({"vendor": str(item.get("vendor", "unknown"))[:80],
                             "product": str(item.get("product", "unknown"))[:100],
                             "defaultStatus": str(item.get("defaultStatus", "unknown"))[:30],
                             "versions": [{key: str(v[key])[:100] for key in
                                 ("version", "status", "lessThan", "lessThanOrEqual", "versionType") if key in v}
                                 for v in item.get("versions", [])[:3] if isinstance(v, dict)]})
        url = "https://www.cve.org/CVERecord?id=" + identity
        retained = {key: record[key] for key in ("dataType", "dataVersion", "cveMetadata", "containers") if key in record}
        text = json.dumps(retained, indent=2, ensure_ascii=False)
        rows.append({"title": str(cna.get("title") or identity)[:180], "link": url,
                     "content": str(description)[:700], "publish_date": meta.get("datePublished"),
                     "advisory": {"cve_id": identity, "affected": affected, "scores": scores[:3],
                                  "summary_only": True, "applicability": "unverified"},
                     "references": [row for row in cna.get("references", []) if isinstance(row, dict)][:8],
                     "retained_source": {"url": url, "final_url": url, "text": text,
                                         "sha256": hashlib.sha256(text.encode()).hexdigest(), "truncated": False}})
    return rows
