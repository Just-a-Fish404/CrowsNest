"""
CrowsNest core: DNS email-security checks shared by the GUI and the CLI.

Existing functions (spf_check, dkim_check, dmarc_check, domain_assessment)
keep their names and return strings so the GUI keeps working. New in this
version:

    validate_sender()      - is a provider (Mailchimp, SendGrid, ...) authorized
                             in the domain's SPF record (including nested
                             include: chains) and does its DKIM selector exist?
    run_full_assessment()  - one call that returns everything as a dict
    format_report()        - turns that dict into plain text (GUI + CLI)
"""

import csv
import io
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import dns.exception
import dns.resolver

DNS_LOOKUP_LIMIT = 10   # RFC 7208 section 4.6.4
_HARD_STOP = 25         # never chase more SPF lookups than this, whatever the record says

# ---------------------------------------------------------------------------
# Known senders. Providers occasionally change these values, so verify against
# the provider's docs if a check looks wrong. Add your own entries freely.
#   spf_includes   - include: domains the provider tells you to publish
#   dkim_selectors - selectors the provider commonly uses (any one found = OK)
# ---------------------------------------------------------------------------
SENDERS = {
    "mailchimp": {
        "label": "Mailchimp",
        "spf_includes": ["servers.mcsv.net"],
        "dkim_selectors": ["k2", "k3"],
        "note": "Mailchimp typically sends with its own return-path, so a missing SPF "
                "include is often harmless; DKIM (k2/k3) is the record that matters most.",
    },
    "mandrill": {
        "label": "Mandrill (Mailchimp Transactional)",
        "spf_includes": ["spf.mandrillapp.com"],
        "dkim_selectors": ["mandrill"],
    },
    "sendgrid": {
        "label": "SendGrid",
        "spf_includes": ["sendgrid.net"],
        "dkim_selectors": ["s1", "s2"],
    },
    "google": {
        "label": "Google Workspace",
        "spf_includes": ["_spf.google.com"],
        "dkim_selectors": ["google"],
    },
    "microsoft365": {
        "label": "Microsoft 365",
        "spf_includes": ["spf.protection.outlook.com"],
        "dkim_selectors": ["selector1", "selector2"],
    },
    "amazon-ses": {
        "label": "Amazon SES",
        "spf_includes": ["amazonses.com"],
        "dkim_selectors": [],   # SES uses per-account random selectors
    },
    "mailgun": {
        "label": "Mailgun",
        "spf_includes": ["mailgun.org"],
        "dkim_selectors": ["smtp", "k1"],
    },
    "postmark": {
        "label": "Postmark",
        "spf_includes": ["spf.mtasv.net"],
        "dkim_selectors": [],   # Postmark uses per-account selectors
    },
    "zendesk": {
        "label": "Zendesk",
        "spf_includes": ["mail.zendesk.com"],
        "dkim_selectors": ["zendesk1", "zendesk2"],
    },
}

SENDER_ALIASES = {
    "mc": "mailchimp",
    "gmail": "google",
    "gsuite": "google",
    "google-workspace": "google",
    "googleworkspace": "google",
    "office365": "microsoft365",
    "o365": "microsoft365",
    "m365": "microsoft365",
    "microsoft-365": "microsoft365",
    "outlook": "microsoft365",
    "ses": "amazon-ses",
    "aws-ses": "amazon-ses",
    "amazonses": "amazon-ses",
}

# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------
_resolver = dns.resolver.Resolver()
_resolver.timeout = 3.0
_resolver.lifetime = 6.0


def configure_resolver(nameservers=None, timeout=None):
    """Optional: override DNS servers / timeout (used by the CLI flags)."""
    if nameservers:
        _resolver.nameservers = list(nameservers)
    if timeout:
        _resolver.timeout = float(timeout)
        _resolver.lifetime = float(timeout) * 2


def normalize_domain(value):
    """'  User@Example.com. ' -> 'example.com'"""
    value = (value or "").strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.rstrip(".")


def _get_txt(name):
    """Return (list_of_txt_strings, error_or_None). Never raises DNS errors."""
    try:
        answer = _resolver.resolve(name, "TXT")
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "No Answer"
    except dns.exception.Timeout:
        return [], "Timeout"
    except dns.resolver.NoNameservers:
        return [], "No Nameservers"
    except dns.exception.DNSException as exc:
        return [], type(exc).__name__
    records = ["".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
               for rdata in answer]
    return records, None


def _is_spf(record):
    r = record.strip().lower()
    return r == "v=spf1" or r.startswith("v=spf1 ")


# ---------------------------------------------------------------------------
# Original checks (same names + messages as before)
# ---------------------------------------------------------------------------
def domain_exists(domain):
    if not domain or len(domain) > 253:
        return False
    try:
        _resolver.resolve(domain, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True     # domain exists, just has no A record (common for mail-only domains)
    except dns.exception.DNSException:
        pass
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, UnicodeError):
        return False


def domain_assessment(domain, selector=None):
    """True if the domain resolves. (The old version also re-ran every check
    and threw the results away; the GUI/CLI run them once themselves.)"""
    return domain_exists(normalize_domain(domain))


def spf_check(domain):
    records, err = _get_txt(domain)
    if any(_is_spf(r) for r in records):
        return "Spf Record Found"
    return f"No SPF Record Was Found: {err}" if err else "No SPF Record Was Found"


def dkim_check(domain, selector):
    records, err = _get_txt(f"{selector}._domainkey.{domain}")
    if records:
        return "DKIM Record Found"
    return f"No DKIM Record Was Found: {err}" if err else "No DKIM Record Was Found"


def _dmarc_record(domain):
    records, err = _get_txt(f"_dmarc.{domain}")
    for r in records:
        if r.strip().lower().startswith("v=dmarc1"):
            return r, None
    return None, err


def dmarc_check(domain):
    record, err = _dmarc_record(domain)
    if record:
        return "DMARC Record Found"
    return f"No DMARC Record Was Found: {err}" if err else "No DMARC Record Was Found"


# ---------------------------------------------------------------------------
# SPF analysis (walks include: / redirect= chains)
# ---------------------------------------------------------------------------
def analyze_spf(domain):
    """
    Walk the domain's SPF record and everything it includes.

    Returns a dict:
      record     - the top-level SPF string (or None)
      includes   - {include_domain: [chain of domains that led to it]}
      lookups    - DNS-lookup mechanisms counted per RFC 7208 (limit is 10)
      all        - qualifier on the final 'all' ('-all', '~all', '?all', '+all', or None)
      warnings   - human-readable problems
    """
    state = {"record": None, "includes": {}, "lookups": 0, "all": None,
             "warnings": [], "visited": set()}

    def walk(name, chain, via_include):
        if name in state["visited"]:
            return
        state["visited"].add(name)
        records, err = _get_txt(name)
        spf = [r for r in records if _is_spf(r)]
        if not spf:
            state["warnings"].append(
                f"{name}: no SPF record ({err or 'no v=spf1 TXT record'})")
            return
        if len(spf) > 1:
            state["warnings"].append(
                f"{name}: multiple SPF records published (invalid, receivers return PermError)")
        record = spf[0].strip()
        if not chain[:-1] and state["record"] is None:
            state["record"] = record

        for term in record.split()[1:]:
            low = term.lower()
            if low.startswith("redirect="):
                target = low.split("=", 1)[1]
                state["lookups"] += 1
                if state["lookups"] <= _HARD_STOP:
                    walk(target, chain + [target], via_include)
                continue
            if low.startswith("exp="):
                continue
            qualifier = "+"
            if low[0] in "+-~?":
                qualifier, low = low[0], low[1:]
            mech = re.split(r"[:/=]", low, maxsplit=1)[0]
            value = low.partition(":")[2]

            if mech == "all":
                if not via_include:
                    state["all"] = "all" if qualifier == "+" and not term.startswith("+") \
                        else f"{qualifier}all"
            elif mech == "include" and value:
                state["lookups"] += 1
                state["includes"].setdefault(value, chain + [value])
                if state["lookups"] <= _HARD_STOP:
                    walk(value, chain + [value], True)
            elif mech in ("a", "mx", "ptr", "exists"):
                state["lookups"] += 1

    walk(domain, [domain], False)

    if state["record"] is None:
        state["warnings"].insert(0, "No SPF record found at the domain")
    else:
        if state["lookups"] > DNS_LOOKUP_LIMIT:
            state["warnings"].append(
                f"{state['lookups']} DNS lookups exceeds the limit of {DNS_LOOKUP_LIMIT} "
                "(receivers may return PermError)")
        if state["all"] is None:
            state["warnings"].append("SPF record has no 'all' mechanism")
        elif state["all"] in ("+all", "all"):
            state["warnings"].append("'+all' lets anyone send as this domain")
        elif state["all"] == "?all":
            state["warnings"].append("'?all' is neutral and provides no protection")

    del state["visited"]
    return state


# ---------------------------------------------------------------------------
# Sender validation
# ---------------------------------------------------------------------------
def list_senders():
    return {key: val["label"] for key, val in SENDERS.items()}


def resolve_sender(name):
    """Turn 'mailchimp' / 'Google Workspace' / 'include:servers.mcsv.net' into a profile dict."""
    raw = (name or "").strip().lower()
    key = raw.replace(" ", "-")
    key = SENDER_ALIASES.get(key, key)
    if key in SENDERS:
        profile = dict(SENDERS[key])
        profile["key"] = key
        return profile
    custom = raw[len("include:"):] if raw.startswith("include:") else raw
    if "." in custom and " " not in custom:
        return {"key": custom, "label": custom, "spf_includes": [custom],
                "dkim_selectors": [], "custom": True}
    raise ValueError(
        f"Unknown sender '{name}'. Use one of: {', '.join(sorted(SENDERS))} "
        "- or pass an SPF include domain such as servers.mcsv.net")


def validate_sender(domain, sender, selector=None, spf=None):
    """
    Check that `sender` is authorized for `domain`.

    SPF : is one of the provider's include domains anywhere in the SPF tree?
    DKIM: does any of the provider's selectors (plus `selector`, if given) exist?
    """
    domain = normalize_domain(domain)
    profile = resolve_sender(sender)
    spf = spf or analyze_spf(domain)

    matched, chain = None, None
    for inc in profile["spf_includes"]:
        if inc.lower() in spf["includes"]:
            matched, chain = inc.lower(), spf["includes"][inc.lower()]
            break

    selectors = list(profile["dkim_selectors"])
    if selector and selector not in selectors:
        selectors.append(selector)
    dkim = []
    for sel in selectors:
        records, err = _get_txt(f"{sel}._domainkey.{domain}")
        dkim.append({"selector": sel, "found": bool(records), "error": err})

    spf_ok = matched is not None
    dkim_ok = any(d["found"] for d in dkim)
    if selectors:
        status = "PASS" if (spf_ok and dkim_ok) else "PARTIAL" if (spf_ok or dkim_ok) else "FAIL"
    else:
        status = "PASS" if spf_ok else "FAIL"

    return {
        "sender": profile["label"],
        "status": status,
        "spf_authorized": spf_ok,
        "spf_expected": profile["spf_includes"],
        "spf_matched": matched,
        "spf_chain": chain,
        "dkim": dkim,
        "dkim_found": dkim_ok,
        "note": profile.get("note"),
    }


# ---------------------------------------------------------------------------
# One call for everything + text report (used by both GUI and CLI)
# ---------------------------------------------------------------------------
def run_full_assessment(domain, selector=None, sender=None):
    domain = normalize_domain(domain)
    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "valid": domain_exists(domain),
    }
    if not result["valid"]:
        return result

    spf = analyze_spf(domain)
    dmarc_rec, _ = _dmarc_record(domain)
    policy = re.search(r"\bp=(\w+)", dmarc_rec, re.I) if dmarc_rec else None

    result["spf"] = spf_check(domain)
    result["spf_details"] = {"record": spf["record"], "lookups": spf["lookups"],
                             "all": spf["all"], "warnings": spf["warnings"]}
    result["dkim"] = dkim_check(domain, selector) if selector else \
        "Skipped (no selector provided)"
    result["dmarc"] = dmarc_check(domain)
    result["dmarc_policy"] = policy.group(1).lower() if policy else None
    result["sender"] = validate_sender(domain, sender, selector, spf) if sender else None
    return result


def assessment_ok(result):
    """True if nothing is missing (used for CLI exit codes)."""
    if not result.get("valid"):
        return False
    good = (result["spf"].startswith("Spf Record Found")
            and result["dmarc"].startswith("DMARC Record Found")
            and not result["dkim"].startswith("No DKIM"))
    if result.get("sender"):
        good = good and result["sender"]["status"] == "PASS"
    return good


def format_report(result):
    if not result.get("valid"):
        return f"Error: '{result.get('domain', '')}' is not a valid domain."

    lines = [f"SPF: {result['spf']}"]
    det = result["spf_details"]
    if det["record"]:
        lines.append(f"     {det['lookups']}/{DNS_LOOKUP_LIMIT} DNS lookups, policy: {det['all'] or 'none'}")
    for w in det["warnings"]:
        lines.append(f"     ! {w}")
    lines.append(f"DKIM: {result['dkim']}")
    dmarc = f"DMARC: {result['dmarc']}"
    if result.get("dmarc_policy"):
        dmarc += f" (policy: {result['dmarc_policy']})"
    lines.append(dmarc)

    s = result.get("sender")
    if s:
        lines += ["", f"Sender: {s['sender']} -> {s['status']}"]
        if s["spf_authorized"]:
            lines.append(f"  SPF:  authorized via {' -> '.join(s['spf_chain'])}")
        else:
            lines.append(f"  SPF:  NOT found (expected include:{s['spf_expected'][0]})")
        if s["dkim"]:
            for d in s["dkim"]:
                state = "found" if d["found"] else f"missing ({d['error'] or 'empty'})"
                lines.append(f"  DKIM: {d['selector']}._domainkey - {state}")
        else:
            lines.append("  DKIM: no known selectors for this sender (use --selector)")
        if s.get("note"):
            lines.append(f"  Note: {s['note']}")

    stamp = datetime.fromisoformat(result["timestamp"]).strftime("%B %d, %Y at %I:%M %p")
    lines += ["", stamp]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------
def parse_batch_lines(lines):
    """
    One domain per line. Optional per-line overrides, comma separated:
        domain[,selector[,sender]]
    Blank lines and anything after '#' are ignored.
    """
    entries = []
    for number, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")][:3]
        parts += [""] * (3 - len(parts))
        entries.append({"line": number, "domain": parts[0],
                        "selector": parts[1] or None, "sender": parts[2] or None})
    return entries


def run_batch(entries, default_selector=None, default_sender=None, workers=5, progress=None):
    """Assess many domains concurrently. Results keep the input order; a failure on
    one domain is recorded on that domain and never stops the rest."""
    def one(entry):
        try:
            result = run_full_assessment(entry["domain"],
                                         entry["selector"] or default_selector,
                                         entry["sender"] or default_sender)
        except Exception as exc:
            result = {"domain": normalize_domain(entry["domain"]), "valid": False,
                      "error": str(exc)}
        result["line"] = entry["line"]
        if progress:
            progress(result)
        return result

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        return list(pool.map(one, entries))


def summarize(result):
    """Flatten one result into short fields for a table or CSV row."""
    row = {"domain": result.get("domain", ""), "overall": "", "spf": "-", "dkim": "-",
           "dmarc": "-", "dmarc_policy": "", "sender": "-", "detail": ""}
    if not result.get("valid"):
        row["overall"] = "ERROR" if result.get("error") else "INVALID"
        row["detail"] = result.get("error", "domain does not resolve")
        return row
    row["spf"] = "ok" if result["spf"].startswith("Spf Record Found") else "missing"
    if result["dkim"].startswith("Skipped"):
        row["dkim"] = "skipped"
    else:
        row["dkim"] = "missing" if result["dkim"].startswith("No DKIM") else "ok"
    row["dmarc"] = "ok" if result["dmarc"].startswith("DMARC Record Found") else "missing"
    row["dmarc_policy"] = result.get("dmarc_policy") or ""
    if result.get("sender"):
        row["sender"] = result["sender"]["status"]
    row["overall"] = "OK" if assessment_ok(result) else "ISSUES"
    return row


COLUMNS = [("domain", "DOMAIN"), ("overall", "OVERALL"), ("spf", "SPF"), ("dkim", "DKIM"),
           ("dmarc", "DMARC"), ("dmarc_policy", "POLICY"), ("sender", "SENDER")]


def render_table(rows):
    """Plain-text table of summarize() rows, with a problem list and totals."""
    widths = [max(len(title), *(len(str(r[key])) for r in rows)) for key, title in COLUMNS]
    line = lambda cells: "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)).rstrip()
    out = [line([t for _, t in COLUMNS]), line(["-" * w for w in widths])]
    out += [line([r[k] for k, _ in COLUMNS]) for r in rows]
    for r in rows:
        if r["detail"]:
            out.append(f"  ! {r['domain']}: {r['detail']}")
    counts = {}
    for r in rows:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1
    out += ["", f"{len(rows)} domains: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))]
    return "\n".join(out)


def rows_to_csv(rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=[k for k, _ in COLUMNS] + ["detail"],
                            extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().rstrip("\n")
