"""
CrowsNest CLI - same engine as the GUI.

Examples:
    python crowsnest_cli.py scan example.com -s google
    python crowsnest_cli.py scan example.com -s k2 --sender mailchimp
    python crowsnest_cli.py sender example.com mailchimp
    python crowsnest_cli.py sender example.com include:servers.mcsv.net --json
    python crowsnest_cli.py senders
    python crowsnest_cli.py batch domains.txt --sender mailchimp -s k2 --csv -o report.csv
    type domains.txt | python crowsnest_cli.py batch - --json

Batch file: one domain per line, optional per-line overrides "domain,selector,sender";
blank lines and # comments are ignored.

Exit codes:  0 = everything checked passed
             1 = a record was missing / sender not fully authorized
             2 = invalid domain, unknown sender, or bad usage
"""

import argparse
import json
import sys
import threading

import CrowsNest as cn

VERSION = "1.2.0"


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")
    common.add_argument("--nameserver", action="append", metavar="IP",
                        help="DNS server to query (repeatable), e.g. --nameserver 1.1.1.1")
    common.add_argument("--timeout", type=float, metavar="SEC", help="DNS timeout in seconds")

    parser = argparse.ArgumentParser(
        prog="crowsnest",
        description="CrowsNest - check a domain's SPF, DKIM and DMARC records.")
    parser.add_argument("--version", action="version", version=f"CrowsNest {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", parents=[common], help="full SPF/DKIM/DMARC assessment")
    scan.add_argument("domain")
    scan.add_argument("-s", "--selector", help="DKIM selector, e.g. google, selector1, k2")
    scan.add_argument("--sender", help="also verify this sender is authorized (e.g. mailchimp)")

    snd = sub.add_parser("sender", parents=[common],
                         help="verify a sending service is authorized for a domain")
    snd.add_argument("domain")
    snd.add_argument("sender", help="name (mailchimp, sendgrid, google...) or include:domain")
    snd.add_argument("-s", "--selector", help="extra DKIM selector to check")

    bat = sub.add_parser("batch", parents=[common], help="assess many domains from a file")
    bat.add_argument("file", help="text file with one domain per line, or - for stdin")
    bat.add_argument("-s", "--selector", help="default DKIM selector for every domain")
    bat.add_argument("--sender", help="default sender to verify for every domain")
    bat.add_argument("--csv", action="store_true", help="print one summary row per domain as CSV")
    bat.add_argument("-w", "--workers", type=int, default=5, metavar="N",
                     help="domains to check at once (default 5)")
    bat.add_argument("-o", "--output", metavar="FILE", help="write output to FILE instead of the screen")

    sub.add_parser("senders", help="list built-in sender names")
    return parser


def run_batch_command(args):
    try:
        if args.file == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.file, encoding="utf-8-sig") as handle:
                lines = handle.read().splitlines()
    except OSError as exc:
        print(f"Error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 2

    entries = cn.parse_batch_lines(lines)
    if not entries:
        print("Error: no domains found in input", file=sys.stderr)
        return 2

    done, lock = [0], threading.Lock()

    def progress(result):
        if not sys.stderr.isatty():
            return
        with lock:
            done[0] += 1
            print(f"[{done[0]}/{len(entries)}] {result['domain']}", file=sys.stderr)

    results = cn.run_batch(entries, args.selector, args.sender, args.workers, progress)
    rows = [cn.summarize(r) for r in results]

    if args.json:
        text = json.dumps(results, indent=2)
    elif args.csv:
        text = cn.rows_to_csv(rows)
    else:
        text = cn.render_table(rows)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            print(f"Error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {len(rows)} results to {args.output}", file=sys.stderr)
    else:
        print(text)

    return 0 if all(r["overall"] == "OK" for r in rows) else 1


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "senders":
        for key, label in sorted(cn.list_senders().items()):
            print(f"{key:<14} {label}")
        return 0

    cn.configure_resolver(args.nameserver, args.timeout)

    try:
        sender = args.sender
        if sender:
            cn.resolve_sender(sender)   # fail fast on a typo before doing any DNS
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.command == "batch":
        return run_batch_command(args)

    result = cn.run_full_assessment(args.domain, args.selector, sender)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(cn.format_report(result))

    if not result["valid"]:
        return 2
    if args.command == "sender":
        return 0 if result["sender"]["status"] == "PASS" else 1
    return 0 if cn.assessment_ok(result) else 1


if __name__ == "__main__":
    sys.exit(main())
