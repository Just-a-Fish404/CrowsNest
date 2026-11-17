# CrowsNest - Email Security Record Checker

CrowsNest checks a domain's **SPF**, **DKIM** and **DMARC** DNS records and can verify that a
specific sending service (Mailchimp, SendGrid, Google Workspace, ...) is actually authorized to
send mail for that domain. It comes as a desktop GUI and a command-line tool built on the same
engine, so both always give the same answers.

It only reads public DNS records. It never contacts mail servers or sends email.

## Features

* **SPF / DKIM / DMARC lookup** with DMARC policy (`none`, `quarantine`, `reject`) shown
* **Sender validation**: confirms a provider's `include:` is in the SPF record, following nested
`include:` and `redirect=` chains, and shows the path that authorizes it
* **SPF health warnings**: more than 10 DNS lookups, `+all` / `?all`, missing `all`, duplicate SPF records
* **Batch mode**: check a whole list of domains, with table, CSV or JSON output
* **GUI** with a sender dropdown, "Load Domain List" and "Export CSV"
* **Scriptable CLI** with `--json` output and meaningful exit codes



## CLI

```
python src/crowsnest\_cli.py scan example.com -s google
python src/crowsnest\_cli.py scan example.com -s k2 --sender mailchimp
python src/crowsnest\_cli.py sender example.com mailchimp
python src/crowsnest\_cli.py sender example.com include:servers.mcsv.net --json
python src/crowsnest\_cli.py senders
python src/crowsnest\_cli.py batch examples/domains.txt --csv -o report.csv
```

|Command|What it does|
|-|-|
|`scan DOMAIN`|Full SPF/DKIM/DMARC assessment. `-s` sets the DKIM selector, `--sender` also validates a sender.|
|`sender DOMAIN SENDER`|Is this sending service authorized? `SENDER` is a name or `include:some.domain`.|
|`batch FILE`|Assess many domains. Use `-` to read from stdin.|
|`senders`|List the built-in sender names.|

Common options: `--json`, `--nameserver IP` (repeatable), `--timeout SEC`.
Batch options: `--csv`, `-o FILE`, `-w N` (domains at once, default 5), `-s` / `--sender` as defaults.

**Batch file format**: one domain per line; optionally `domain,selector,sender` to override the
defaults for that line. Blank lines and `#` comments are ignored. See `examples/domains.txt`.

**Exit codes**: `0` everything passed, `1` a record is missing or a sender is not fully
authorized, `2` invalid domain, unknown sender, or bad input.

### Example output (illustrative)

```
$ python src/crowsnest\_cli.py scan example.com -s k2 --sender mailchimp
SPF: Spf Record Found
     4/10 DNS lookups, policy: -all
DKIM: DKIM Record Found
DMARC: DMARC Record Found (policy: quarantine)

Sender: Mailchimp -> PASS
  SPF:  authorized via example.com -> servers.mcsv.net
  DKIM: k2.\_domainkey - found
  DKIM: k3.\_domainkey - found
```

## GUI

```
python src/gui.py
```

Enter a domain, optionally a DKIM selector and a sender, and click **Run Assessment**.
**Load Domain List** runs a batch from a text/CSV file and **Export CSV** saves the results.
tkinter ships with Python on Windows and macOS; on Debian/Ubuntu install `python3-tk`.
The window icon expects `crowsnest.png` next to `gui.py`.

## Built-in senders

`mailchimp`, `mandrill`, `sendgrid`, `google`, `microsoft365`, `amazon-ses`, `mailgun`,
`postmark`, `zendesk`. Aliases such as `gmail`, `m365` and `ses` work too. Any other service can be
checked by passing its SPF include domain directly (`include:example.net`).

Providers change their include domains and DKIM selectors from time to time. The table is the
`SENDERS` dictionary at the top of `src/CrowsNest.py`; check it against the provider's own
documentation and edit it freely.

## Limitations

* **Presence, not validity.** DKIM and DMARC checks confirm a record exists; they do not validate
signatures or parse every tag.
* **Include-based matching.** Sender validation looks for the provider's `include:` domain. A provider
authorized only through raw `ip4:`/`ip6:` ranges will show as not found.
* **SPF is not always required.** Some providers (Mailchimp, for example) typically send with their own
return-path, so a missing SPF include may be harmless there and DKIM matters more.
* **Selectors must be known.** DKIM selectors are not discoverable from DNS; the tool checks the
provider's usual selectors plus any you supply.

## Development

```
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The tests replace DNS with a fake zone, so they run offline. To build the Windows executables
(GUI and CLI), run `build\_exe.bat` from the repo root; output lands in `dist/`.

```
src/CrowsNest.py        core engine (shared by GUI and CLI)
src/crowsnest\_cli.py    command-line interface
src/gui.py              tkinter GUI
tests/                  offline unit tests
examples/domains.txt    sample batch file
```

## License

MIT - see [LICENSE](LICENSE).

