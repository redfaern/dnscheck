# dnscheck

Hourly authoritative-DNS and DNSSEC health check for your own nameservers,
running unprivileged on a Raspberry Pi under systemd.

It answers one question every hour — *are all three nameservers serving these
zones, in agreement, correctly signed, and validating from outside?* — and
reports to healthchecks.io, which owns notification and the dead-man's switch.

## What it checks

Zones are declared in two lists. **Both** lists get the service checks;
`SIGNED_ZONES` additionally gets the DNSSEC ones.

Per zone, against each nameserver you list:

- **Reachability** — the server answers at all, within 6s.
- **Authority** — the answer carries the `AA` flag. A box that has dropped your
  zone still replies; "replied" is not "still authoritative".
- **Agreement** — SOA serials match across every nameserver, per zone. Zones are
  compared against themselves, never against each other: two zones having
  different serials is normal, three nameservers disagreeing about one zone is
  not.
  A mismatch is re-checked after 20s before it is reported, because disagreeing
  for a few seconds after a NOTIFY is normal, healthy behaviour.
- **Signing** *(signed zones)* — an `RRSIG` exists over both the SOA and the DNSKEY RRset, and
  neither expires within `WARN_DAYS`. The DNSKEY signatures are checked
  separately because the KSK resigns on its own schedule and can stall while
  the SOA's signatures still look fresh.
- **Chain of trust** *(signed zones)* — two public validators return the `AD`
  flag for a *random, never-before-queried* label in the zone. Random because
  the apex sits in every resolver's cache, so asking for it can return a
  validated answer from before the breakage; and a random label also exercises
  the NSEC/NSEC3 denial-of-existence proof, which is the half of DNSSEC that
  breaks quietly.
- **Resolvability** *(unsigned zones)* — the same random label must not draw a
  `SERVFAIL` from a validating resolver. An unsigned zone cannot produce `AD`,
  so its absence proves nothing; but SERVFAIL usually means a DS record left
  behind at the parent, which breaks the zone for every validating resolver on
  the Internet while it still answers perfectly from its own nameservers. Only
  an outside view catches that. If `AD` *does* appear, the zone is signed and
  in the wrong list — reported, so its signature expiry does not go unwatched.

Nothing listens on a port. The only outbound destination is healthchecks.io.

## Layout

| File | Goes to | Mode |
|---|---|---|
| `check-dns.sh` | `/usr/local/lib/dnscheck/` | 0755 root:root |
| `NOTES.md` | `/usr/local/lib/dnscheck/` | 0644 root:root |
| `dnscheck.env.example` | `/etc/dnscheck/dnscheck.env` | 0600 root:root, dir 0755 |
| `dnscheck.service`, `dnscheck.timer` | `/etc/systemd/system/` | 0644 root:root |

`dnscheck.env` holds `HC_URL`, which **is a credential** — anyone with it can
forge a check-in and keep the dead-man switch quiet while DNS is down. It is
gitignored, and only the `.example` is ever committed. systemd reads it as root
before dropping to the service user, so nothing unprivileged needs to read it.

The check runs under `DynamicUser=yes`: a transient unprivileged account with no
shell, no home, no password, and nothing left behind.

## Use

```sh
sudo ./deploy.sh --dry-run     # show every action, change nothing
sudo ./deploy.sh               # place files, set modes, report what is missing
bash test-parse.sh             # offline; no network, no dig, no DNS
```

`deploy.sh` is deliberately **not** an installer. It places files and tells you
what is still to do; it never writes `dnscheck.env`, never invents an `HC_URL`,
and never arms the timer. Configuration and arming are yours.

`check-dns.sh --no-ping` runs every check and prints the report without
contacting healthchecks.io, so testing a change cannot mark the check up or fire
a false alert.

The script parses `/etc/dnscheck/dnscheck.env` itself rather than depending on
systemd to hand it over, so a run by hand and a run under the timer check the
same thing. That file is 0600 root:root, so **run it with sudo** — otherwise it
cannot read the config and says so, rather than quietly checking nothing.

For logs, `sudo journalctl -u dnscheck`. Without sudo, journalctl prints
`-- No entries --` rather than an error, unless your account is in `adm` or
`systemd-journal`.

## healthchecks.io

Period **1 hour**, grace **15 min**, on its own UUID — never shared with
another check. Reminders via *Account Settings › Email Reports › daily*.

Grace only governs how long silence must last before "the script or the host has
stopped" is declared. A DNS problem pings `/fail`, which marks the check down
immediately; period and grace are not consulted.

## Read this before changing anything

[NOTES.md](NOTES.md) carries the reasoning: which decisions are settled and why,
the grace-period arithmetic, why the nag lives at healthchecks.io rather than in
this script, and what is deliberately left undone.
