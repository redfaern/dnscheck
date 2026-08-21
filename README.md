# dnscheck

Hourly authoritative-DNS and DNSSEC health check for your own nameservers,
running unprivileged on a Raspberry Pi under systemd.

It answers one question every hour — *are all three nameservers serving these
zones, in agreement, correctly signed, and validating from outside?* — and
reports to healthchecks.io, which owns notification and the dead-man's switch.

## What it checks

Zones are declared one per row in `/etc/dnscheck/zones`, each carrying its own
nameservers, validators and expiry threshold. **Every** zone gets the service
checks; those declared `signed` additionally get the DNSSEC ones.

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
- **Signing** *(signed zones)* — an `RRSIG` exists over both the SOA and the
  DNSKEY RRset, and neither expires within that zone's `warn` threshold. The
  DNSKEY signatures are checked
  separately because the KSK resigns on its own schedule and can stall while
  the SOA's signatures still look fresh.
- **Chain of trust** *(signed zones)* — the zone's validators return the `AD`
  flag for a *random, never-before-queried* label in it. Random because
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
  its row says otherwise — reported, so its expiry does not go unwatched.

Nothing listens on a port. The only outbound destination is healthchecks.io.

## Zones

Each zone gets a row in `/etc/dnscheck/zones`, five whitespace-separated
columns:

```
# zone                state     warn  nameservers                    validators
example.com           signed    -     -                              -
example.net           signed    -     -                              -
example.org           unsigned  -     -                              -
legacy.example.com    signed    8     old1=192.0.2.7,old2=192.0.2.8  -
internal.example      signed    -     lan1=10.0.0.53,lan2=10.0.0.54  10.0.0.53
dmz.example.com       signed    -     dmz1=10.0.1.53                 none
```

| column | meaning |
|---|---|
| `zone` | the zone apex |
| `state` | `signed` or `unsigned` — **declared, not detected** |
| `warn` | alarm when a signature has fewer than this many days left |
| `nameservers` | `label=ip` pairs; the label names the server in every alert |
| `validators` | recursive resolvers that confirm the chain from outside |

`-` in any column takes the default from `dnscheck.env`, so an ordinary zone
stays one short row. Lists inside a column are separated by **commas**, because
a space there would start a new column; `dnscheck.env` accepts either, so a
list can be pasted between the two files unedited.

### What the per-zone columns are for

**Zones do not all live on the same nameservers.** A single global list can only
express "every zone is on every server", which cannot describe a split horizon,
a zone still parked on a previous provider, or an internal zone on internal
resolvers. Each row names its own, and the summary line reports whichever
servers that zone was actually checked against.

**A threshold tracks the signing policy, not the host.** The default of 3 days
is measured against the floor of BIND's resigning cycle. A zone signed
somewhere else, under a different policy, needs its own number rather than one
that alarms every cycle on a healthy zone.

**`validators none` is for a zone no outside resolver can see.** This one
matters more than it looks. Ask a public resolver about a name under a private
TLD and it answers `NXDOMAIN` — which the check counts as an answer, so an
internal zone reports **healthy forever while nothing about it has been
verified**. Declaring `none` says so out loud instead, on every run:

```
dmz.example.com: 1/1 NS up [dmz1:2026082011 aa 29d], no outside validation (validators none)
```

If you have an internal validating resolver, naming it in that column gets the
real check back.

### Turning DNSSEC on

Leave the zone `unsigned` until the parent publishes your `DS` record. Between
signing a zone and the registry adding the `DS`, every nameserver serves
signatures and no resolver validates them: the zone is *insecure, not broken*,
and resolves fine for everyone. Marked `signed` it alarms for however long that
takes; marked `unsigned` it keeps its reachability and agreement checks
throughout, and the moment the `DS` appears the check tells you the zone now
validates and should be moved. Flipping the column is the deliberate act that
starts watching its signatures.

If you do leave it `signed` through the changeover, the failure names the cause
rather than a symptom — the nameservers are fine, and being sent to look at
them is a wasted evening:

```
example.org: every nameserver serves signatures but no validator sees AD
(1.1.1.1 8.8.8.8) — the parent's DS record is missing or does not match, so the
zone is insecure rather than broken.
```

## Install

On a fresh Debian, Raspberry Pi OS or Ubuntu host. **Create the
healthchecks.io check first** — period **1 hour**, grace **15 min**, on a uuid
of its own — and have its ping URL to hand; step 4 needs it.

```sh
# 1. dependencies
sudo apt update
sudo apt install -y bind9-dnsutils curl

# 2. fetch and unpack — no git, no account, no SSH key
cd ~
curl -fsSL https://github.com/redfaern/dnscheck/archive/refs/heads/main.tar.gz | tar xz
cd dnscheck-main

# 3. see what would happen, then place the files
./deploy.sh --dry-run
sudo ./deploy.sh

# 4. put your defaults and ping URL in, then your zones
sudo nano /etc/dnscheck/dnscheck.env
sudo nano /etc/dnscheck/zones

# 5. confirm the run will use what you think it will
sudo /usr/local/lib/dnscheck/check-dns.sh --show-config
```

Then the four steps `deploy.sh` prints when it finishes — checks, sandbox,
alert path, arm:

```sh
sudo /usr/local/lib/dnscheck/check-dns.sh --no-ping        # 1. the checks
sudo systemctl start dnscheck.service                      # 2. the sandbox
sudo journalctl -u dnscheck -n 30 --no-pager
sudo systemctl enable --now dnscheck.timer                 # 4. arm it
```

Step 3 is the ALERT path, the step people skip, and the only one that proves
the notification actually reaches you. Point the check at a throwaway zone
table rather than your real one:

```sh
printf 'dnssec-failed.org signed - unreachable=192.0.2.1 -\n' > /tmp/alert.zones
sudo DNSCHECK_ZONES=/tmp/alert.zones /usr/local/lib/dnscheck/check-dns.sh
rm /tmp/alert.zones
```

`dnssec-failed.org` is maintained as a permanently broken zone for exactly
this, so the validators report a chain that will not validate, and the
unreachable address adds a second, different failure. It pings for real, so
the check goes down and then recovers on the next scheduled run.

To update later, repeat steps 2 and 3. `deploy.sh` is idempotent, reports what
it changed, and never touches an existing `dnscheck.env`.

### Other distributions

Anything with systemd 247+ (Debian 12, Ubuntu 22.04, Fedora 36, and later) and
GNU coreutils. Only the package manager differs — `dig` comes from
`bind9-dnsutils` on Debian and Ubuntu, `bind-utils` on Fedora, RHEL and
openSUSE, and `bind` on Arch. `deploy.sh` checks for `dig`, `curl` and the
systemd version, and names what is missing.

Not supported: macOS and the BSDs, which lack GNU `date -d` and `stat -c`; and
any host without systemd.

## Layout

| File | Goes to | Mode |
|---|---|---|
| `check-dns.sh` | `/usr/local/lib/dnscheck/` | 0755 root:root |
| `NOTES.md` | `/usr/local/lib/dnscheck/` | 0644 root:root |
| `dnscheck.env.example` | `/etc/dnscheck/dnscheck.env` | 0600 root:root, dir 0755 |
| `zones.example` | `/etc/dnscheck/zones` | 0644 root:root |
| `dnscheck.service`, `dnscheck.timer` | `/etc/systemd/system/` | 0644 root:root |

`dnscheck.env` holds `HC_URL`, which **is a credential** — anyone with it can
forge a check-in and keep the dead-man switch quiet while DNS is down. It is
gitignored, and only the `.example` is ever committed. systemd reads it as root
before dropping to the service user, so nothing unprivileged needs to read it —
and the ping passes it to `curl` through a config file on stdin rather than on
a command line, so it never appears in `ps` either.

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

To see what a run would actually use, and where each value came from:

```sh
sudo /usr/local/lib/dnscheck/check-dns.sh --show-config
```

That is not the same question as "what is in the file", which is all `grep` can
answer — it cannot show a quote that was stripped, a default that filled a gap,
an environment variable that won, or which of two duplicate lines was taken.
`HC_URL` is shown truncated, since it is a credential and this output is the
kind that gets pasted somewhere. It works before the config is valid, which is
when you most need it.

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
