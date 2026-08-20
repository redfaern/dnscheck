# dnscheck — hourly DNS + DNSSEC health check

Checks your authoritative nameservers for reachability, authority,
zone-transfer agreement, signature freshness, and a working chain of trust —
then reports to healthchecks.io, which owns notification and the dead-man's
switch.

## Settled: healthchecks.io is the only notification channel

Decided 2026-08-21. The script has exactly one outbound destination. It does not
call ntfy.sh, and it should not be "improved" later by adding a second channel
without revisiting the reasoning below.

healthchecks.io owns the alerting; you attach whatever delivery you want to it
at their end (ntfy, email, Pushover — its own integration, on its own check).
That is a delivery choice you can change in a web UI, not a change to this
script.

Why one channel is the ROBUST answer here, not merely the simple one:

- **Deduplication is a robustness property, not a convenience.**
  healthchecks.io notifies on the *transition* down and up, once each. A direct
  push from an hourly script means 24 alerts a day for as long as the outage
  lasts. You mute the channel on day two — and a muted channel is a monitor
  that has failed, right before the one that matters.
- **The alert and the dead-man switch cannot disagree.** With two emitters,
  "DNS is broken" and "the check stopped running" can arrive from different
  places, in either order, and you have to reconcile them at 2am. With one,
  down is down.
- **Silence has exactly one meaning.** A second channel means an absent message
  could be a quiet network, a quiet script, or a quiet service. That ambiguity
  is what the switch exists to remove.
- **One thing to configure, one thing to test.** A ping URL that is right and a
  topic name that is wrong is a monitor that looks armed and is not.
- **The detail still arrives.** The script POSTs the problem list as the ping
  body; healthchecks.io puts it in the notification. You get the actual lines,
  not just "check went down".

The cost, stated plainly: if healthchecks.io itself is unreachable while DNS is
broken, no alert goes out. Two things narrow that. The unit exits non-zero on
any problem, so `systemctl --failed` and `journalctl -u dnscheck` hold the
record locally. And a failed ping is itself reported — see "Still open" for the
cross-attestation idea that closes the rest of it without adding a channel.

## Settled: instant ntfy alert, plus a daily email reminder

Decided 2026-08-21. Free, no subscription. Two deliveries, both attached to the
healthchecks.io check — the script itself still has exactly one outbound
destination, so this does not reopen the single-emitter decision above.

| | |
|---|---|
| Detection | ntfy integration → the dnscheck topic. Instant push, carries the problem lines. |
| Reminder | Account Settings › Email Reports › **daily** reminders, while any check is down. |
| Recovery | ntfy, on the up transition. |

**Why the nag lives at healthchecks.io and not in this script.** You asked for a
reminder every 6 hours until fixed. A loop in `check-dns.sh` could do exactly
that, and it would be the wrong place: if the host loses power, a nag living
on that host dies with it. The host being dead is precisely when you need reminding,
and only something outside the box can do it. A reminder that fires for "DNSSEC
broke" but goes silent for "the Pi is gone" is aimed at the wrong half of the
problem.

**Why daily and not 6-hourly.** healthchecks.io has no per-check repeat
interval; the built-in reminder is hourly or daily, account-wide. Daily is the
deliberate pick — the instant ntfy push is what tells you something broke, and
the email is only the backstop for having missed or cleared it. Hourly email for
a three-day outage is 72 messages and a filter rule, which is how a backstop
stops being one.

**Account-wide is a feature here.** The reminder covers every down check in the
account, so it nags for every other check you have there too, without a second
thing to configure.

**Declined: Pushover on Emergency priority.** It repeats every 5 minutes until
deliberately acknowledged, which is a stronger guarantee than any timer — but it
is a paid app, and the instant-push-plus-daily-backstop covers the realistic
failure. Recorded so it is not re-proposed as a free option; it is not one.

**The gap this leaves, stated plainly.** A problem that starts just after the
daily reminder goes out, on a day you also missed the ntfy push, waits up to 24
hours for the next nudge. Accepted knowingly: the push is the primary signal and
the email is a safety net, not a schedule.

## Design notes

**Signed and unsigned zones are DECLARED, not detected.** `SIGNED_ZONES` gets
the full DNSSEC checks; `UNSIGNED_ZONES` gets reachability, authority and serial
agreement only. Both lists are optional individually — a site with no signed
zones is not a misconfigured site.

Auto-detecting it would be easy and wrong. "This zone has no DNSKEY, so it must
be unsigned" reclassifies a zone whose signing has STOPPED as working exactly as
intended — the precise failure the tool exists to catch, converted into silence.
Being signed is a fact about your intent, so you state it, and moving a zone
between the lists is the deliberate act of changing that intent.

Both errors are caught rather than assumed away. An unsigned zone in
`SIGNED_ZONES` alarms about RRSIGs that were never meant to exist, loudly and
immediately. A signed zone in `UNSIGNED_ZONES` is reported the first time a
validator returns AD for it — that direction is the expensive one, because the
zone works fine while its signature expiry goes unwatched.

**`WARN_DAYS` is measured against the resigning floor, not the signature
lifetime.** BIND's default policy issues RRSIGs valid for 14 days and refreshes
them 5 days before expiry, so remaining life sawtooths between 14 and 5. It is
*supposed* to reach 5 and jump back. A threshold anywhere in that band fires on
a healthy zone: 7 would alarm for the two days of every nine-day cycle the zone
spends between 7 and 5 days left — about a fifth of all time, permanently.

The shipped value is 3, two days under the refresh point, leaving room for the
resign itself, the transfer to the secondaries, and the jitter BIND applies so
signatures do not all come due together. Hitting 3 means resigning is two days
overdue, with three days left before validating resolvers begin to fail.

The general rule, for any policy: a couple of days below the REFRESH threshold.
Deriving it from the validity interval instead is the mistake — those are
different numbers, and only one of them is the floor.

**A missing signature is diagnosed once, by the zone, not six times by the
nameservers.** One nameserver cannot tell "signing broke on this box" from
"this zone was never signed and is in the wrong list", and those two want
opposite actions. So the per-server findings are collected and the judgement is
made after every nameserver and both validators have been heard from:

- **Unanimous** — no nameserver serves signatures, no validator sees AD. That
  is not a zone whose signing broke; it is an unsigned zone in the wrong list,
  and it says so in one line. The absent AD is the same fact restated, so it is
  not reported again.
- **Partial** — some servers serve signatures and others do not. That one IS a
  fault, and a serious one, so the offending server is named.

The first version reported eight problems for an unsigned zone added to
`SIGNED_ZONES`, none of which named the cause. Eight accurate symptoms that
leave you to work out the diagnosis are worse than one line that has already
done it — an alert is only worth sending if it tells you what to do.

**There is no way to tell a public resolver to skip its cache, so the query is
made uncacheable instead.** DNS has no "bypass cache" flag — recursion either
happens or it does not — and 1.1.1.1 will not take instructions about its own
cache. What CAN be controlled is the name asked about: a label that has never
been queried has nothing cached against it, so the resolver is forced to do the
work now. The label carries the epoch second as well as a random number,
because `$RANDOM` alone can repeat, and a repeat inside the zone's negative-
cache TTL would be served from cache — quietly turning the one query that must
not be cached into one that was.

**What remains cached, and why that is correct.** The label is fresh, but the
material used to validate it — the parent's DS, the zone's DNSKEY, the NS
records — is cached by the resolver for its TTL. So a chain that broke five
minutes ago can still validate until that cached material expires. This is not
worked around, because it is not an error: the resolver's cache state IS what
real users experience. A probe that bypassed it would report a breakage nobody
is yet suffering, and, more misleadingly, report one as fixed before it
actually is for anyone.

The consequence to accept: a broken chain is detected within the DNSKEY/DS TTL
rather than instantly. Closing that gap properly means comparing the parent's
DS against the zone's DNSKEY directly from the authoritative servers, where no
resolver cache is involved at all — see "Still open".

**For unsigned zones the validator probe asks a different question.** AD is
absent by definition, so its absence proves nothing. What is worth knowing is
whether the zone RESOLVES: a SERVFAIL from a validating resolver usually means a
DS record left behind at the parent, which breaks the zone for every validating
resolver on the Internet while it still answers perfectly from its own
nameservers. Nothing on the authoritative side can see that.

**Serials are compared per zone, never between zones.** Every nameserver must
agree about a given zone; two zones having different serials is normal and says
nothing. The question being asked is "are all my nameservers serving the same
version of this zone", which is a within-zone question.


**The script reads its own config; it does not rely on systemd.** Under the
timer, `EnvironmentFile=` and the script's own read are equivalent. By hand they
are not — a terminal run gets no `EnvironmentFile`, so the script used to fall
back to built-in defaults: checking whatever was compiled in rather than what is
configured, and finding `HC_URL` empty. Every documented verification step is a
manual run, which made the configuration the one thing they could not verify.
`NS`, the zone lists and `HC_URL` now have no defaults at all — a fallback for those is
how a misconfigured run comes to look like a passing one.

**The config is parsed, not sourced.** The format is systemd's
`EnvironmentFile`, and bash disagrees with systemd about the most ordinary line
in it: `SIGNED_ZONES=a.com b.com` is one value to systemd, but to bash it is
two assignments — it becomes just `a.com`, and `b.com` becomes a stray variable
nothing reads. It does not error. A config listing three nameservers would
quietly check one and report "1 of 1 up": a green check that had stopped
watching two thirds of what it was pointed at.

Demanding quotes would fix bash's reading at the cost of rejecting every config
written the way systemd documents it — including one already deployed and
working. So the script parses the systemd way instead: rest-of-line is the
value, surrounding quotes stripped if present. Quoted or not, the timer and the
terminal read the file identically. It also means nothing in the config is ever
executed, which sourcing could not promise.
## Design notes

**A random label, not the apex.** The draft asked the validator for the zone's
own SOA. That record sits in 1.1.1.1's cache for its TTL, so on a broken zone
you can get a validated answer that predates the breakage — the check goes green
for up to an hour after DNSSEC stops working. Querying
`dnscheck-<random>.<zone>` cannot be cached, forces a full resolution now, and
exercises the NSEC/NSEC3 denial-of-existence proof. That is the half of DNSSEC
that breaks quietly: a zone can serve perfectly signed positive answers while
its negative proofs are broken.

**Two validators.** With one, "1.1.1.1 is having a bad afternoon" and "your
chain of trust is broken" are the same alert. They are not the same problem.

**The AA flag, not just an answer.** A nameserver that has dropped your zone can
still reply. Checking only for a non-empty answer treats "replied" as "still
authoritative for this zone", which is exactly the failure a config typo or a
failed reload produces.

**DNSKEY signatures too, not just the SOA's.** The DNSKEY RRset is signed by the
KSK on its own schedule. Its signatures can expire while the SOA's are fresh, so
a SOA-only check misses a stalled KSK resign until the zone goes dark.

**Serial mismatch needs two strikes.** Serials disagreeing for a few seconds
after a NOTIFY is normal, healthy behaviour. Alarming on first sight pages you
for a working system. The script re-queries after 20s and only reports a
mismatch that survives: two strikes, not one.

**Its own healthchecks UUID.** Sharing one with another check would let that
check's healthy pings keep this one looking alive, which is precisely the
failure a dead-man switch exists to catch. The same argument is why only one
thing here ever pings: a second emitter on the same uuid keeps the switch quiet
for a monitor that has stopped.

**systemd, not cron.** A timer gives overlap protection (a second start while
one is running is queued, not run concurrently), `RuntimeMaxSec` for a hung
`dig`, jitter so it does not fire on the hour with every other job on the
Internet, `Persistent=true` to re-arm the switch after a reboot, the sandbox,
and — via `DynamicUser=yes` — the dedicated unprivileged account without an
account to create, remember, or forget to lock.

## Deploy

```sh
sudo apt install bind9-dnsutils curl        # dig, if not already present

sudo install -d -m 0755 /usr/local/lib/dnscheck
sudo install -m 0755 -o root -g root check-dns.sh /usr/local/lib/dnscheck/
sudo install -m 0644 -o root -g root NOTES.md    /usr/local/lib/dnscheck/

sudo install -d -m 0700 /etc/dnscheck
sudo install -m 0600 -o root -g root dnscheck.env.example /etc/dnscheck/dnscheck.env
sudo nano /etc/dnscheck/dnscheck.env         # paste the HC_URL, confirm the IPs

sudo install -m 0644 dnscheck.service dnscheck.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

Verify before arming, in this order:

```sh
# 1. The checks themselves, without touching healthchecks.io. The script reads
#    /etc/dnscheck/dnscheck.env itself, so this exercises the REAL config —
#    but run it as root, because that file is 0600.
sudo /usr/local/lib/dnscheck/check-dns.sh --no-ping

# 2. The sandbox — the run above proves the checks work under the real user.
#    This proves the unit file does not block them.
sudo systemctl start dnscheck.service
sudo journalctl -u dnscheck -n 30 --no-pager
# sudo on journalctl matters: without it you get "-- No entries --" rather
# than an error, unless your account is in the adm or systemd-journal group.

# 3. The ALERT path, not just the ping path. Point SIGNED_ZONES at a zone that is
#    permanently broken on purpose (dnssec-failed.org is maintained for exactly
#    this) and confirm the notification actually reaches you.
sudo SIGNED_ZONES=dnssec-failed.org /usr/local/lib/dnscheck/check-dns.sh

# 4. Arm it.
sudo systemctl enable --now dnscheck.timer
systemctl list-timers dnscheck.timer
```

Step 3 is the one people skip. A dead-man switch you have never seen trip is a
hypothesis, not a monitor.

One more, once, and then never again — verifying the REMINDER, not just the
alert:

```sh
# Leave the check down overnight on purpose: stop the timer, wait out the
# period + grace, and go to bed.
sudo systemctl stop dnscheck.timer
```

Next morning you should have both the ntfy push (from the down transition) and
the daily reminder email. If the email is missing, it is in spam — find it and
whitelist the sender now, while you are looking for it deliberately, rather than
during the outage it was bought for. Then `sudo systemctl start dnscheck.timer`
and confirm the up transition arrives too.

## healthchecks.io check settings

| | |
|---|---|
| Period | 1 hour |
| Grace | 15 min — see the arithmetic below |
| Integration | ntfy → the dnscheck topic, on THIS check only |
| Reminders | Account Settings › Email Reports › daily (account-wide) |
| UUID | its own, never shared with another check |

The delivery choice lives here and nowhere else, which is the point: changing
how you are told is a web-UI edit, not a change to a script running as root's
timer on the Pi.

### Why 15 minutes of grace, and not 5 or 10

Grace has to cover the largest possible gap between two consecutive pings.
healthchecks.io alerts at `last_ping + period + grace`, and the ping is sent at
the END of a run, so the gap is the schedule interval plus however much the run
durations differ.

With the ORIGINAL timer, `RandomizedDelaySec=300` was re-rolled before every
iteration, so a run at :00 could be followed by one at :05 — a 65-minute gap
from the schedule alone, before counting run time:

| Grace | Alerts at | Largest real gap | Verdict |
|---|---|---|---|
| 5 min | 65 min | 65 min + run-time swing | trips within days |
| 10 min | 70 min | 65 min + run-time swing (up to ~5 min) | trips eventually |
| 15 min | 75 min | 65 min + swing | survives, but on jitter it did not need |

`FixedRandomDelay=yes` removes the schedule term entirely — the offset is now
derived from the machine ID and unit name, so it is the same every firing.
Consecutive runs are a flat 60 minutes apart and grace only has to absorb the
difference in run durations: seconds when healthy, up to ~5 minutes when
everything is timing out. Largest gap becomes ~65 min, alert at 75 min, margin
~10 min.

**So: period 1 hour, grace 15 minutes** — with `FixedRandomDelay=yes` set. Grace
10 would also work now, but 15 costs nothing, and here is why:

**Grace only delays the DEAD-MAN alert, never the DNS alert.** A DNS or DNSSEC
problem pings `/fail`, which marks the check down the moment healthchecks.io
receives it — period and grace are not consulted at all. Grace governs one
question only: how long silence must last before "the script or the host has
stopped" is declared. Ten extra minutes of certainty there is cheap; a false
"your DNS monitoring is dead" at 3am, twice a month, is not.

## Still open

- **Nothing validates `NS` against the delegation.** The addresses in the
  config are taken on trust, so a wrong or renumbered one is reported as a
  server that is down rather than one that has moved. Comparing the configured
  set against the parent's NS RRset would catch it — left out deliberately,
  because it means trusting a lookup to tell you whether lookups work.
- **A zone is only checked once it is in one of the lists.** Nothing discovers
  a new zone; adding one is a config edit, as is moving a newly signed zone from
  `UNSIGNED_ZONES` to `SIGNED_ZONES`. That is the same consent-by-edit rule used
  elsewhere here, and the AD-on-an-unsigned-zone check covers the second half of
  it — but a zone can still be live and entirely unmonitored until someone
  remembers to add it.
- **Cross-attestation, unbuilt.** If the host already runs another monitor
  that reports on its own schedule over a different channel, having THAT one
  carry dnscheck's last-run timestamp as content would close the
  "healthchecks.io itself is unreachable" gap — a stale date in a message that
  still arrives. It costs this script nothing and adds no second emitter here,
  because the reporting happens entirely in the other tool. Not built: it
  belongs in whatever that other monitor is, not in this repo.
- **No DS-vs-DNSKEY comparison at the parent.** The AD-flag probe catches a
  broken DS *after* it breaks. Comparing the parent's DS to the zone's DNSKEY
  would catch a mismatched key mid-rollover, before it breaks. Deliberately left
  out to keep this simple; worth adding if you ever roll the KSK by hand.
