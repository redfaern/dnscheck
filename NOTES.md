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
account, so it nags for the Minecraft dead-man switch too, without a second
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

**The script reads its own config; it does not rely on systemd.** Under the
timer, `EnvironmentFile=` and the script's own read are equivalent. By hand they
are not — a terminal run gets no `EnvironmentFile`, so the script used to fall
back to built-in defaults: checking whatever was compiled in rather than what is
configured, and finding `HC_URL` empty. Every documented verification step is a
manual run, which made the configuration the one thing they could not verify.
`NS`, `ZONES` and `HC_URL` now have no defaults at all — a fallback for those is
how a misconfigured run comes to look like a passing one.

**The config is parsed, not sourced.** The format is systemd's
`EnvironmentFile`, and bash disagrees with systemd about the most ordinary line
in it: `ZONES=a.com b.com` is one value to systemd, but to bash it is two
assignments — `ZONES` becomes just `a.com`, and `b.com` becomes a stray variable
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
mismatch that survives — the same rule the Minecraft watchdog uses for RCON.

**Its own healthchecks UUID.** Sharing mcsuper's would let a healthy Minecraft
update keep the DNS check looking alive, which is precisely the failure a
dead-man switch exists to catch. Same argument as "only `mcsuper update` pings".

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

# 3. The ALERT path, not just the ping path. Point ZONES at a zone that is
#    permanently broken on purpose (dnssec-failed.org is maintained for exactly
#    this) and confirm the notification actually reaches you.
sudo ZONES=dnssec-failed.org /usr/local/lib/dnscheck/check-dns.sh

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
| UUID | its own, never mcsuper's |

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
- **A zone is only checked once it is in `ZONES`.** Nothing discovers a newly
  signed zone; adding one is a config edit. That is the same consent-by-edit
  rule used elsewhere here, but it does mean a zone can be live and unmonitored
  until someone remembers it.
- **Cross-attestation with mcsuper, unbuilt.** mcsuper's weekly heartbeat
  already reports the backup and watch timestamps as content, so one pulse
  attests to all three timers (SPEC 7.3). Adding dnscheck's last-run timestamp
  to that body would close the "healthchecks.io itself is down" gap over a
  genuinely independent channel — without giving this script a second emitter,
  because the reporting still happens inside `mcsuper update`. Cheap, and the
  right shape. Say the word and I will do it as an mcsuper change.
- **No DS-vs-DNSKEY comparison at the parent.** The AD-flag probe catches a
  broken DS *after* it breaks. Comparing the parent's DS to the zone's DNSKEY
  would catch a mismatched key mid-rollover, before it breaks. Deliberately left
  out to keep this simple; worth adding if you ever roll the KSK by hand.
