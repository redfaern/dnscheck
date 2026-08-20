#!/usr/bin/env bash
# deploy.sh — put this repo onto the Pi, in the right places with the right modes.
#
# Deliberately NOT an installer. It does not create a healthchecks.io check, it
# does not write dnscheck.env, and it will not invent an HC_URL. Configuration
# is yours: this script only places files, sets permissions, and tells you what
# is still missing. Run it as often as you like — it is idempotent.
#
# Run from a checkout on the Pi:   sudo ./deploy.sh
# See what it would do first:      ./deploy.sh --dry-run

set -euo pipefail

LIB_DIR=/usr/local/lib/dnscheck
CONF_DIR=/etc/dnscheck
UNIT_DIR=/etc/systemd/system
CONF_FILE="$CONF_DIR/dnscheck.env"

DRY_RUN=0
NO_RELOAD=0

usage() {
    cat <<'USAGE'
deploy.sh — install the dnscheck files onto this host

  --dry-run     print every action, change nothing. Safe to run as yourself.
  --no-reload   skip "systemctl daemon-reload" (for staging a change).
  --help        this text

Places:
  /usr/local/lib/dnscheck/     check-dns.sh, NOTES.md      0755 root:root
  /etc/dnscheck/               config directory            0755 root:root
  /etc/dnscheck/dnscheck.env   your config                 0600 root:root
  /etc/systemd/system/         dnscheck.{service,timer}    0644 root:root

Never touched: an existing dnscheck.env. The .example is only ever copied in
when no config exists at all, and even then it is left for you to edit — the
timer is not enabled by this script.
USAGE
}

while (($#)); do
    case $1 in
        --dry-run)   DRY_RUN=1 ;;
        --no-reload) NO_RELOAD=1 ;;
        -h|--help)   usage; exit 0 ;;
        *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

cd "$(dirname "$(readlink -f "$0")")"

say()  { printf '%s\n' "$*"; }
run() {
    if ((DRY_RUN)); then
        printf '  would: %s\n' "$*"
    else
        "$@"
    fi
}

if ((!DRY_RUN)) && ((EUID != 0)); then
    say 'deploy.sh writes to /usr/local/lib, /etc and /etc/systemd/system — run it with sudo.'
    say 'To see what it would do without root:  ./deploy.sh --dry-run'
    exit 1
fi

todo=0
# todo=$((todo + 1)), NOT ((todo++)). Post-increment evaluates to the OLD value,
# so the very first call is ((0)) — false — which is exit status 1, and under
# `set -e` that kills the script silently at the exact moment it first has
# something to report. An assignment always returns 0.
note() { todo=$((todo + 1)); printf '  %d. %s\n' "$todo" "$1"; }

# Compare before copying, so a re-run over unchanged files says so rather than
# printing a wall of "installed" that means nothing.
sync_file() {  # sync_file <src> <dest> <mode>
    local src=$1 dest=$2 mode=$3
    if [[ -f $dest ]] && cmp -s "$src" "$dest"; then
        local cur
        cur=$(stat -c '%a' "$dest" 2>/dev/null || echo '')
        if [[ $cur == "$mode" ]]; then
            printf '  unchanged: %s\n' "$dest"
            return 0
        fi
        printf '  mode %s -> %s: %s\n' "$cur" "$mode" "$dest"
        run chmod "$mode" "$dest"
        return 0
    fi
    printf '  install:   %s\n' "$dest"
    run install -m "$mode" -o root -g root "$src" "$dest"
}

say '== dnscheck deploy =='
((DRY_RUN)) && say '(dry run — nothing will be changed)'
say ''

# --- prerequisites -----------------------------------------------------------
say 'checking prerequisites'
for cmd in dig curl systemctl; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  found:     %s\n' "$cmd"
    else
        printf '  MISSING:   %s\n' "$cmd"
        case $cmd in
            dig)  note 'install dig:  sudo apt install bind9-dnsutils' ;;
            curl) note 'install curl: sudo apt install curl' ;;
            *)    note "install $cmd" ;;
        esac
    fi
done

# FixedRandomDelay= in the timer needs systemd 247. Bookworm ships 252, but say
# so rather than let the timer silently fall back to a re-rolled delay — which
# would widen the ping interval and, eventually, trip the dead-man switch for
# no reason at all.
if command -v systemctl >/dev/null 2>&1; then
    sd_ver=$(systemctl --version | awk 'NR==1{print $2}')
    if [[ $sd_ver =~ ^[0-9]+$ ]] && ((sd_ver < 247)); then
        printf '  systemd:   %s — TOO OLD\n' "$sd_ver"
        note "systemd $sd_ver does not support FixedRandomDelay= (needs 247+). The timer will still run, but the ping interval will vary by up to 5 min — widen the healthchecks.io grace to 20 min if you cannot upgrade."
    else
        printf '  systemd:   %s\n' "$sd_ver"
    fi
fi
say ''

# --- the script and its notes ------------------------------------------------
say "placing the check in $LIB_DIR"
run install -d -m 0755 -o root -g root "$LIB_DIR"
sync_file check-dns.sh "$LIB_DIR/check-dns.sh" 0755
sync_file NOTES.md     "$LIB_DIR/NOTES.md"     0644
say ''

# --- configuration -----------------------------------------------------------
# 0755 on the directory, 0600 on the file. The file mode is the whole security
# boundary — HC_URL is a credential and only root reads it, because systemd
# parses EnvironmentFile before dropping to the service user. Locking the
# DIRECTORY as well adds nothing against anyone who cannot already read the
# file, while making /etc/dnscheck the one directory under /etc that a normal
# account cannot even list. Surprising is its own kind of bug.
say "configuration in $CONF_DIR"
run install -d -m 0755 -o root -g root "$CONF_DIR"
# install -d does not change an existing directory's mode, so repair it: an
# earlier version of this script created it 0700.
if [[ -d $CONF_DIR ]]; then
    dir_mode=$(stat -c '%a' "$CONF_DIR" 2>/dev/null || echo '')
    if [[ -n $dir_mode && $dir_mode != 755 ]]; then
        printf '  mode %s -> 755: %s\n' "$dir_mode" "$CONF_DIR"
        run chmod 0755 "$CONF_DIR"
    fi
fi

if [[ -f $CONF_FILE ]]; then
    printf '  keeping:   %s (never overwritten)\n' "$CONF_FILE"
    cur=$(stat -c '%a' "$CONF_FILE" 2>/dev/null || echo '')
    if [[ $cur != 600 ]]; then
        printf '  mode %s -> 600: %s\n' "$cur" "$CONF_FILE"
        run chmod 0600 "$CONF_FILE"
        run chown root:root "$CONF_FILE"
    fi
    # Every placeholder, not just the URL. A config with the real HC_URL but
    # the example's documentation-range nameservers still in it would ping
    # healthchecks.io happily every hour while checking nothing that exists.
    grep -q 'PUT-THE-DNSCHECK-UUID-HERE' "$CONF_FILE" 2>/dev/null \
        && note "$CONF_FILE still has the placeholder HC_URL — paste the real ping URL"
    grep -qE '192\.0\.2\.|198\.51\.100\.|203\.0\.113\.' "$CONF_FILE" 2>/dev/null \
        && note "$CONF_FILE still lists RFC 5737 documentation addresses in NS — put your real nameservers in"
    grep -qE '^[[:space:]]*ZONES=.*example\.(com|net|org)' "$CONF_FILE" 2>/dev/null \
        && note "$CONF_FILE still lists example.com/.net in ZONES — put your real zones in"
    true
else
    printf '  install:   %s (from the example — EDIT IT)\n' "$CONF_FILE"
    run install -m 0600 -o root -g root dnscheck.env.example "$CONF_FILE"
    note "edit $CONF_FILE: replace the placeholder NS, ZONES and HC_URL - the example ships documentation values only"
fi
say ''

# --- units -------------------------------------------------------------------
say "units in $UNIT_DIR"
sync_file dnscheck.service "$UNIT_DIR/dnscheck.service" 0644
sync_file dnscheck.timer   "$UNIT_DIR/dnscheck.timer"   0644

if ((NO_RELOAD)); then
    say '  skipping daemon-reload (--no-reload)'
else
    printf '  systemctl daemon-reload\n'
    run systemctl daemon-reload
fi
say ''

# --- state -------------------------------------------------------------------
# Report, do not act. Arming the timer is a decision, and it should follow the
# verification below rather than happen as a side effect of copying files.
say 'current state'
if systemctl is-enabled dnscheck.timer >/dev/null 2>&1; then
    printf '  timer:     enabled\n'
    if ((!DRY_RUN)); then
        systemctl list-timers dnscheck.timer --no-pager 2>/dev/null | sed -n '2p' | sed 's/^/  next:      /'
    fi
else
    printf '  timer:     not enabled\n'
    note 'arm it once you have verified the alert path: sudo systemctl enable --now dnscheck.timer'
fi
say ''

# --- what is still missing ---------------------------------------------------
if ((todo)); then
    say "$todo thing(s) still to do:"
    # notes were printed as they were found; re-state the order of operations
    say ''
fi

cat <<'NEXT'
verify before arming, in this order:

  1. the checks, without touching healthchecks.io
     sudo /usr/local/lib/dnscheck/check-dns.sh --no-ping

  2. the sandbox — proves the unit file does not block what step 1 proved works
     sudo systemctl start dnscheck.service
     sudo journalctl -u dnscheck -n 30 --no-pager
     (sudo matters: without it journalctl prints "-- No entries --" rather than
      an error, unless your account is in the adm or systemd-journal group)

  3. the ALERT path, not just the ping path. Point it at a zone that is broken
     on purpose and confirm the notification actually reaches you:
     sudo ZONES=dnssec-failed.org /usr/local/lib/dnscheck/check-dns.sh

  4. arm it
     sudo systemctl enable --now dnscheck.timer

healthchecks.io: period 1 hour, grace 15 min, on a uuid of its OWN — never one
shared with another check.
Reminders: Account Settings > Email Reports > daily.

Step 3 is the one people skip. A dead-man switch you have never seen trip is a
hypothesis, not a monitor.
NEXT
