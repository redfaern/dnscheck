#!/usr/bin/env bash
# check-dns.sh — authoritative DNS + DNSSEC health check.
#
# Runs hourly under systemd, unprivileged. healthchecks.io owns ALL
# notification and the dead-man's switch; it forwards to the dnscheck ntfy topic
# through its own integration. Nothing here talks to ntfy directly — see
# NOTES.md, "Why the script does not call ntfy".
#
# Configuration is read from /etc/dnscheck/dnscheck.env (see below), and the
# environment overrides it. HC_URL is a credential — anyone holding it can forge
# a check-in and keep the switch quiet while DNS is down — so it never appears
# in this file.

set -uo pipefail
# Deliberately no -e. The job here is to collect EVERY problem and report them
# together; aborting on the first failed dig would hide the other two
# nameservers, which is the opposite of what a health check is for.

PATH=/usr/bin:/bin
export LC_ALL=C

usage() {
    cat <<'USAGE'
check-dns.sh — authoritative DNS + DNSSEC health check

  --show-config
              print the settings this run would use, and where each came
              from, then exit. Answers "why is it this", which grepping the
              file cannot.
  --no-ping   run every check and print the report, but do not contact
              healthchecks.io — so a test run cannot mark the check up,
              or fire a false alert.
  --help      this text

Configuration (environment; normally /etc/dnscheck/dnscheck.env):
  NS          default "label=ip" pairs, space separated
  VALIDATORS  default recursive resolvers used to confirm the chain of trust
  WARN_DAYS   default alarm when an RRSIG expires within this many days
  HC_URL      healthchecks.io ping URL (a credential; never in this file)

Zones (normally /etc/dnscheck/zones), one row per zone, five columns:
  <zone> <signed|unsigned> <warn-days|-> <label=ip,...|-> <ip,...|none|->

  "-" in any column takes the default from dnscheck.env. "none" in the
  validators column skips the chain-of-trust check for a zone that cannot be
  resolved from outside — an internal zone checked against a public resolver
  would otherwise report healthy while proving nothing.
USAGE
}

no_ping=0
show_cfg=0
while (($#)); do
    case $1 in
        --no-ping) no_ping=1 ;;
        --show-config) show_cfg=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

CONF_FILE=${DNSCHECK_CONF:-/etc/dnscheck/dnscheck.env}

# Read the config OURSELVES, rather than relying on systemd's EnvironmentFile.
#
# Under systemd the two are equivalent. By hand they are not: a run started from
# a terminal gets no EnvironmentFile, so before this existed a manual run
# silently fell back to built-in defaults — checking whatever was compiled in
# rather than what is configured, and finding HC_URL empty. Every documented
# verification step is a manual run, which made the configuration the one thing
# they could not verify.
#
# PARSED, not sourced. The file's format is systemd's EnvironmentFile, and bash
# disagrees with systemd about the most ordinary line in it: `SIGNED_ZONES=a.com b.com`
# is one value to systemd, but to bash it is TWO assignments — SIGNED_ZONES becomes
# just `a.com` and `b.com` becomes a stray variable nothing reads. No error.
# A config listing three nameservers would quietly check one and report
# "1 of 1 up": a green check that had stopped watching two thirds of what it
# was pointed at.
#
# Demanding quotes would fix bash's reading at the cost of breaking every config
# written the way systemd documents. So this parses the systemd way instead —
# rest-of-line is the value, optional surrounding quotes are stripped. Quoted or
# not, the timer and the terminal now read the file identically.
#
# It also means nothing in the config is ever executed, which sourcing could not
# promise.
conf_get() {  # conf_get <file> <key>  -> prints the value, or nothing
    [[ -r $1 ]] || return 1
    local line
    line=$(grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | tail -1) || return 1
    [[ -n $line ]] || return 1
    line=${line#*=}
    line=${line#"${line%%[![:space:]]*}"}   # strip leading whitespace
    line=${line%"${line##*[![:space:]]}"}   # strip trailing whitespace
    # Strip one matched pair of surrounding quotes, exactly as systemd does.
    if [[ ${#line} -ge 2 && ${line:0:1} == '"' && ${line: -1} == '"' ]]; then
        line=${line:1:${#line}-2}
    elif [[ ${#line} -ge 2 && ${line:0:1} == "'" && ${line: -1} == "'" ]]; then
        line=${line:1:${#line}-2}
    fi
    printf '%s' "$line"
}

declare -A _src=()
for _v in NS VALIDATORS WARN_DAYS HC_URL; do
    # An explicit SIGNED_ZONES=... on the command line wins over the file: the
    # documented way to test the alert path is to point the check at a
    # deliberately broken zone, and that must not be silently overridden by the
    # configured one. Under systemd every value is already in the environment,
    # so this branch is what makes the timer and a manual run agree.
    #
    # Where each value came from is recorded as it is resolved, so
    # --show-config can answer "why is it this" and not merely "what is it".
    # A setting that is right by accident — inherited from the environment,
    # or a default standing in for a line you thought you had edited — reads
    # identically to one that is right on purpose, until something asks.
    if [[ -n ${!_v+set} ]]; then
        _src[$_v]=environment
        continue
    fi
    if _val=$(conf_get "$CONF_FILE" "$_v"); then
        printf -v "$_v" '%s' "$_val"
        _src[$_v]=config
    fi
done
unset _v _val

# Defaults for the two settings that carry nothing site-specific. NS, SIGNED_ZONES and
# HC_URL deliberately have NO defaults: a built-in fallback for those is how a
# misconfigured run looks like a passing one.
: "${VALIDATORS:=1.1.1.1 8.8.8.8}"
# 3, not 7. This is measured against the floor of the RESIGNING cycle, not the
# signature's validity: BIND's default policy signs for 14 days and refreshes 5
# days before expiry, so remaining life sawtooths between 14 and 5 and is meant
# to. Any threshold inside that band alarms on a healthy zone — 7 would fire for
# two days out of every nine, forever.
: "${WARN_DAYS:=3}"
[[ -n ${_src[VALIDATORS]:-} ]] || _src[VALIDATORS]=default
[[ -n ${_src[WARN_DAYS]:-}  ]] || _src[WARN_DAYS]=default

# One separator, both files. A list in the zone table MUST use commas — spaces
# there separate the five columns, so there is no choice about it — while a
# list here has always used spaces. Two formats for the same kind of value is
# a trap for exactly the moment you copy a row's nameservers up here as the
# default, or a default down into a row. So accept either in this file and
# normalise; the zone table keeps its commas because it cannot do otherwise,
# and --show-config prints the resolved form so the two always look alike.
NS=${NS//,/ }
VALIDATORS=${VALIDATORS//,/ }

# --show-config: what the run will ACTUALLY use, and where each value came
# from. Not the same question as "what is in the file", which is all that
# grep can answer — it cannot show a quote that was stripped, a default that
# filled a gap, an environment variable that won, or which of two duplicate
# lines was taken.
# Lists are DISPLAYED comma-separated, whatever they are stored as. Two
# reasons, and the second is the one that matters.
#
# Pasting: this output is what gets copied into dnscheck.env or into a zone
# table row, and only commas work in both places.
#
# Reading: a value wider than its column pushes into the next one, and with
# spaces inside the value every gap then looks alike —
#
#   ns1=192.0.2.1 ns2=198.51.100.1 ns3=203.0.113.1 1.1.1.1 8.8.8.8
#
# is five things with no way to see where the nameservers stop and the
# validators start. Commas inside leave exactly one space in that line, and it
# is the column boundary.
#
# Rebuilt by word splitting rather than substituted, so a run of spaces in the
# config collapses instead of becoming ",,".
fmt_list() {
    local out='' w
    for w in ${1-}; do out+="$w,"; done
    printf '%s' "${out%,}"
}

show_config() {
    local v val src n i st nsf warnf wz ws ww wn
    printf '%-15s %s\n' 'config file' "$CONF_FILE"
    if [[ -r $CONF_FILE ]]; then
        printf '%-15s %s\n' '' 'readable'
    elif [[ -e $CONF_FILE ]]; then
        printf '%-15s %s\n' '' "NOT READABLE by $(id -un) — values below are environment and defaults only"
    else
        printf '%-15s %s\n' '' 'does not exist'
    fi
    printf '\n%-15s %-12s %s\n' 'SETTING' 'FROM' 'VALUE'
    for v in NS VALIDATORS WARN_DAYS HC_URL; do
        val=${!v:-}
        src=${_src[$v]:-unset}
        if [[ $v == HC_URL ]]; then
            # A credential. Shown as enough to tell two uuids apart and no
            # more, because the whole point of this flag is that its output
            # gets pasted somewhere to ask a question about it.
            [[ -n $val ]] && val="${val%"${val#*//*/????}"}…redacted" || val=''
        fi
        n=''
        case $v in
            NS|VALIDATORS)
                [[ -n $val ]] && n="  ($(wc -w <<<"$val"))"
                val=$(fmt_list "$val") ;;
        esac
        printf '%-15s %-12s %s%s\n' "$v" "$src" "${val:-—}" "$n"
    done

    # The zone table as RESOLVED, with every '-' already replaced by the
    # default it stands for. "Which nameservers will this zone actually be
    # checked against" is the question, and the file cannot answer it.
    printf '\n%-15s %s\n' 'zones file' "$ZONES_FILE"
    if (( Z_COUNT )); then
        # Widths from the content, not from guesses. Fixed widths were wrong in
        # both directions: a nameserver list is routinely wider than any column
        # anyone would pick, so it pushed into the next one and left the
        # VALIDATORS heading sitting over the middle of the nameservers; and a
        # short zone list padded out to nothing. A heading that does not sit
        # above its column is worse than no heading, because it is read as one.
        #
        # The header string is the floor, so a narrow table still reads.
        wz=4 ws=5 ww=4 wn=11
        for (( i=0; i<Z_COUNT; i++ )); do
            (( Z_SIGNED[i] )) && st=signed || st=unsigned
            nsf=$(fmt_list "${Z_NS[i]}")
            warnf=${Z_WARN[i]:--}
            (( ${#Z_NAME[i]} > wz )) && wz=${#Z_NAME[i]}
            (( ${#st}        > ws )) && ws=${#st}
            (( ${#warnf}     > ww )) && ww=${#warnf}
            (( ${#nsf}       > wn )) && wn=${#nsf}
        done
        # Two spaces between columns, so the gap inside a comma-free value can
        # never be mistaken for the gap between two of them.
        printf '\n%-*s  %-*s  %-*s  %-*s  %s\n' \
            "$wz" 'ZONE' "$ws" 'STATE' "$ww" 'WARN' "$wn" 'NAMESERVERS' 'VALIDATORS'
        for (( i=0; i<Z_COUNT; i++ )); do
            (( Z_SIGNED[i] )) && st=signed || st=unsigned
            printf '%-*s  %-*s  %-*s  %-*s  %s\n' \
                "$wz" "${Z_NAME[i]}" "$ws" "$st" "$ww" "${Z_WARN[i]:--}" \
                "$wn" "$(fmt_list "${Z_NS[i]}")" "$(fmt_list "${Z_VAL[i]}")"
        done
    fi
    if (( ${#ZONE_ERR[@]} )); then
        printf '\n%s\n' 'PROBLEMS with the zones file:'
        printf '  %s\n' "${ZONE_ERR[@]}"
    fi
}


# ------------------------------------------------------------------- zones ---
#
# One row per zone, because a zone's nameservers are a fact about that zone.
# The old SIGNED_ZONES/UNSIGNED_ZONES pair could only say "every zone lives on
# every nameserver in NS", which is an assumption dressed as configuration: no
# way to express an internal zone on internal servers beside a public one, and
# no way to give a zone signed under a different policy its own threshold.
#
# A table rather than JSON, deliberately. It takes comments — and in this
# project the config file IS the documentation — it needs no parser beyond
# `read`, one '#' disables a zone for an afternoon, and thirty rows still line
# up in a terminal. It also keeps the topology OUT of dnscheck.env, which can
# then go on being 0600 root:root and parsed by systemd as root: zone
# topology is public DNS data, HC_URL is a credential, and only the credential
# needs that treatment.
ZONES_FILE=${DNSCHECK_ZONES:-/etc/dnscheck/zones}

Z_NAME=() Z_SIGNED=() Z_WARN=() Z_NS=() Z_VAL=()
Z_COUNT=0
ZONE_ERR=()

# Collects EVERY fault rather than dying on the first, and reports each with
# its line number. Three typos should cost one edit, not three runs.
#
# Nothing is appended until the whole row has validated, so a rejected row
# leaves the arrays exactly as it found them and the five stay in step.
parse_zones() {
    local line lineno=0 zone state warn ns vals extra tok i bad
    local r_warn r_ns r_val
    if [[ ! -e $ZONES_FILE ]]; then
        ZONE_ERR+=("$ZONES_FILE does not exist — copy zones.example there and edit it")
        return
    fi
    if [[ ! -r $ZONES_FILE ]]; then
        ZONE_ERR+=("$ZONES_FILE is not readable by $(id -un) — run this as root")
        return
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$((lineno + 1))
        # Trailing comments are fine here, unlike dnscheck.env where the rest
        # of the line is the value. No field can contain a '#'.
        line=${line%%#*}
        [[ $line =~ [^[:space:]] ]] || continue
        read -r zone state warn ns vals extra <<<"$line"

        if [[ -n $extra ]]; then
            ZONE_ERR+=("line $lineno: more than five columns — a list with a space in it? Use commas inside the nameserver and validator columns")
            continue
        fi
        if [[ -z $vals ]]; then
            ZONE_ERR+=("line $lineno: expected five columns (zone state warn-days nameservers validators), got: $line")
            continue
        fi
        if [[ ! $zone =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
            ZONE_ERR+=("line $lineno: '$zone' is not a domain name")
            continue
        fi
        bad=0
        for (( i=0; i<Z_COUNT; i++ )); do
            [[ ${Z_NAME[i]} == "$zone" ]] && { ZONE_ERR+=("line $lineno: $zone is listed twice"); bad=1; }
        done
        (( bad )) && continue
        if [[ $state != signed && $state != unsigned ]]; then
            ZONE_ERR+=("line $lineno: state must be 'signed' or 'unsigned', not '$state'. Which one a zone is gets DECLARED, not detected: a zone whose signing stopped must look broken, not get reclassified as fine.")
            continue
        fi

        # --- warn-days
        if [[ $state == unsigned ]]; then
            # Empty, not the default. An unsigned zone has no signatures, so
            # showing it a threshold in --show-config would imply one applies.
            r_warn=''
            if [[ $warn != - ]]; then
                ZONE_ERR+=("line $lineno: $zone is unsigned, so it has no signatures to expire — warn-days must be '-'")
                continue
            fi
        elif [[ $warn == - ]]; then
            r_warn=${WARN_DAYS:-}
            # Normalise here as well: the global guard runs after this, and
            # a leading zero in an arithmetic context is octal.
            [[ $r_warn =~ ^[0-9]+$ ]] && r_warn=$((10#$r_warn))
        elif [[ $warn =~ ^[0-9]+$ ]]; then
            r_warn=$((10#$warn))
        else
            ZONE_ERR+=("line $lineno: warn-days must be a whole number of days or '-', not '$warn'")
            continue
        fi

        # --- nameservers
        if [[ $ns == - ]]; then
            if [[ -z ${NS:-} ]]; then
                ZONE_ERR+=("line $lineno: nameservers is '-' but no default NS is set in $CONF_FILE")
                continue
            fi
            r_ns=$NS
        else
            r_ns=${ns//,/ }
            bad=0
            for tok in $r_ns; do
                [[ $tok == *=* && $tok != =* && $tok != *= ]] && continue
                ZONE_ERR+=("line $lineno: nameserver '$tok' must be label=ip — the label is what names this server in every alert")
                bad=1
            done
            (( bad )) && continue
        fi

        # --- validators
        if [[ $vals == - ]]; then
            r_val=${VALIDATORS:-}
            if [[ -z $r_val ]]; then
                ZONE_ERR+=("line $lineno: validators is '-' but no default VALIDATORS is set in $CONF_FILE")
                continue
            fi
        elif [[ $vals == none ]]; then
            r_val=none
        else
            r_val=${vals//,/ }
        fi

        Z_NAME+=("$zone")
        [[ $state == signed ]] && Z_SIGNED+=(1) || Z_SIGNED+=(0)
        Z_WARN+=("$r_warn")
        Z_NS+=("$r_ns")
        Z_VAL+=("$r_val")
        Z_COUNT=$((Z_COUNT + 1))
    done < "$ZONES_FILE"
    (( Z_COUNT )) || ZONE_ERR+=("$ZONES_FILE lists no zones")
}
parse_zones

# Before the config VALIDATION below, deliberately: an incomplete or wrong
# config is exactly when you want to see what was actually read, and a flag
# that only works once everything is already correct is a flag for nobody.
((show_cfg)) && { show_config; exit 0; }

cfg_missing() {
    printf 'missing %s.\n\n' "$1" >&2
    if [[ -e $CONF_FILE && ! -r $CONF_FILE ]]; then
        printf '%s exists but is not readable by %s — run this as root.\n' \
            "$CONF_FILE" "$(id -un)" >&2
    elif [[ ! -e $CONF_FILE ]]; then
        printf 'No config at %s. Copy dnscheck.env.example there and edit it.\n' \
            "$CONF_FILE" >&2
    else
        printf 'Set it in %s.\n' "$CONF_FILE" >&2
    fi
    exit 3
}

[[ -n ${NS:-}    ]] || cfg_missing NS
# The zone lists moved out of dnscheck.env and into their own table, so that a
# zone can carry its own nameservers, its own validators and its own expiry
# threshold. Refuse the old keys rather than ignore them: an unread key is just
# an unused variable, so a config still using them would parse fine, run fine,
# and check whatever the zones file happened to say — or nothing at all — while
# looking exactly like a working config. Refusing is loud and takes one edit.
for _old in ZONES SIGNED_ZONES UNSIGNED_ZONES; do
    grep -qE "^[[:space:]]*$_old[[:space:]]*=" "$CONF_FILE" 2>/dev/null || continue
    printf '%s in %s: the zone lists now live in %s, one row per zone.\n\n' \
        "$_old" "$CONF_FILE" "$ZONES_FILE" >&2
    printf '  <zone> <signed|unsigned> <warn-days|-> <label=ip,...|-> <ip,...|none|->\n\n' >&2
    printf 'A zone keeps its own nameservers there, so an internal zone on internal\n' >&2
    printf 'servers can sit beside a public one, and "none" in the last column skips\n' >&2
    printf 'the chain-of-trust check for a zone no outside resolver can see. Delete\n' >&2
    printf '%s from %s once the rows are in place.\n' "$_old" "$CONF_FILE" >&2
    exit 3
done
unset _old

# Reported together, with line numbers, and only now — --show-config above
# prints them too, and a broken config is exactly when you want to look.
if (( ${#ZONE_ERR[@]} )); then
    printf 'cannot read the zone table:\n\n' >&2
    printf '  %s\n' "${ZONE_ERR[@]}" >&2
    printf '\nEach row is: <zone> <signed|unsigned> <warn-days|-> <label=ip,...|-> <ip,...|none|->\n' >&2
    printf 'See zones.example, or run --show-config to see what was read.\n' >&2
    exit 3
fi
# Not needed for --no-ping, which exists precisely so the checks can be
# exercised before there is a healthchecks.io check to point at.
((no_ping)) || [[ -n ${HC_URL:-} ]] || cfg_missing HC_URL

# WARN_DAYS is the only setting that reaches an arithmetic context, and bash
# fails two different ways there, both quiet.
#
#   WARN_DAYS=three    `three` is read as a VARIABLE, is unset, and set -u
#                      kills the run mid-check — before any report or ping.
#   WARN_DAYS=3 days   every realistic typo: a stray trailing comment, a unit,
#                      a decimal point. (( )) prints an arithmetic error and
#                      returns non-zero, and with no set -e the run carries on
#                      treating the comparison as FALSE. Signature expiry is
#                      no longer watched, and the run pings SUCCESS.
#
# The second is the dangerous one, and it is the same failure as the bare ZONES
# key refused above: parses fine, runs fine, checks nothing. So validate rather
# than trust — and normalise to base 10, because a leading zero in an
# arithmetic context is OCTAL and 010 would silently mean 8.
[[ ${WARN_DAYS:-} =~ ^[0-9]+$ ]] || cfg_missing 'a numeric WARN_DAYS (whole days, digits only)'
WARN_DAYS=$((10#$WARN_DAYS))

problems=()
summary=()
note() { problems+=("$1"); }
info() { summary+=("$1"); }

now=$(date -u +%s)

# A missing dig is itself the finding, reported through the normal path rather
# than as a silent exit — an exit here would look identical to "all healthy"
# to everything except the journal.
command -v dig >/dev/null 2>&1 \
    || { note 'dig is not installed (apt install bind9-dnsutils) — no checks ran'; Z_COUNT=0; }

# RRSIG inception/expiry timestamps are YYYYMMDDHHMMSS, always UTC.
epoch() {
    local t=${1-}
    [[ $t =~ ^[0-9]{14}$ ]] || return 1
    date -u -d "${t:0:4}-${t:4:2}-${t:6:2} ${t:8:2}:${t:10:2}:${t:12:2}" +%s 2>/dev/null
}

# +comments as well as +answer: the header carries the rcode and the AA flag,
# and both say things the records themselves cannot.
auth_query() {
    dig +dnssec +norecurse +noall +comments +answer +time=3 +tries=2 \
        @"$2" "$1" "$3" 2>/dev/null
}

hdr_status() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$1" | head -1; }
hdr_flags()  { sed -n 's/^;; flags: \([^;]*\);.*/\1/p'  <<<"$1" | head -1; }

# Check the RRSIG covering one RRset for presence and remaining life.
# Sets RRSIG_DAYS on success.
check_rrsig() {
    local out=$1 zone=$2 name=$3 type=$4 exps exp ee best='' best_exp=''

    # ALL the expiries, not the first one seen. An RRset can legitimately
    # carry more than one RRSIG — the DNSKEY RRset does exactly that through a
    # double-KSK rollover, which is BIND's default method. A resolver
    # validates if ANY signature is good, so the honest figure is the LATEST
    # expiry. Taking whichever awk reached first could report the outgoing
    # key's signature on a perfectly healthy zone, during a rollover, which is
    # when a spurious page is least welcome.
    exps=$(awk -v t="$type" '$4=="RRSIG" && $5==t {print $9}' <<<"$out")
    if [[ -z $exps ]]; then
        note "$zone @$name: $type present but not signed — signing stopped, or the zone reloaded unsigned"
        return 1
    fi
    while read -r exp; do
        [[ -n $exp ]] || continue
        ee=$(epoch "$exp") || continue
        if [[ -z $best ]] || (( ee > best )); then best=$ee; best_exp=$exp; fi
    done <<<"$exps"
    if [[ -z $best ]]; then
        note "$zone @$name: cannot parse $type RRSIG expiry ($(tr '\n' ' ' <<<"$exps" | sed 's/ *$//'))"
        return 1
    fi

    # Compare EPOCHS, not a day count. Integer division truncates toward zero,
    # so (ee - now) / 86400 is 0 for anything within ±24h: a signature that
    # expired eleven hours ago and one with eleven hours left are the same
    # number. `days < 0` therefore misses the entire first day of a real
    # outage — the day you would act in — and calls it "expires in 0d". And
    # `days <= 0` would fix that by declaring a healthy zone EXPIRED instead.
    # Neither threshold can work, because the distinction is destroyed before
    # the comparison.
    if (( best < now )); then
        # Hours, not days: this branch's most likely reading is now a sub-day
        # one, and "EXPIRED 0d ago" reads like a rounding artefact rather than
        # an emergency.
        note "$zone @$name: $type RRSIG EXPIRED $(( (now - best + 3599) / 3600 ))h ago ($best_exp) — resolvers are already failing"
    elif (( (best - now) / 86400 < WARN_ACTIVE )); then
        note "$zone @$name: $type RRSIG expires in $(( (best - now) / 86400 ))d ($best_exp)"
    fi

    # The coarse day count is fine here: it only feeds min_days and the summary
    # line, where a negative number still reads correctly.
    RRSIG_DAYS=$(( (best - now) / 86400 ))
    return 0
}

# One nameserver, one zone. Sets NS_SERIAL and NS_RRSIG_DAYS; appends its own
# notes rather than returning them, so it must never run in a subshell — an
# array appended to inside $(...) is discarded when the subshell exits.
check_ns() {
    local zone=$1 name=$2 ip=$3 signed=$4 out status flags soa_days
    NS_SERIAL=''
    NS_RRSIG_DAYS=''
    NS_UNSIGNED=0
    NS_AA=0

    out=$(auth_query "$zone" "$ip" SOA)
    if [[ -z $out ]]; then
        note "$zone @$name ($ip): no response — down, filtered, or too slow"
        return 1
    fi

    status=$(hdr_status "$out")
    if [[ $status != NOERROR ]]; then
        note "$zone @$name: SOA query returned ${status:-no rcode}"
        return 1
    fi

    # Without AA the box answered, but not as an authority for this zone — a
    # dropped zone, a failed reload, a config that no longer includes it.
    # "It replied" is not the same as "it is still serving your zone".
    #
    # Recorded as well as reported. On a FAILING run the note above says so;
    # on a healthy run the summary line prints "aa" against this server, so
    # the strongest per-server claim the check makes leaves a trace either
    # way. A check whose success is silent cannot be distinguished, in a
    # journal, from a check that did not run.
    flags=" $(hdr_flags "$out") "
    if [[ $flags == *" aa "* ]]; then
        NS_AA=1
    else
        note "$zone @$name: answered without the AA flag — no longer authoritative for this zone"
    fi

    NS_SERIAL=$(awk '$4=="SOA"{print $7; exit}' <<<"$out")
    [[ -n $NS_SERIAL ]] || note "$zone @$name: NOERROR but no SOA record in the answer"

    # Everything above applies to any zone. Everything below is DNSSEC, and
    # only a zone DECLARED signed gets it — an unsigned zone has no RRSIGs to
    # be missing, and reporting their absence as a fault would make the check
    # permanently red for a zone that is working exactly as intended.
    #
    # Declared, not detected. Auto-detecting "this zone has no DNSKEY, so it
    # must be unsigned" would mean that a zone whose signing STOPPED gets
    # silently reclassified as fine — the precise failure this exists to catch.
    # Which zones are signed is a fact about your intent, so you state it.
    ((signed)) || return 0

    # No signatures AT ALL from this server. Do not diagnose it here: one
    # nameserver cannot tell "signing broke on this box" from "this zone was
    # never signed and is in the wrong list", and those want opposite actions.
    # Record it and let the zone loop decide, once every nameserver and both
    # validators have been heard from. Six identical lines that each guess
    # wrong are worse than one line that knows.
    NS_UNSIGNED=0
    if ! awk '$4=="RRSIG" && $5=="SOA"{f=1} END{exit !f}' <<<"$out"; then
        NS_UNSIGNED=1
        return 0
    fi

    RRSIG_DAYS=''
    check_rrsig "$out" "$zone" "$name" SOA
    soa_days=$RRSIG_DAYS

    # The DNSKEY RRset is signed by the KSK on its own schedule, so its
    # signatures can expire while the SOA's are still fresh. Checking only the
    # SOA would miss a stalled KSK resign right up until the zone went dark.
    out=$(auth_query "$zone" "$ip" DNSKEY)
    if [[ -n $out && $(hdr_status "$out") == NOERROR ]]; then
        RRSIG_DAYS=''
        check_rrsig "$out" "$zone" "$name" DNSKEY
        [[ -n $RRSIG_DAYS && -n $soa_days ]] && (( RRSIG_DAYS < soa_days )) && soa_days=$RRSIG_DAYS
    else
        note "$zone @$name: DNSKEY query failed — cannot check the KSK signature"
    fi

    NS_RRSIG_DAYS=$soa_days
    return 0
}

# SOA serial only, for the mismatch re-check.
soa_serial() {
    auth_query "$1" "$2" SOA | awk '$4=="SOA"{print $7; exit}'
}

# Per zone now, not per run: the table gives each zone its own nameservers,
# its own validators and its own expiry threshold.
for (( zi=0; zi<Z_COUNT; zi++ )); do
    zone=${Z_NAME[zi]}
    signed=${Z_SIGNED[zi]}
    zone_ns=${Z_NS[zi]}
    zone_val=${Z_VAL[zi]}
    # check_rrsig reads this rather than the global: the threshold tracks the
    # SIGNING POLICY — BIND's 14-day/5-day resign cycle is the whole reason it
    # is 3 — and policy belongs to the zone, not to the host running the check.
    WARN_ACTIVE=${Z_WARN[zi]}
    # 'none' means the zone was DECLARED unresolvable from outside. An empty
    # list makes the validator loop run zero times; the notes that would fire
    # on zero validators are suppressed below, because "not checked" and
    # "checked and unreachable" are different findings.
    zone_val_list=$zone_val
    [[ $zone_val == none ]] && zone_val_list=''
    ns_total=$(wc -w <<<"$zone_ns")
    v_total=$(wc -w <<<"$zone_val_list")
    answered=0 serials='' details='' min_days='' unsigned_ns=''

    for pair in $zone_ns; do
        name=${pair%%=*}; ip=${pair#*=}
        if check_ns "$zone" "$name" "$ip" "$signed"; then
            ((answered++))
            [[ -n $NS_SERIAL ]] && serials+="$name:$NS_SERIAL "
            ((NS_UNSIGNED)) && unsigned_ns+="$name "
            # One field per server for the summary line: what it said its
            # serial was, whether it claimed authority, and how much life its
            # signatures have. Assembled here rather than in check_ns because
            # only the caller knows this server answered at all.
            detail="$name:${NS_SERIAL:-noserial}"
            ((NS_AA)) && detail+=" aa"
            if [[ -n $NS_RRSIG_DAYS ]]; then
                detail+=" ${NS_RRSIG_DAYS}d"
                [[ -z $min_days ]] && min_days=$NS_RRSIG_DAYS
                (( NS_RRSIG_DAYS < min_days )) && min_days=$NS_RRSIG_DAYS
            fi
            details+="$detail, "
        fi
    done
    details=${details%, }

    (( answered < ns_total )) \
        && note "$zone: only $answered of $ns_total nameservers answered"

    # A serial mismatch is NORMAL for the seconds it takes a NOTIFY to
    # propagate. Alarming on first sight would page you for healthy behaviour,
    # and an alert that cries wolf hourly is an alert you stop reading.
    # Confirm it persists first: two strikes, not one.
    distinct=$(tr ' ' '\n' <<<"$serials" | sed 's/.*://' | sort -u | grep -c .)
    if (( distinct > 1 )); then
        sleep 20
        recheck=''
        for pair in $zone_ns; do
            name=${pair%%=*}; ip=${pair#*=}
            s=$(soa_serial "$zone" "$ip")
            [[ -n $s ]] && recheck+="$name:$s "
        done
        again=$(tr ' ' '\n' <<<"$recheck" | sed 's/.*://' | sort -u | grep -c .)
        if (( again > 1 )); then
            # Both lists trimmed. They accumulate a trailing space exactly as
            # the summary's did, and this is the line you would be reading at
            # 3am — "ns3:2026080399  (was:" is not what you want to be
            # deciphering then.
            note "$zone: serials still disagree after 20s — ${recheck% } (was: ${serials% })"
        else
            info "$zone: serials converged during the run (transfer was in progress)"
        fi
    fi

    # The chain of trust, seen from outside. A RANDOM label, not the apex: the
    # apex SOA sits in every resolver's cache for its TTL, so asking for it can
    # return a validated answer from before the breakage. A name that has never
    # been queried forces a full resolution now, and exercises the NSEC/NSEC3
    # denial-of-existence proof — the half of DNSSEC that breaks quietly.
    # The rcode does not matter here; the AD flag does.
    v_answered=0 v_ad=0 no_ad='' ad_from='' resolved_by='' ad_unexpected='' servfail_from=''
    for v in $zone_val_list; do
        # Timestamp AND randomness. $RANDOM alone is 0-32767 and its
        # concatenation is not uniform, so a label CAN repeat — and a repeat
        # inside the zone's negative-cache TTL (the SOA minimum, commonly an
        # hour) would be answered from cache, quietly turning the one query
        # that must not be cached into one that was. The epoch second makes a
        # collision impossible between runs rather than merely unlikely.
        label="dnscheck-$(date -u +%s)-$RANDOM.$zone"
        vout=$(dig +dnssec +time=5 +tries=2 @"$v" "$label" A 2>/dev/null)
        vflags=" $(hdr_flags "$vout") "
        [[ -z $vout || $vflags == '  ' ]] && continue
        ((v_answered++))
        if ((signed)); then
            # Collected, not reported yet — for the same reason as the
            # missing signatures above. "No AD" on a zone that was never
            # signed is not a broken chain of trust, it is the absence of one.
            if [[ $vflags == *" ad "* ]]; then
                ((v_ad++))
                ad_from+="$v "
            else
                no_ad+="$v "
            fi
        elif [[ $(hdr_status "$vout") == SERVFAIL ]]; then
            # The failure mode unique to an unsigned zone. AD is absent by
            # definition here, so its absence proves nothing — but SERVFAIL
            # from a validating resolver, on a zone that should simply be
            # insecure, usually means a DS record left behind at the parent.
            # That breaks the zone for every validating resolver on the
            # Internet while it still answers perfectly from its own
            # nameservers — which is why only an outside view catches it.
            servfail_from+="$v "
        elif [[ $vflags == *" ad "* ]]; then
            # Config drift, in the expensive direction: the zone is signed and
            # nobody told the check, so its signature expiry goes unwatched.
            ad_unexpected+="$v "
        else
            resolved_by+="$v "
        fi
    done
    [[ $zone_val != none ]] && (( v_answered == 0 )) \
        && note "$zone: no validator reachable ($zone_val) — chain of trust unconfirmed"

    # Named together, reported once. A stale DS breaks a zone for EVERY
    # validating resolver, and a zone in the wrong list is one fact about the
    # config, not one per resolver that noticed — so both of these used to
    # print the same sentence twice with a different IP in it. Same reason the
    # missing-signature diagnosis was collapsed: repetition reads as several
    # problems and buries the ones that are.
    [[ -n $servfail_from ]] \
        && note "$zone: SERVFAIL from ${servfail_from% } — an unsigned zone that will not resolve usually means a stale DS at the parent"
    [[ -n $ad_unexpected ]] \
        && note "$zone: listed as unsigned but ${ad_unexpected% } validates it — it IS signed; move it to SIGNED_ZONES so its signatures get monitored"

    # Now enough is known to say which of the two very different things an
    # absence of signatures means.
    if ((signed)); then
        u_count=0
        [[ -n $unsigned_ns ]] && u_count=$(wc -w <<<"$unsigned_ns")

        if [[ $zone_val == none ]] && (( u_count > 0 && u_count == answered )); then
            # No signatures anywhere, and no outside view to cross-check
            # against. Say exactly that rather than guessing: with validators
            # 'none' the check genuinely cannot tell a zone whose signing
            # stopped from one that was never signed, and picking either
            # would be inventing a diagnosis it has no evidence for.
            note "$zone: no nameserver serves signatures, and validators are 'none' for this zone — either signing has stopped or it is not a signed zone, and the check cannot tell which"
        elif (( u_count > 0 && u_count == answered && v_ad == 0 )); then
            # Unanimous: no nameserver serves signatures and no validator sees
            # a chain. This is not a zone whose signing broke, it is a zone
            # that was never signed, sitting in the wrong list. ONE line that
            # names the cause, rather than eight that each report a symptom.
            # The missing AD is the same fact restated, so it is not repeated.
            note "$zone: listed as signed, but NO nameserver serves signatures and no validator sees AD — this is an unsigned zone; move it to UNSIGNED_ZONES"
        else
            # Partial, and therefore real. A zone that is signed, with one
            # server no longer serving the signatures, is exactly the fault a
            # per-zone summary would have hidden — so name the server.
            (( u_count > 0 ))                 && note "$zone: no RRSIG from ${unsigned_ns% } while other nameservers serve them — signing has stopped on that server"
            if [[ -n $no_ad ]]; then
                if (( u_count == 0 && v_ad == 0 )); then
                    # Signatures on every nameserver that answered, and AD from
                    # none. Signing is therefore NOT the problem, and saying
                    # "the chain is not validating" sends you to look at the
                    # nameservers, which are fine. What is missing is the
                    # parent's DS record: without it a resolver has no reason
                    # to believe this zone is signed, so it never checks. That
                    # is exactly the state a zone sits in between "we signed
                    # it" and "the registry published the DS", and it is a
                    # different thing from a broken chain — the zone still
                    # resolves for everyone, it is merely insecure.
                    note "$zone: every nameserver serves signatures but no validator sees AD (${no_ad% }) — the parent's DS record is missing or does not match, so the zone is insecure rather than broken. Until the DS is published, mark this zone 'unsigned' in the zone table."
                else
                    # Some validators see the chain and these do not, so the
                    # fault is theirs or the path to them — named together,
                    # because it is one finding about several resolvers.
                    note "$zone: no AD flag from ${no_ad% } — the DNSSEC chain is not validating there, though other validators see it"
                fi
            fi
        fi
    fi

    # Trimmed: serials accumulates a trailing space, which showed up in every
    # summary line as "ns3:2026080414 ,".
    serials_shown=${serials% }
    ad_from=${ad_from% }; resolved_by=${resolved_by% }

    # Per SERVER, not per zone. The old line reported one serial list, the
    # MINIMUM RRSIG life across all nameservers, and a count of validators —
    # so a healthy run proved that some server was authoritative and some
    # signature had 29 days left, without saying which. Every claim now names
    # the server or resolver it came from, which is what makes the line
    # evidence rather than an assertion. It stays ONE line per zone: nine
    # lines a run would bury the problem lines they sit among.
    # "not checked" must never render as "checked and fine". A zone with
    # validators 'none' says so on its own line, every run, so the gap is
    # visible in the journal rather than inferred from the zones file.
    if [[ $zone_val == none ]]; then
        if ((signed)); then
            info "$zone: $answered/$ns_total NS up [${details% }], no outside validation (validators none)"
        else
            info "$zone: $answered/$ns_total NS up [${details% }], unsigned, no outside validation (validators none)"
        fi
    elif ((signed)); then
        info "$zone: $answered/$ns_total NS up [${details% }], AD from ${ad_from:-none}"
    else
        info "$zone: $answered/$ns_total NS up [${details% }], unsigned, resolved by ${resolved_by:-none}"
    fi
done

# ------------------------------------------------------------------ report ---

body=''
(( ${#problems[@]} )) && body+=$(printf '%s\n' "${problems[@]}")$'\n\n'
(( ${#summary[@]}  )) && body+=$(printf '%s\n' "${summary[@]}")

# ping_hc <url> <retries> — POST the report body to healthchecks.io.
#
# Neither the URL nor the body goes in argv, and each for its own reason.
#
# HC_URL is a credential: anyone holding it can forge a check-in and keep the
# switch quiet while DNS is down. dnscheck.env is 0600 root:root and systemd
# parses it before dropping to the service user, so nothing unprivileged can
# read it — and a command line would have handed it to every local account
# through `ps` anyway, once an hour, for as long as the ping took. The config
# file's own header says "never in argv"; this is what makes that true.
#
# The BODY has a different problem: curl reads a --data-binary argument
# beginning with `@` as a FILENAME. No line starts with one today — they all
# start with a zone name — but the day one did, curl would fail to open the
# file and abort before sending. On the /fail path that converts "DNS is
# broken" into "the check went silent": the same alert a grace period later,
# with none of the detail.
#
# A --config file closes both. curl reads it from stdin, so neither value is
# ever in the process table, and `data-binary = "@file"` is an explicit file
# reference rather than a string that might be mistaken for one. The body goes
# through a temp file, which PrivateTmp= in the unit keeps private to the run.
# --retry still holds: curl buffers a --data body in memory rather than
# streaming it, so every attempt sends identical bytes.
ping_hc() {
    local url=$1 retries=$2 tmp rc
    tmp=$(mktemp) || { echo 'cannot create a temp file for the ping body' >&2; return 1; }
    printf '%s' "$body" > "$tmp"
    printf 'url = "%s"\ndata-binary = "@%s"\n' "$url" "$tmp" |
        curl -fsS --max-time 20 --retry "$retries" --retry-delay 3 \
             --user-agent "dnscheck/1.0 ($(hostname -s 2>/dev/null || echo unknown))" \
             -o /dev/null -K -
    rc=$?
    rm -f "$tmp"
    return $rc
}

if (( ${#problems[@]} )); then
    printf '%s\n' "${problems[@]}" >&2
    # The per-zone summary goes to the journal on THIS path too, not only on
    # the healthy one. It was already in the ping body, so healthchecks.io saw
    # it, but the journal did not — which left the one run you actually go and
    # read showing what broke and nothing about what did not. "ns3 did not
    # answer" is a different problem from "ns3 did not answer and the other
    # two disagree about the serial", and the difference is in these lines.
    (( ${#summary[@]} )) && printf '%s\n' "${summary[@]}"
    # A verdict, last. Under systemd the exit status IS the verdict and systemd
    # announces it; by hand nothing does, and the run ends on summary lines
    # that read as healthy whatever came before them. So a run by hand looked
    # fine while returning 1. One line, stating which it was.
    printf 'FAILED — %d problem(s), %d zone(s) checked\n' "${#problems[@]}" "$Z_COUNT" >&2
    (( no_ping )) && exit 1
    ping_hc "${HC_URL%/}/fail" 2 \
        || echo 'dead-man ping FAILED — healthchecks.io was not told about the failure' >&2
    exit 1
fi

(( ${#summary[@]} )) && printf '%s\n' "${summary[@]}"
printf 'OK — %d zone(s) checked, no problems\n' "$Z_COUNT"
(( no_ping )) && exit 0
# Retries on the success path too: a missed ping is not a missed message, it is
# an ALARM. Crying wolf teaches you to ignore the one signal whose entire
# meaning is that it stopped.
ping_hc "$HC_URL" 3 \
    || { echo 'dead-man ping FAILED — checks passed but healthchecks.io was not told' >&2; exit 1; }
exit 0
