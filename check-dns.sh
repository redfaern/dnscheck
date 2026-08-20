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

  --no-ping   run every check and print the report, but do not contact
              healthchecks.io — so a test run cannot mark the check up,
              or fire a false alert.
  --help      this text

Configuration (environment; normally /etc/dnscheck/dnscheck.env):
  NS          "label=ip" pairs, space separated
  ZONES       zones to check, space separated
  VALIDATORS  recursive resolvers used to confirm the chain of trust
  WARN_DAYS   alarm when an RRSIG expires within this many days
  HC_URL      healthchecks.io ping URL (a credential; never in this file)
USAGE
}

no_ping=0
while (($#)); do
    case $1 in
        --no-ping) no_ping=1 ;;
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
# disagrees with systemd about the most ordinary line in it: `ZONES=a.com b.com`
# is one value to systemd, but to bash it is TWO assignments — ZONES becomes
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

for _v in NS ZONES VALIDATORS WARN_DAYS HC_URL; do
    # An explicit ZONES=... on the command line wins over the file: the
    # documented way to test the alert path is to point the check at a
    # deliberately broken zone, and that must not be silently overridden by the
    # configured one. Under systemd every value is already in the environment,
    # so this branch is what makes the timer and a manual run agree.
    [[ -n ${!_v+set} ]] && continue
    _val=$(conf_get "$CONF_FILE" "$_v") && printf -v "$_v" '%s' "$_val"
done
unset _v _val

# Defaults for the two settings that carry nothing site-specific. NS, ZONES and
# HC_URL deliberately have NO defaults: a built-in fallback for those is how a
# misconfigured run looks like a passing one.
: "${VALIDATORS:=1.1.1.1 8.8.8.8}"
: "${WARN_DAYS:=7}"

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
[[ -n ${ZONES:-} ]] || cfg_missing ZONES
# Not needed for --no-ping, which exists precisely so the checks can be
# exercised before there is a healthchecks.io check to point at.
((no_ping)) || [[ -n ${HC_URL:-} ]] || cfg_missing HC_URL

problems=()
summary=()
note() { problems+=("$1"); }
info() { summary+=("$1"); }

now=$(date -u +%s)

# A missing dig is itself the finding, reported through the normal path rather
# than as a silent exit — an exit here would look identical to "all healthy"
# to everything except the journal.
command -v dig >/dev/null 2>&1 \
    || { note 'dig is not installed (apt install bind9-dnsutils) — no checks ran'; ZONES=''; }

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
    local out=$1 zone=$2 name=$3 type=$4 rrsig exp ee days
    rrsig=$(awk -v t="$type" '$4=="RRSIG" && $5==t {print; exit}' <<<"$out")
    if [[ -z $rrsig ]]; then
        note "$zone @$name: $type present but not signed — signing stopped, or the zone reloaded unsigned"
        return 1
    fi
    exp=$(awk '{print $9}' <<<"$rrsig")
    if ! ee=$(epoch "$exp"); then
        note "$zone @$name: cannot parse $type RRSIG expiry ($exp)"
        return 1
    fi
    days=$(( (ee - now) / 86400 ))
    if (( days < 0 )); then
        note "$zone @$name: $type RRSIG EXPIRED ${days#-}d ago ($exp) — resolvers are already failing"
    elif (( days < WARN_DAYS )); then
        note "$zone @$name: $type RRSIG expires in ${days}d ($exp)"
    fi
    RRSIG_DAYS=$days
    return 0
}

# One nameserver, one zone. Sets NS_SERIAL and NS_RRSIG_DAYS; appends its own
# notes rather than returning them, so it must never run in a subshell — an
# array appended to inside $(...) is discarded when the subshell exits.
check_ns() {
    local zone=$1 name=$2 ip=$3 out status flags soa_days
    NS_SERIAL=''
    NS_RRSIG_DAYS=''

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
    flags=" $(hdr_flags "$out") "
    [[ $flags == *" aa "* ]] \
        || note "$zone @$name: answered without the AA flag — no longer authoritative for this zone"

    NS_SERIAL=$(awk '$4=="SOA"{print $7; exit}' <<<"$out")
    [[ -n $NS_SERIAL ]] || note "$zone @$name: NOERROR but no SOA record in the answer"

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

ns_total=$(wc -w <<<"$NS")
v_total=$(wc -w <<<"$VALIDATORS")

for zone in $ZONES; do
    answered=0 serials='' min_days=''

    for pair in $NS; do
        name=${pair%%=*}; ip=${pair#*=}
        if check_ns "$zone" "$name" "$ip"; then
            ((answered++))
            [[ -n $NS_SERIAL ]] && serials+="$name:$NS_SERIAL "
            if [[ -n $NS_RRSIG_DAYS ]]; then
                [[ -z $min_days ]] && min_days=$NS_RRSIG_DAYS
                (( NS_RRSIG_DAYS < min_days )) && min_days=$NS_RRSIG_DAYS
            fi
        fi
    done

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
        for pair in $NS; do
            name=${pair%%=*}; ip=${pair#*=}
            s=$(soa_serial "$zone" "$ip")
            [[ -n $s ]] && recheck+="$name:$s "
        done
        again=$(tr ' ' '\n' <<<"$recheck" | sed 's/.*://' | sort -u | grep -c .)
        if (( again > 1 )); then
            note "$zone: serials still disagree after 20s — $recheck (was: $serials)"
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
    v_answered=0
    for v in $VALIDATORS; do
        label="dnscheck-$RANDOM$RANDOM.$zone"
        vout=$(dig +dnssec +time=5 +tries=2 @"$v" "$label" A 2>/dev/null)
        vflags=" $(hdr_flags "$vout") "
        [[ -z $vout || $vflags == '  ' ]] && continue
        ((v_answered++))
        [[ $vflags == *" ad "* ]] \
            || note "$zone: no AD flag from $v — the DNSSEC chain is not validating"
    done
    (( v_answered == 0 )) \
        && note "$zone: no validator reachable ($VALIDATORS) — chain of trust unconfirmed"

    # Trimmed: serials accumulates a trailing space, which showed up in every
    # summary line as "ns3:2026080414 ,".
    serials_shown=${serials% }
    info "$zone: $answered/$ns_total NS up, serial ${serials_shown:-none}, RRSIG ${min_days:-?}d left, $v_answered/$v_total validators AD"
done

# ------------------------------------------------------------------ report ---

body=''
(( ${#problems[@]} )) && body+=$(printf '%s\n' "${problems[@]}")$'\n\n'
(( ${#summary[@]}  )) && body+=$(printf '%s\n' "${summary[@]}")

if (( ${#problems[@]} )); then
    printf '%s\n' "${problems[@]}" >&2
    (( no_ping )) && exit 1
    curl -fsS --max-time 20 --retry 2 --retry-delay 3 \
        --user-agent "dnscheck/1.0 ($(hostname -s 2>/dev/null || echo unknown))" \
        --data-binary "$body" -o /dev/null "${HC_URL%/}/fail" \
        || echo 'dead-man ping FAILED — healthchecks.io was not told about the failure' >&2
    exit 1
fi

(( ${#summary[@]} )) && printf '%s\n' "${summary[@]}"
(( no_ping )) && exit 0
# Retries on the success path too: a missed ping is not a missed message, it is
# an ALARM. Crying wolf teaches you to ignore the one signal whose entire
# meaning is that it stopped.
curl -fsS --max-time 20 --retry 3 --retry-delay 3 \
    --user-agent "dnscheck/1.0 ($(hostname -s 2>/dev/null || echo unknown))" \
    --data-binary "$body" -o /dev/null "$HC_URL" \
    || { echo 'dead-man ping FAILED — checks passed but healthchecks.io was not told' >&2; exit 1; }
exit 0
