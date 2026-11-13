#!/usr/bin/env bash
# test-parse.sh — offline checks for the field-position parsing in check-dns.sh.
#
# The parsing is the only part of that script that can be wrong *silently*.
# A dig that does not answer produces a loud "no response"; an awk column that
# is off by one produces a confident, permanently-green health check that is
# reading the wrong number. So the fixtures below are real dig output.
#
# Run: bash test-parse.sh    (no network, no dig, no DNS)

set -uo pipefail
pass=0; fail=0
is() { # is <label> <got> <want>
    if [[ $2 == "$3" ]]; then ((pass++)); else
        ((fail++)); printf 'FAIL %s\n  got:  %s\n  want: %s\n' "$1" "$2" "$3"
    fi
}

# Real `dig +dnssec +norecurse +noall +comments +answer @ns SOA` shape.
read -r -d '' SOA_OUT <<'FIXTURE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41234
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
example.com.	3600	IN	SOA	ns1.example.net. hostmaster.example.net. 2026081701 10800 3600 604800 3600
example.com.	3600	IN	RRSIG	SOA 13 3 3600 20260910000000 20260811000000 34505 example.com. abc123==
FIXTURE

read -r -d '' NXD_OUT <<'FIXTURE'
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 9
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 1
FIXTURE

read -r -d '' LAME_OUT <<'FIXTURE'
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 7
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
FIXTURE

hdr_status() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$1" | head -1; }
hdr_flags()  { sed -n 's/^;; flags: \([^;]*\);.*/\1/p'  <<<"$1" | head -1; }

is 'rcode NOERROR'  "$(hdr_status "$SOA_OUT")"  'NOERROR'
is 'rcode NXDOMAIN' "$(hdr_status "$NXD_OUT")"  'NXDOMAIN'
is 'rcode REFUSED'  "$(hdr_status "$LAME_OUT")" 'REFUSED'

is 'flags authoritative' "$(hdr_flags "$SOA_OUT")"  'qr aa'
is 'flags validated'     "$(hdr_flags "$NXD_OUT")"  'qr rd ra ad'

# The AD/AA substring tests, with the same padding the script uses. Padding
# matters: without it "ad" would also match inside "additional"-ish tokens and,
# worse, "ra" would not be distinguishable from "ad" by a naive glob.
aa=" $(hdr_flags "$SOA_OUT") "
ad=" $(hdr_flags "$NXD_OUT") "
[[ $aa == *" aa "* ]] && is 'AA detected' yes yes || is 'AA detected' no yes
[[ $ad == *" ad "* ]] && is 'AD detected' yes yes || is 'AD detected' no yes
[[ $aa == *" ad "* ]] && is 'AA output has no AD' yes no || is 'AA output has no AD' no no

# A query that got no reply. dig still writes to stdout, so the output is not
# empty — the test that once caught this, [[ -z $out ]], let it through to the
# rcode check, which printed "SOA query returned " with nothing after it.
# Both shapes: 9.18+ prints one line per try, 9.16 one line in all.
read -r -d '' TIMEOUT_918 <<'FIXTURE'
;; communications error to 192.0.2.1#53: timed out
;; communications error to 192.0.2.1#53: timed out
;; no servers could be reached
FIXTURE
read -r -d '' TIMEOUT_916 <<'FIXTURE'
;; connection timed out; no servers could be reached
FIXTURE

no_reply()   { [[ -z $(hdr_status "$1") ]]; }
dig_reason() { sed -n 's/^;; *//p' <<<"$1" | tail -1; }

no_reply "$TIMEOUT_918" && is 'timeout (9.18) is no reply' yes yes || is 'timeout (9.18) is no reply' no yes
no_reply "$TIMEOUT_916" && is 'timeout (9.16) is no reply' yes yes || is 'timeout (9.16) is no reply' no yes
no_reply ''             && is 'empty output is no reply'   yes yes || is 'empty output is no reply'   no yes
no_reply "$LAME_OUT"    && is 'REFUSED is a reply'          no no  || is 'REFUSED is a reply'          yes yes
no_reply "$SOA_OUT"     && is 'NOERROR is a reply'          no no  || is 'NOERROR is a reply'          yes yes
is 'reason, 9.18'  "$(dig_reason "$TIMEOUT_918")" 'no servers could be reached'
is 'reason, 9.16'  "$(dig_reason "$TIMEOUT_916")" 'connection timed out; no servers could be reached'
is 'reason, empty' "$(dig_reason '')" ''

# Column positions. SOA: name ttl class SOA mname rname SERIAL ...
is 'SOA serial is $7' "$(awk '$4=="SOA"{print $7; exit}' <<<"$SOA_OUT")" '2026081701'

# RRSIG: name ttl class RRSIG type alg labels origttl EXPIRY inception keytag ...
is 'RRSIG type-covered is $5' \
   "$(awk '$4=="RRSIG"{print $5; exit}' <<<"$SOA_OUT")" 'SOA'
is 'RRSIG expiry is $9' \
   "$(awk '$4=="RRSIG" && $5=="SOA"{print $9; exit}' <<<"$SOA_OUT")" '20260910000000'
is 'RRSIG inception is $10 (guards the off-by-one)' \
   "$(awk '$4=="RRSIG" && $5=="SOA"{print $10; exit}' <<<"$SOA_OUT")" '20260811000000'

# The comment lines must never be mistaken for records.
is 'comments contribute no SOA' \
   "$(awk '$4=="SOA"{print $7}' <<<"$NXD_OUT")" ''

epoch() {
    local t=${1-}
    [[ $t =~ ^[0-9]{14}$ ]] || return 1
    date -u -d "${t:0:4}-${t:4:2}-${t:6:2} ${t:8:2}:${t:10:2}:${t:12:2}" +%s 2>/dev/null
}
is 'epoch of a known RRSIG stamp' "$(epoch 20260910000000)" '1788998400'
epoch 'not-a-timestamp' >/dev/null 2>&1 && is 'junk rejected' no yes || is 'junk rejected' yes yes
epoch '' >/dev/null 2>&1 && is 'empty rejected' no yes || is 'empty rejected' yes yes


# --- the zone table -----------------------------------------------------------
#
# The parser is the other place a mistake is silent: a row that fails to parse
# and is skipped without a word means a zone stops being checked while the run
# still goes green. Every case below asserts on what the RUN would do, by
# driving the real script through --show-config rather than reimplementing the
# parsing here — a copy of the logic would only test the copy.

SCRIPT=$(dirname "$(readlink -f "$0")")/check-dns.sh
TD=$(mktemp -d) || exit 1
trap 'rm -rf "$TD"' EXIT
cat > "$TD/env" <<'CONF'
NS=ns1=192.0.2.1 ns2=192.0.2.2
VALIDATORS=1.1.1.1 8.8.8.8
WARN_PERIOD=3d
HC_URL=https://hc-ping.com/x
CONF

zt() {  # zt <zones-file-body> -> the resolved table rows, one per line
    printf '%s\n' "$1" > "$TD/zones"
    DNSCHECK_CONF="$TD/env" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --show-config 2>&1 |
        sed -n '/^ZONE  */,$p' | tail -n +2 | sed 's/  */ /g;s/ $//'
}
zerr() { # zerr <zones-file-body> -> the parse errors, one per line
    printf '%s\n' "$1" > "$TD/zones"
    DNSCHECK_CONF="$TD/env" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --no-ping 2>&1 |
        sed -n 's/^  line /line /p'
}

is 'defaults fill every "-"' \
   "$(zt 'a.com signed - - -')" 'a.com signed 3d ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'a zone overrides the default nameservers' \
   "$(zt 'a.com signed - x=10.0.0.1,y=10.0.0.2 -')" 'a.com signed 3d x=10.0.0.1,y=10.0.0.2 1.1.1.1,8.8.8.8'
is 'a zone overrides the default threshold' \
   "$(zt 'a.com signed 9d - -')" 'a.com signed 9d ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'a threshold in hours' \
   "$(zt 'a.com signed 12H - -')" 'a.com signed 12h ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'validators none survives to the resolved table' \
   "$(zt 'a.com signed - - none')" 'a.com signed 3d ns1=192.0.2.1,ns2=192.0.2.2 none'
is 'an unsigned zone carries no threshold' \
   "$(zt 'a.com unsigned - - -')" 'a.com unsigned - ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'comments and blank lines are skipped' \
   "$(zt '# a comment

a.com signed - - -   # trailing comment')" 'a.com signed 3d ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'a commented-out zone is not checked' "$(zt '#a.com signed - - -
b.com signed - - -')" 'b.com signed 3d ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'

# A bad row must be REPORTED, never silently dropped: a skipped row is a zone
# that stopped being watched while the check went on reporting success.
is 'too few columns is an error'   "$(zerr 'a.com signed -')"           'line 1: expected five columns (zone state warn nameservers validators), got: a.com signed -'
is 'a space inside a list is an error' "$(zerr 'a.com signed - x=1 y=2 -')" 'line 1: more than five columns — a list with a space in it? Use commas inside the nameserver and validator columns'
is 'an unknown state is an error'  "$(zerr 'a.com sined - - -' | cut -d. -f1)" "line 1: state must be 'signed' or 'unsigned', not 'sined'"
is 'a bare ip without a label is an error' "$(zerr 'a.com signed - 10.0.0.1 -')" "line 1: nameserver '10.0.0.1' must be label=ip — the label is what names this server in every alert"
is 'a threshold on an unsigned zone is an error' "$(zerr 'a.com unsigned 5d - -')" "line 1: a.com is unsigned, so it has no signatures to expire — warn must be '-'"
is 'a threshold with no unit is an error' "$(zerr 'a.com signed 5 - -')" "line 1: warn '5' has no unit — write 5d for days, or use s, m, h or w"
is 'an unknown unit is an error' "$(zerr 'a.com signed 5y - -')" "line 1: warn must be a whole number and a unit (s, m, h, d or w — 3d, 36h) or '-', not '5y'"
is 'a decimal is an error' "$(zerr 'a.com signed 1.5d - -')" "line 1: warn must be a whole number and a unit (s, m, h, d or w — 3d, 36h) or '-', not '1.5d'"
is 'a duplicate zone is an error' "$(zerr 'a.com signed - - -
a.com signed - - -')" 'line 2: a.com is listed twice'
is 'every fault in one pass, not the first only' \
   "$(zerr 'a.com sined - - -
b.com signed x - -' | wc -l)" '2'

# The resolved table above proves a zone's threshold was READ. This proves it
# is the one actually applied: without it, dropping the per-zone value and
# using the global default everywhere passes every other test in this file.
now=$(date -u +%s)
problems=()
note() { problems+=("$1"); }
eval "$(sed -n '/^human_span() {/,/^}/p;/^check_rrsig() {/,/^}/p;/^dur_secs() {/,/^}/p' "$SCRIPT")"

is 'seconds'  "$(dur_secs 90s)" '90'
is 'minutes'  "$(dur_secs 90m)" '5400'
is 'hours'    "$(dur_secs 36h)" '129600'
is 'days'     "$(dur_secs 3d)"  '259200'
is 'weeks'    "$(dur_secs 2w)"  '1209600'
is 'a leading zero is not octal' "$(dur_secs 010d)" '864000'
is 'a bare number is refused' "$(dur_secs 3 || echo refused)" 'refused'
is 'a space is refused'       "$(dur_secs '3 d' || echo refused)" 'refused'
is 'ms is not a unit here'    "$(dur_secs 500ms || echo refused)" 'refused'
sig5=$(date -u -d "@$(( now + 5*86400 ))" +%Y%m%d%H%M%S)
rrset="a.com. 3600 IN RRSIG SOA 13 2 3600 $sig5 20260101000000 1 a.com. AA=="

problems=(); WARN_ACTIVE=$(dur_secs 3d);  check_rrsig "$rrset" a.com ns1 SOA >/dev/null
is 'threshold 3d: five days left is quiet' "${#problems[@]}" '0'
problems=(); WARN_ACTIVE=$(dur_secs 9d);  check_rrsig "$rrset" a.com ns1 SOA >/dev/null
is 'threshold 9d: the same signature alarms' "${#problems[@]}" '1'
is 'and says how long is left' "${problems[0]#*RRSIG }" "expires in 120h ($sig5)"

# human_span picks the largest unit that says something. Days alone truncate to
# "0d" for everything inside a day, so a signature with eleven hours left and
# one with eleven minutes read identically — and both read as fine. Days only
# from a week up, so everything under a week, where the thresholds live, reads
# in hours: switching at one day read 47h as "1d".
is 'a span of days'   "$(human_span $(( 9 * 86400 + 3600 )))" '9d'
is 'exactly a week'   "$(human_span $(( 7 * 86400 )))"        '7d'
is 'just under a week' "$(human_span $(( 7 * 86400 - 1 )))"   '167h'
is 'three days'       "$(human_span $(( 3 * 86400 )))"        '72h'
is 'a day and a bit reads in hours' "$(human_span $(( 25 * 3600 )))" '25h'
is 'exactly one day'  "$(human_span 86400)"                   '24h'
is 'a span of hours'  "$(human_span $(( 11 * 3600 )))"        '11h'
is 'exactly three hours' "$(human_span $(( 3 * 3600 )))"      '3h'
is 'just under three hours' "$(human_span $(( 3 * 3600 - 1 )))" '179m'
is 'just under an hour' "$(human_span 3599)"                  '59m'
is 'a span of minutes'  "$(human_span $(( 43 * 60 )))"        '43m'
is 'less than a minute' "$(human_span 30)"                    '<1m'
is 'zero'               "$(human_span 0)"                     '<1m'

# A zone signed on the fly (Cloudflare) carries about a day of validity, all
# the time. In whole days, 2d alarms on every run and 1d sits an hour from
# doing the same; hours are what make it watchable.
sig25h=$(date -u -d "@$(( now + 25 * 3600 ))" +%Y%m%d%H%M%S)
rr25="a.com. 300 IN RRSIG SOA 13 2 300 $sig25h 20260101000000 1 a.com. AA=="
problems=(); WARN_ACTIVE=$(dur_secs 12h); check_rrsig "$rr25" a.com ns1 SOA >/dev/null
is 'threshold 12h: 25 hours left is quiet' "${#problems[@]}" '0'
problems=(); WARN_ACTIVE=$(dur_secs 26h); check_rrsig "$rr25" a.com ns1 SOA >/dev/null
is 'threshold 26h: 25 hours left alarms' "${problems[0]#*RRSIG }" "expires in 25h ($sig25h)"

problems=(); WARN_ACTIVE=$(dur_secs 3d)
sig11h=$(date -u -d "@$(( now + 11 * 3600 ))" +%Y%m%d%H%M%S)
check_rrsig "a.com. 3600 IN RRSIG SOA 13 2 3600 $sig11h 20260101000000 1 a.com. AA==" a.com ns1 SOA >/dev/null
is 'eleven hours left reports hours, not 0d' "${problems[0]#*RRSIG }" "expires in 11h ($sig11h)"

problems=(); exp11h=$(date -u -d "@$(( now - 11 * 3600 ))" +%Y%m%d%H%M%S)
check_rrsig "a.com. 3600 IN RRSIG SOA 13 2 3600 $exp11h 20260101000000 1 a.com. AA==" a.com ns1 SOA >/dev/null
is 'expired eleven hours ago says so in hours' "${problems[0]#*RRSIG }"    "EXPIRED 11h ago ($exp11h) — resolvers are already failing"


# Two separators for one kind of value is a trap at the moment a list gets
# copied between the two files. The zone table has no choice — a space there
# starts a new column — so dnscheck.env takes either and normalises.
cat > "$TD/env-commas" <<'CONF'
NS=ns1=192.0.2.1,ns2=192.0.2.2
VALIDATORS=1.1.1.1,8.8.8.8
WARN_PERIOD=3d
HC_URL=https://hc-ping.com/x
CONF
printf 'a.com signed - - -\n' > "$TD/zones"
is 'commas in dnscheck.env resolve as spaces do' \
   "$(DNSCHECK_CONF="$TD/env-commas" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --show-config 2>&1 |
      sed -n '/^ZONE  */,$p' | tail -n +2 | sed 's/  */ /g;s/ $//')" \
   'a.com signed 3d ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'

# --show-config renders lists with commas whatever the config used. Two things
# depend on it: the output is what gets pasted back into either file, and a
# list wider than its column runs into the next one — with spaces inside the
# value, every gap in that row then looks the same and there is no telling
# where the nameservers end and the validators begin.
cat > "$TD/env-messy" <<'CONF'
NS=ns1=192.0.2.1   ns2=192.0.2.2,,ns3=192.0.2.3
VALIDATORS=1.1.1.1 8.8.8.8
WARN_PERIOD=3d
HC_URL=https://hc-ping.com/x
CONF
printf 'a.com signed - - -\n' > "$TD/zones"
sc() { DNSCHECK_CONF="$TD/env-messy" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --show-config 2>&1; }
is 'the settings table renders a list with commas' \
   "$(sc | sed -n 's/^NS  *config  *\([^ ]*\).*/\1/p')" \
   'ns1=192.0.2.1,ns2=192.0.2.2,ns3=192.0.2.3'
is 'and still counts the entries' "$(sc | sed -n 's/.*(\([0-9]*\))$/\1/p' | head -1)" '3'
is 'the zone row shows both lists comma separated' \
   "$(sc | sed -n '/^a\.com/p' | sed 's/^.*  *[0-9][0-9]*[smhdw]  *//; s/  */ /g; s/ $//')" \
   'ns1=192.0.2.1,ns2=192.0.2.2,ns3=192.0.2.3 1.1.1.1,8.8.8.8'

# Column headings must sit above their column. Fixed widths meant a nameserver
# list — routinely wider than any width anyone would pick — pushed into the
# next column and left VALIDATORS floating over the middle of the nameservers.
# A heading that is not above its column is worse than none, because it is
# read as one.
#
# Both assertions are made on the WIDEST row, where the column padding is zero
# and what is left between two values is the column separator itself. On any
# narrower row the padding would swamp it and the test would pass regardless.
cat > "$TD/zones-wide" <<'ZONES'
a.io signed - x=192.0.2.9 -
some-quite-long-department.example.com.au signed - - -
ZONES
wide() { DNSCHECK_CONF="$TD/env" DNSCHECK_ZONES="$TD/zones-wide" bash "$SCRIPT" --show-config 2>&1; }

is 'the headings sit above their columns' \
   "$(wide | awk '
       /^ZONE  +STATE/ { hn=index($0,"NAMESERVERS"); hv=index($0,"VALIDATORS"); next }
       /^some-quite-long-department/ {
           print (index($0,"ns1=192.0.2.1")==hn && index($0,"1.1.1.1")==hv) ? "yes" : "no" }')" \
   'yes'

gap=$(wide | sed -n '/^some-quite-long-department/s/.*ns2=192\.0\.2\.2\( *\)1\.1\.1\.1.*/\1/p')
is 'two spaces between columns, on the row with no padding' "${#gap}" '2'

# The config-level threshold. WARN_PERIOD takes a unit and refuses a bare
# number — the likeliest leftover, since bare days were the only form before
# units. WARN_DAYS, the deprecated spelling, is still read, in whole days.
#
# Runs that get past config would go on to query the nameservers, so dig is a
# stub that fails at once: these cases are about what was READ, and a real dig
# would make them slow, and dependent on the network, for nothing.
mkdir -p "$TD/bin"; printf '#!/bin/sh\nexit 9\n' > "$TD/bin/dig"; chmod +x "$TD/bin/dig"
printf 'a.com signed - - -\n' > "$TD/zones"
setw() { { printf 'NS=ns1=192.0.2.1\nHC_URL=https://hc-ping.com/x\n'; (( $# )) && printf '%s\n' "$@"; } > "$TD/env-w"; }
run()  { PATH="$TD/bin:$PATH" DNSCHECK_CONF="$TD/env-w" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" "$@" 2>&1; }

setw 'WARN_PERIOD=3'
is 'WARN_PERIOD with no unit refuses to start' "$(run --no-ping | head -1)" \
   'missing a unit on WARN_PERIOD=3 — write WARN_PERIOD=3d for days, or use s, m, h or w.'
setw 'WARN_PERIOD=3 days'
is 'WARN_PERIOD with words in it refuses to start' "$(run --no-ping | head -1)" \
   "missing a valid WARN_PERIOD — a whole number and a unit, s m h d or w (3d, 36h), not '3 days'."
setw 'WARN_PERIOD=36h'
is 'WARN_PERIOD in hours' "$(run --show-config | awk '$1=="WARN_PERIOD"{print $2, $3}')" 'config 36h'
setw
is 'the default is 3d' "$(run --show-config | awk '$1=="WARN_PERIOD"{print $2, $3}')" 'default 3d'
is 'and no WARN_DAYS row when it is not set' "$(run --show-config | grep -c '^WARN_DAYS')" '0'

setw 'WARN_DAYS=8'
is 'WARN_DAYS=8 is WARN_PERIOD=8d' "$(run --show-config | awk '$1=="WARN_PERIOD"{print $2, $3}')" 'WARN_DAYS 8d'
is 'and the zones that use the default get it' "$(run --show-config | awk '$1=="a.com"{print $3}')" '8d'
is '--show-config marks it deprecated' "$(run --show-config | sed -n 's/^WARN_DAYS  *config  *8  *//p')" \
   '(deprecated — read as WARN_PERIOD=8d)'
is 'and the run says so, without failing on it' "$(run --no-ping | grep '^note:')" \
   "note: WARN_DAYS is deprecated — replace WARN_DAYS=8 with WARN_PERIOD=8d in $TD/env-w"
setw 'WARN_DAYS=8d'
is 'WARN_DAYS takes days only' "$(run --no-ping | head -1)" \
   "missing a whole number of days in WARN_DAYS, not '8d' — or replace it with WARN_PERIOD, which takes a unit (8d, 192h)."
setw 'WARN_DAYS=8' 'WARN_PERIOD=192h'
is 'both set refuses to start' "$(run --no-ping | head -1)" 'both WARN_PERIOD=192h and WARN_DAYS=8 are set.'
setw 'WARN_PERIOD=192h'
is 'a WARN_DAYS in the environment counts as set too' \
   "$(WARN_DAYS=8 run --no-ping | head -1)" 'both WARN_PERIOD=192h and WARN_DAYS=8 are set.'

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
