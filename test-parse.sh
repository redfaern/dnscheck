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
WARN_DAYS=3
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
   "$(zt 'a.com signed - - -')" 'a.com signed 3 ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'a zone overrides the default nameservers' \
   "$(zt 'a.com signed - x=10.0.0.1,y=10.0.0.2 -')" 'a.com signed 3 x=10.0.0.1,y=10.0.0.2 1.1.1.1,8.8.8.8'
is 'a zone overrides the default threshold' \
   "$(zt 'a.com signed 9 - -')" 'a.com signed 9 ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'validators none survives to the resolved table' \
   "$(zt 'a.com signed - - none')" 'a.com signed 3 ns1=192.0.2.1,ns2=192.0.2.2 none'
is 'an unsigned zone carries no threshold' \
   "$(zt 'a.com unsigned - - -')" 'a.com unsigned - ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'comments and blank lines are skipped' \
   "$(zt '# a comment

a.com signed - - -   # trailing comment')" 'a.com signed 3 ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'
is 'a commented-out zone is not checked' "$(zt '#a.com signed - - -
b.com signed - - -')" 'b.com signed 3 ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'

# A bad row must be REPORTED, never silently dropped: a skipped row is a zone
# that stopped being watched while the check went on reporting success.
is 'too few columns is an error'   "$(zerr 'a.com signed -')"           'line 1: expected five columns (zone state warn-days nameservers validators), got: a.com signed -'
is 'a space inside a list is an error' "$(zerr 'a.com signed - x=1 y=2 -')" 'line 1: more than five columns — a list with a space in it? Use commas inside the nameserver and validator columns'
is 'an unknown state is an error'  "$(zerr 'a.com sined - - -' | cut -d. -f1)" "line 1: state must be 'signed' or 'unsigned', not 'sined'"
is 'a bare ip without a label is an error' "$(zerr 'a.com signed - 10.0.0.1 -')" "line 1: nameserver '10.0.0.1' must be label=ip — the label is what names this server in every alert"
is 'a threshold on an unsigned zone is an error' "$(zerr 'a.com unsigned 5 - -')" "line 1: a.com is unsigned, so it has no signatures to expire — warn-days must be '-'"
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
eval "$(sed -n '/^check_rrsig() {/,/^}/p' "$SCRIPT")"
sig5=$(date -u -d "@$(( now + 5*86400 ))" +%Y%m%d%H%M%S)
rrset="a.com. 3600 IN RRSIG SOA 13 2 3600 $sig5 20260101000000 1 a.com. AA=="

problems=(); WARN_ACTIVE=3;  check_rrsig "$rrset" a.com ns1 SOA >/dev/null
is 'threshold 3: five days left is quiet' "${#problems[@]}" '0'
problems=(); WARN_ACTIVE=9;  check_rrsig "$rrset" a.com ns1 SOA >/dev/null
is 'threshold 9: the same signature alarms' "${#problems[@]}" '1'
is 'and says how long is left' "${problems[0]#*RRSIG }" "expires in 5d ($sig5)"

# Two separators for one kind of value is a trap at the moment a list gets
# copied between the two files. The zone table has no choice — a space there
# starts a new column — so dnscheck.env takes either and normalises.
cat > "$TD/env-commas" <<'CONF'
NS=ns1=192.0.2.1,ns2=192.0.2.2
VALIDATORS=1.1.1.1,8.8.8.8
WARN_DAYS=3
HC_URL=https://hc-ping.com/x
CONF
printf 'a.com signed - - -\n' > "$TD/zones"
is 'commas in dnscheck.env resolve as spaces do' \
   "$(DNSCHECK_CONF="$TD/env-commas" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --show-config 2>&1 |
      sed -n '/^ZONE  */,$p' | tail -n +2 | sed 's/  */ /g;s/ $//')" \
   'a.com signed 3 ns1=192.0.2.1,ns2=192.0.2.2 1.1.1.1,8.8.8.8'

# --show-config renders lists with commas whatever the config used. Two things
# depend on it: the output is what gets pasted back into either file, and a
# list wider than its column runs into the next one — with spaces inside the
# value, every gap in that row then looks the same and there is no telling
# where the nameservers end and the validators begin.
cat > "$TD/env-messy" <<'CONF'
NS=ns1=192.0.2.1   ns2=192.0.2.2,,ns3=192.0.2.3
VALIDATORS=1.1.1.1 8.8.8.8
WARN_DAYS=3
HC_URL=https://hc-ping.com/x
CONF
printf 'a.com signed - - -\n' > "$TD/zones"
sc() { DNSCHECK_CONF="$TD/env-messy" DNSCHECK_ZONES="$TD/zones" bash "$SCRIPT" --show-config 2>&1; }
is 'the settings table renders a list with commas' \
   "$(sc | sed -n 's/^NS  *config  *\([^ ]*\).*/\1/p')" \
   'ns1=192.0.2.1,ns2=192.0.2.2,ns3=192.0.2.3'
is 'and still counts the entries' "$(sc | sed -n 's/.*(\([0-9]*\))$/\1/p' | head -1)" '3'
is 'the zone row separates its two lists by exactly one space' \
   "$(sc | sed -n '/^a\.com/p' | sed 's/^.*  *[0-9][0-9]*  *//')" \
   'ns1=192.0.2.1,ns2=192.0.2.2,ns3=192.0.2.3 1.1.1.1,8.8.8.8'
printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
