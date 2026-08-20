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

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
