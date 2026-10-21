#!/usr/bin/env bash
# Owner: Caleb — Build threat_intel/malicious_domains.txt from the URLhaus hostfile.
set -euo pipefail
ROOT="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
TI="$ROOT/threat_intel"
# RULE_DIR="$ROOT/sensor/suricata/rules"
# CONFIG="$ROOT/sensor/suricata/suricata.yaml"
FEEDS="$TI/feeds.yaml"
mkdir -p "$TI"
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
# command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
[[ -s "$FEEDS" ]] || { echo "Missing feed configuration: $FEEDS" >&2; exit 1; }

# Read simple key: URL entries from feeds.yaml without requiring a YAML parser.
feed_url() { awk -v key="$1:" '$1 == "  " key {print $2; exit}' "$FEEDS"; }
URLHAUS_DOMAINS="$(feed_url urlhaus_domains)"
URLHAUS_URLS="$(feed_url urlhaus_urls)"
# EMERGING_URL="$(feed_url emerging_threats)"
for url in "$URLHAUS_DOMAINS" "$URLHAUS_URLS"; do
  [[ "$url" == https://* ]] || { echo "Feed URL missing/invalid in $FEEDS" >&2; exit 1; }
done
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fetch() { curl --fail --location --silent --show-error --max-time 120 "$1" -o "$2"; }
# valid_rules() {
#   local f="$1"
#   [[ -s "$f" ]] || { echo "Refusing empty rules file: $f" >&2; return 1; }
#   grep -Eq '^[[:space:]]*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)[[:space:]]+(tcp|udp|icmp|ip|http|tls|dns|ssh|ftp|smb|dcerpc|modbus|dnp3|s7comm|ikev2|krb5|ntp|dhcp|rdp|snmp|sip|tftp|enip|cip|http2|quic|mqtt|pgsql|pop3|imap|smtp|filedata|pkthdr)[[:space:]]+' "$f" || {
#     echo "No recognizable Suricata rules in $f" >&2; return 1;
#   }
#   if grep -Eqi '<html|<!doctype html|access denied|not found' "$f"; then
#     echo "Downloaded content looks like an error page: $f" >&2; return 1
#   fi
# }

# Stage URLhaus domain indicators from the hostfile.
fetch "$URLHAUS_DOMAINS" "$TMP/urlhaus-hosts.txt"
awk ' /^[[:space:]]*#/ {next} NF >= 2 {d=tolower($2); if (d !~ /^localhost$/ && d !~ /^[0-9.]+$/ && d !~ /^\[/) print d}' \
  "$TMP/urlhaus-hosts.txt" | sort -u > "$TMP/malicious_domains.txt"
[[ -s "$TMP/malicious_domains.txt" ]] || { echo "URLhaus domain feed was empty/invalid" >&2; exit 1; }

# URLhaus's online plain-text list is one URL per line. Extract raw IPv4 hosts
# separately so URLhaus URLs hosted directly on IP addresses are also matched
# by analysis/detectors/reputation.py. An empty IP list is valid.
fetch "$URLHAUS_URLS" "$TMP/urlhaus-urls.txt"
if ! grep -Eo '^https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' "$TMP/urlhaus-urls.txt" \
    | sed -E 's#^https?://##' \
    | awk -F. 'NF == 4 && $1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255' \
    | sort -u > "$TMP/malicious_ips.txt"; then
  : # grep returns 1 when the feed contains no raw-IP URLs; keep an empty list.
fi
if [[ ! -s "$TMP/malicious_ips.txt" ]]; then
  echo "URLhaus online URL list contained no raw IPv4 hosts; installing an empty malicious_ips.txt" >&2
fi

# Stage and validate Emerging Threats Open rules only. URLhaus matching is Python-side.
# fetch "$EMERGING_URL" "$TMP/emerging.tar.gz"
# tar -tzf "$TMP/emerging.tar.gz" >/dev/null
# mkdir -p "$TMP/extracted"
# tar -xzf "$TMP/emerging.tar.gz" -C "$TMP/extracted"
# EMERGING="$(find "$TMP/extracted" -type f \( -name 'emerging-all.rules' -o -name 'emerging.rules' \) -print -quit)"
# if [[ -z "$EMERGING" ]]; then
#   find "$TMP/extracted" -type f -name '*.rules' -print0 | xargs -0 cat > "$TMP/emerging-combined.rules"
#   EMERGING="$TMP/emerging-combined.rules"
# fi
# cp "$EMERGING" "$TMP/emerging.rules"
# valid_rules "$TMP/emerging.rules"

# # Validate staged ET Open rules with Suricata before replacing the installed copy.
# if command -v suricata >/dev/null && grep -qE '^[[:space:]]*af-packet:|^[[:space:]]*default-rule-path:' "$CONFIG"; then
#   suricata -T -c "$CONFIG" -S "$TMP/emerging.rules"
# fi

# Install only after all required downloads and rule validation succeeded.
# URLhaus indicator lists are data files consumed by reputation.py, not Suricata rules.
mv "$TMP/malicious_domains.txt" "$TI/malicious_domains.txt"
mv "$TMP/malicious_ips.txt" "$TI/malicious_ips.txt"
# mv "$TMP/emerging.rules" "$RULE_DIR/emerging.rules"
chmod 644 "$TI/malicious_domains.txt" "$TI/malicious_ips.txt"
#echo "Updated URLhaus IP/domain indicators and Emerging Threats Open rules. URLhaus is matched by Python reputation.py; only ET Open rules are installed for Suricata. Confirm the active Suricata configuration includes emerging.rules, then reload/restart Suricata as appropriate."
echo "Updated $TI/malicious_domains.txt ($(wc -l < "$TI/malicious_domains.txt") domains) and $TI/malicious_ips.txt ($(wc -l < "$TI/malicious_ips.txt") IPs)."