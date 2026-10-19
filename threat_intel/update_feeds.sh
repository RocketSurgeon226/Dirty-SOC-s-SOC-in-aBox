#!/usr/bin/env bash
# Owner: Caleb — Pull Emerging Threats Open + URLhaus rulesets and reload Suricata.
set -euo pipefail
ROOT="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
TI="$ROOT/threat_intel"
RULE_DIR="$ROOT/sensor/suricata/rules"
CONFIG="$ROOT/sensor/suricata/suricata.yaml"
FEEDS="$TI/feeds.yaml"
mkdir -p "$TI" "$RULE_DIR"
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
[[ -s "$FEEDS" ]] || { echo "Missing feed configuration: $FEEDS" >&2; exit 1; }

# Read simple key: URL entries from feeds.yaml without requiring a YAML parser.
feed_url() { awk -F':[[:space:]]*' -v key="$1" '$1 == "  " key {print $2; exit}' "$FEEDS"; }
URLHAUS_DOMAINS="$(feed_url urlhaus_domains)"
URLHAUS_RULES="$(feed_url urlhaus_suricata)"
EMERGING_URL="$(feed_url emerging_threats)"
for url in "$URLHAUS_DOMAINS" "$URLHAUS_RULES" "$EMERGING_URL"; do
  [[ "$url" == https://* ]] || { echo "Feed URL missing/invalid in $FEEDS" >&2; exit 1; }
done
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fetch() { curl --fail --location --silent --show-error --max-time 120 "$1" -o "$2"; }
valid_rules() {
  local f="$1"
  [[ -s "$f" ]] || { echo "Refusing empty rules file: $f" >&2; return 1; }
  grep -Eq '^[[:space:]]*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)[[:space:]]+(tcp|udp|icmp|ip|http|tls|dns|ssh|ftp|smb|dcerpc|modbus|dnp3|s7comm|ikev2|krb5|ntp|dhcp|rdp|snmp|sip|tftp|enip|cip|http2|quic|mqtt|pgsql|pop3|imap|smtp|filedata|pkthdr)[[:space:]]+' "$f" || {
    echo "No recognizable Suricata rules in $f" >&2; return 1;
  }
  if grep -Eqi '<html|<!doctype html|access denied|not found' "$f"; then
    echo "Downloaded content looks like an error page: $f" >&2; return 1
  fi
}

# Stage URLhaus domain indicators.
fetch "$URLHAUS_DOMAINS" "$TMP/urlhaus-hosts.txt"
awk ' /^[[:space:]]*#/ {next} NF >= 2 {d=tolower($2); if (d !~ /^localhost$/ && d !~ /^[0-9.]+$/ && d !~ /^\[/) print d}' \
  "$TMP/urlhaus-hosts.txt" | sort -u > "$TMP/malicious_domains.txt"
[[ -s "$TMP/malicious_domains.txt" ]] || { echo "URLhaus domain feed was empty/invalid" >&2; exit 1; }

# Stage and validate URLhaus rules.
fetch "$URLHAUS_RULES" "$TMP/urlhaus.rules"
valid_rules "$TMP/urlhaus.rules"

# Stage and validate Emerging Threats Open rules.
fetch "$EMERGING_URL" "$TMP/emerging.tar.gz"
tar -tzf "$TMP/emerging.tar.gz" >/dev/null
mkdir -p "$TMP/extracted"
tar -xzf "$TMP/emerging.tar.gz" -C "$TMP/extracted"
EMERGING="$(find "$TMP/extracted" -type f \( -name 'emerging-all.rules' -o -name 'emerging.rules' \) -print -quit)"
if [[ -z "$EMERGING" ]]; then
  find "$TMP/extracted" -type f -name '*.rules' -print0 | xargs -0 cat > "$TMP/emerging-combined.rules"
  EMERGING="$TMP/emerging-combined.rules"
fi
cp "$EMERGING" "$TMP/emerging.rules"
valid_rules "$TMP/emerging.rules"

# Validate staged rules with Suricata before replacing any currently installed file.
if command -v suricata >/dev/null && grep -qE '^[[:space:]]*af-packet:|^[[:space:]]*default-rule-path:' "$CONFIG"; then
  suricata -T -c "$CONFIG" -S "$TMP/urlhaus.rules"
  suricata -T -c "$CONFIG" -S "$TMP/emerging.rules"
fi

# Install only after every download and validation step succeeded.
mv "$TMP/malicious_domains.txt" "$TI/malicious_domains.txt"
mv "$TMP/urlhaus.rules" "$RULE_DIR/urlhaus.rules"
mv "$TMP/emerging.rules" "$RULE_DIR/emerging.rules"
echo "Updated indicators and rules. Confirm these files are included in the active Suricata rule configuration, then reload/restart Suricata."