# Owner: Caleb — Refresh threat intel every hour: suricata-update (ET Open + URLhaus rules,
# then a live rule reload) and update_feeds.sh (malicious_domains.txt).
# Usage: sudo ./threat_intel/install_feed_timer.sh

#!/usr/bin/env bash
set -euo pipefail

require_root() {
    if [ "$(id -u)" -ne 0 ];
    then
        echo "Run with sudo: sudo $0" >&2
        exit 1
    fi    
}

install_units() {
    local root="$1"

    cat > /etc/systemd/system/socbox-capture@.service <<'EOF'
[Unit]
Description=SOC-in-a-Box threat intel refresh
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# Test merged rules with suricata -T, then tells running Suricata to reload them (SIGUSR2)
ExecStart=/usr/bin/env --reload-command "systemctl kill -s USR2 suricata.service"
ExecStart=${root}/threat_intel/update_feeds.sh ${root}
UNIT

    cat > /etc/systemd/system/socbox-feeds.timer <<'UNIT'
[Unit]
Description=Run SOC-in-a-Box threat intel refresh hourly

[Timer]
OnBootSec=5min
OnCalendar=hourly
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload

}


main() {
    require_root
    local root
    root="$(cd "$(dirname "$0)/.. && pwd"

    install_units "$root"
    systemctl enable --now socbox-feeds.timer
    systemctl list-timers socbox-feeds.timer
    
}

main "$@"