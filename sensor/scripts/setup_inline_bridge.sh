#!/usr/bin/env bash
# Owner: Adam — Fallback: set up the Pi as an inline bridge.
# Usage: sudo ./setup_inline_bridge.sh [port_a] [port_b]   (default: eth0 eth1)
# Remember to run this from a keyboard and monitor: moving eth0 into the bridge drops an SSH session

set -euo pipefail

require_root() {
    if [ "$(id -u)" -ne 0 ];
    then
        echo "Run with sudo: sudo $0" >&2
        exit 1
    fi    
}

require_networkmanager() {
    if ! command -v nmcli >/dev/null 2>&1;
    then
        echo "nmcli not found. This script expects NetworkManager (Raspberry Pi OS Bookworm)." >&2
        exit 1
    fi
}

install_packages() {
    apt-get update
    apt-get install -y iptables
}

enable_bridge_netfilter() {
    modprobe br_netfilter
    echo "br_netfilter" > /etc/modules-load.d/socbox-br_netfilter.conf

    cat > /etc/sysctl.d/99-socbox-bridge.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
    sysctl --system > /dev/null
}

install_nfqueue_service() {
    cat > /etc/systemd/system/socbox-nfqueue.service <<'EOF'
[Unit]
Description=SOC-in-a-Box send bridged traffic to Suricata (NFQUEUE)
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
ExecStart=/usr/bin/env ip6tables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
ExecStop=/usr/bin/env iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
ExecStop=/usr/bin/env ip6tables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now socbox-nfqueue.service
}

create_bridge() {
    local port_a="$1"
    local port_b="$2"

    nmcli connection add type bridge ifname br0 con-name socbox-br0 \
        bridge.stp no ipv4.method auto ipv6.method auto \
        connection.autoconnect-priority 100

    nmcli connection add type bridge-slave ifname "$port_a" master br0 \
        con-name "socbox-br0-${port_a}" connection.autoconnect-priority 100

    nmcli connection add type bridge-slave ifname "$port_b" master br0 \
        con-name "socbox-br0-${port_b}" connection.autoconnect-priority 100

    nmcli connection up socbox-br0
    nmcli connection up "socbox-br0-${port_a}"
    nmcli connection up "socbox-br0-${port_b}"
}

main() {
    require_root
    require_networkmanager
    local port_a="${1:-eth0}"
    local port_b="${2:-eth1}"

    install_packages
    enable_bridge_netfilter
    install_nfqueue_service
    create_bridge "$port_a" "$port_b"
    
    echo "Bridge br0 is up. Start Suricata inline with: sudo suricata -c /etc/suricata/suricata.yaml -q 0"
}

main "$@"