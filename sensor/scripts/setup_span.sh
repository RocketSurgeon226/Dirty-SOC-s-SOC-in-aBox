#!/usr/bin/env bash
# Owner: Adam — Configure the USB Ethernet adapter to receive mirrored (SPAN) traffic.
# Usage: sudo ./setup_span.sh [capture_interface]   (default: eth1)
set -euo pipefail

require_root() {
    if [ "$(id -u)" -ne 0 ];
    then
        echo "Run with sudo: sudo $0" >&2
        exit 1
    fi    
}

install_packages() {
    apt-get update
    apt-get install -y ethtool
}

keep_networkmanager_off() {
    local iface="$1"

    if command -v nmcli >/dev/null 2>&1;
    then
        cat > /etc/NetworkManager/conf.d/90-socbox-capture.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${iface}
EOF
        nmcli general reload conf
    fi
}

install_capture_service() {
    cat > /etc/systemd/system/socbox-capture@.service <<'EOF'
[Unit]
Description=SOC-in-a-Box capture interface %i
After=network-pre.target sys-subsystem-net-devices-%i.device
BindsTo=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env ip addr flush dev %i
ExecStart=/usr/bin/env ip link set %i up promisc on
ExecStart=-/usr/bin/env ethtool -K %i rx off tx off sg off tso off gso off gro off lro off
ExecStop=/usr/bin/env ip link set %i promisc off

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

enable_capture() {
    local iface="$1"
    systemctl enable --now "socbox-capture@${iface}.service"
}

show_status() {
    local iface="$1"
    ip -br link show "$iface"
    ethtool -k "$iface" | grep -E "^(generic-receive-offload|large-receive-offload|tcp-segmentation-offload):"
}

main() {
    require_root
    local iface="${1:-eth1}"

    install_packages
    keep_networkmanager_off "$iface"
    install_capture_service
    enable_capture "$iface"
    show_status "$iface"
    
}

main "$@"