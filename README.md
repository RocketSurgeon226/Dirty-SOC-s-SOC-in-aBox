# Dirty-SOC-s-SOC-in-aBox

**SOC in a Box** is a low-cost (~$188) Raspberry Pi 5 home network security system that detects suspicious activity with Suricata and explains each alert in plain language for homeowners with no cybersecurity experience.

## Team

| Name | Role |
|---|---|
| Adam | Packet Capture and Sensor Setup |
| Caleb | Threat Intelligence and Device Discovery |
| Brady | Rules Engine/Alert Logic |
| Aron | Dashboard/Frontend |
| Quinn | Integration, QA and Demo Coordination |

**Mentor:** Yamen Ziadeh

## How It Works

1. **Traffic collection:** home network traffic is copied to the Pi through a managed switch's mirrored (SPAN) port, or through an inline bridge as a fallback.
2. **Detection:** Suricata inspects the traffic using the Emerging Threats Open ruleset, the URLhaus ruleset, and our custom rules, and writes findings to `eve.json`.
3. **Analysis:** a Python service reads `eve.json`, removes duplicate alerts, assigns a low / medium / high severity, tracks the device inventory, and translates each alert into a plain-language card.
4. **Dashboard:** a local Flask/FastAPI web dashboard shows the alert cards, the device inventory, and a network health score.

Each alert card has four parts: a friendly device name, a severity level, a one-sentence description of what happened, and one recommended action. An optional LLM can improve the wording, but written templates always work without it.

## Alert Categories

| Category | Severity | What the homeowner sees |
|---|---|---|
| Known-malicious IP/domain contact | High | "This device contacted a known bad server." |
| Plaintext credential transmission | High | "A device on your network sent a password in an unprotected way." |
| Port scan | Medium | "Someone or something scanned your network from outside." |
| New or unknown device | Medium | "A new device joined your network; was this you?" |
| Anomalous outbound volume | Medium | "This device is sending far more data than usual." |
| Excessive ad/tracker DNS | Low | "This device is sending an unusual amount of data to ad and tracking companies." |

## Repo Layout

| Folder | Owner | Contents |
|---|---|---|
| `sensor/` | Adam | Suricata config, custom rules, SPAN / inline bridge setup scripts |
| `threat_intel/` | Caleb | Threat feed updates, tracker domain list |
| `analysis/` | Brady | Python analysis service: eve.json reader, dedup, severity, redaction, health score |
| `analysis/detectors/` | Brady, Caleb | Python-side detections: outbound volume, tracker DNS, new device, reputation |
| `analysis/translate/` | Brady | Plain-language templates, card builder, optional LLM |
| `dashboard/` | Aron | Web dashboard and device-labeling flow |
| `tests/` | Quinn | Unit tests, traffic trigger scripts, sample data |
| `docs/` | Everyone | Report sections, demo script, ethics paper |

## Hardware

| Item | Qty | Est. Cost |
|---|---|---|
| Raspberry Pi 5 | 1 | $85 |
| Power supply (USB-C) | 1 | $12 |
| Case with active cooling / heatsink | 1 | $10 |
| microSD card, 32–64 GB | 1 | $14 |
| Managed switch with port mirroring | 1 | $40 |
| USB Ethernet adapter | 1 | $12 |
| Cat 6 cables | 3 | $15 |
| **Total** | **9** | **$188** |

## Setup

These are the steps used to deploy SOC in a Box on a Raspberry Pi 5 (8 GB) running Raspberry Pi OS, with Suricata 8.0.7 built from source. Run everything on the Pi as the normal user (`dirtysocs` below) unless a command uses `sudo`.

### Network layout

The Pi has two network connections:

- **`eth0` (built-in Ethernet): capture only.** Plug it into the managed switch's mirror (destination) port. It has no IP address, and the setup script removes any it gets.
- **`wlan0` (Wi-Fi): management.** SSH, `git pull`, rule downloads and the dashboard all use this connection.

```
internet ── router (DHCP) ── managed switch ── monitored device(s)  (mirror SOURCE port)
                                    └────────── Pi eth0             (mirror DESTINATION port)
Pi wlan0 ── Wi-Fi (management + dashboard)
```

On the switch, set the Pi's port to **Mirroring**, with the monitored port(s) as the source in both directions (ingress and egress). On a TP-Link Omada switch, this is under Devices → the switch → Ports → edit the Pi's port → Operation: **Mirroring**.

Mirror only the ports you mean to monitor. For testing, that's the test machine's port alone, so no one else's traffic is captured (see [Privacy](#privacy)).

### 1. Remove any packaged Suricata

The source build installs into `/usr`. An apt-installed Suricata in the same place causes conflicts, so remove it first:

```bash
sudo systemctl disable --now suricata
sudo apt purge -y suricata suricata-update && sudo apt autoremove -y
```

### 2. Clone the repo

```bash
sudo apt install -y git jq tcpdump
sudo git clone https://github.com/RocketSurgeon226/Dirty-SOC-s-SOC-in-aBox /opt/soc-in-a-box
sudo chown -R dirtysocs:dirtysocs /opt/soc-in-a-box
cd /opt/soc-in-a-box
```

All later steps run from `/opt/soc-in-a-box`.

### 3. Check the capture interface name

```bash
ip -br link
```

The default is `eth0`. If you capture on a different interface, change it in all four places below:

- `af-packet: interface` in `sensor/suricata/suricata.yaml`
- `After=`, `Requires=` and `--af-packet=` in `sensor/systemd/suricata.service`
- `capture_interface` in `config/settings.yaml` (step 7)
- the argument to `setup_span.sh` (step 6)

### 4. Build Suricata 8.0.7

Copy the rule skip list in **before** building. The install script finishes with `suricata-update`, whose self-test fails on the DNP3 and Modbus rules unless `disable.conf` is already in place:

```bash
sudo mkdir -p /etc/suricata
sudo cp sensor/suricata/disable.conf /etc/suricata/disable.conf
sudo ./sensor/scripts/install_suricata.sh      # about 20–40 min on a Pi 5
```

What the script does:

1. Installs the build dependencies
2. Builds and installs Suricata 8.0.7 (Lua is always built in on 8.x)
3. Checks the build for `HAVE_LUA`
4. Enables the ET Open rule source and downloads it with `suricata-update`

### 5. Install the config and rules, then test them

Do this **after** the build. The build's `make install-conf` overwrites `/etc/suricata/suricata.yaml`, so copying the config earlier would be undone.

```bash
sudo mkdir -p /etc/suricata/rules
sudo cp sensor/suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo cp sensor/suricata/rules/*.rules sensor/suricata/lua/plaintext_creds.lua /etc/suricata/rules/
sudo suricata -T -c /etc/suricata/suricata.yaml -v
echo $?
```

A passing test prints `3 rule files processed. N rules successfully loaded, 0 rules failed` and `Configuration provided was successfully loaded`, and `echo $?` prints `0`. Don't continue until it does.

The `-T` test exits silently on some errors, including a missing rule file, so always check the `echo $?` result.

### 6. Prepare the capture port

```bash
sudo ./sensor/scripts/setup_span.sh eth0
```

This removes `eth0`'s IP address and turns on promiscuous mode, so `eth0` only listens. It also stops NetworkManager from managing `eth0`, and installs `socbox-capture@eth0.service` to repeat this on every boot. Run it from a keyboard and monitor, or over Wi-Fi, never over an SSH session that uses `eth0`.

### 7. Set up Python

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config/settings.example.yaml config/settings.yaml
nano config/settings.yaml      # check capture_interface and home_networks
sudo apt install -y nmap       # MAC-to-vendor names on the dashboard
```

`home_networks` must include the monitored network's address range. Suricata's `HOME_NET` in `suricata.yaml` uses the same three private ranges by default.

### 8. Install and start the services

```bash
which suricata                                  # must print /usr/bin/suricata (matches ExecStart)
sudo cp sensor/systemd/*.service /etc/systemd/system/
sudo chmod 755 /var/log/suricata                # lets the dashboard user read eve.json
sudo systemctl daemon-reload
sudo systemctl enable --now suricata socbox-analysis socbox-dashboard
```

Wait about 2 minutes for Suricata to load its rules, then install the hourly threat-intel refresh:

```bash
sudo ./threat_intel/install_feed_timer.sh
```

| Service | What it runs |
|---|---|
| `suricata` | Suricata in SPAN mode on `eth0` |
| `socbox-analysis` | `python -m analysis.main`: reads `eve.json` and writes alert cards to SQLite |
| `socbox-dashboard` | `dashboard/app.py`: the web dashboard on port 8080 |
| `socbox-feeds.timer` | Runs hourly: `suricata-update` with a live rule reload, then `update_feeds.sh` (rebuilds the URLhaus domain and IP lists) |

### 9. Verify

**Is Suricata seeing mirrored traffic?**

```bash
sudo tail -n 500 /var/log/suricata/eve.json | jq -r .event_type | sort | uniq -c
```

You should see `dns` and `flow` events. If it's almost all `arp`, the switch isn't mirroring to the Pi's port. To watch packets arrive in real time, use `sudo tcpdump -ni eth0 not arp`. `flow` events only appear once a flow ends, which can take up to 5 minutes for ICMP.

**Did the threat-intel lists load?**

```bash
journalctl -u socbox-analysis -n 30 --no-pager | grep -i malicious
# Loaded N malicious domain(s), N IP(s)
```

**Does an alert reach the dashboard?** From a test machine on the mirrored port, send fake credentials over plain HTTP:

```bash
curl -u testuser:testpass http://neverssl.com/
curl -d "username=testuser&password=testpass" http://example.com/
```

Then check on the Pi:

```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | grep -v Ethertype | tail -5 \
  | jq -c '{sig: .alert.signature, src: .src_ip}'
```

You should see `SOCBOX Plaintext HTTP Basic Auth` and `SOCBOX Plaintext login form POST`. Open the dashboard at `http://localhost:8080` on the Pi, or `http://<pi-wifi-ip>:8080` from another device. It shows a high-severity "sent a password in an unprotected way" card. The dashboard has no login, so anyone on the network can open it.

### Updating

```bash
cd /opt/soc-in-a-box && git pull
# After changing Suricata config, rules, or the Lua script:
sudo cp sensor/suricata/suricata.yaml /etc/suricata/
sudo cp sensor/suricata/rules/*.rules sensor/suricata/lua/plaintext_creds.lua /etc/suricata/rules/
sudo suricata -T -c /etc/suricata/suricata.yaml && sudo systemctl reload suricata
# After changing Python code:
sudo systemctl restart socbox-analysis socbox-dashboard
```

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Out of memory: Killed process … (Suricata-Main)` in `sudo dmesg` | Too many rules loaded at once. With ET Open only, Suricata uses about 1.2 GB. The URLhaus Suricata ruleset pushed it to about 4.6 GB, and a live reload needs room for two copies. URLhaus is matched in Python instead, so don't add it back as a `suricata-update` source. |
| `pid file '/run/suricata.pid' exists but appears stale` | Left behind by a crashed Suricata. `suricata.service` no longer uses `--pidfile`. If it happens anyway: `sudo rm -f /run/suricata.pid && sudo systemctl reset-failed suricata && sudo systemctl start suricata` |
| `protocol "dnp3"/"modbus" cannot be used in a signature` | `/etc/suricata/disable.conf` is missing. Copy it in and rerun `sudo suricata-update`. |
| `suricata-update` ends with `Suricata test failed` and no error lines | Usually out of memory during its self-test. Check `sudo dmesg`. Stop Suricata during big rule updates, or use `--no-test` and then run `suricata -T` yourself. |
| `No rule files match the pattern /var/lib/suricata/rules/suricata.rules` | `suricata-update` hasn't written the rules yet. Run `sudo suricata-update`. |
| Many `SURICATA Ethertype unknown` alerts with `src: null` | Decoder noise from switch discovery frames, such as TP-Link/Omada. Harmless: they never become cards. To silence them, add `2200121` to `disable.conf`. |
| `DNS EVE v2 logging has been deprecated` notice | Expected. The Python detectors read the v2 format, so leave `version: 2` until they're updated for v3, which is required before Suricata 9.0. |
| `SOCBOX Plaintext login form POST` never fires | The Lua script must use the `suricata.http` library. On Suricata 8, `lua:` scripts are not given sticky buffers like `http.request_body`. |


## Testing

All testing happens on an isolated test network using generated or prerecorded traffic (nmap, hping3, iperf3, tcpreplay).

- **Detection accuracy:** 10 trials per category; a category passes at 9 of 10 correct alert cards.
- **Throughput:** iperf3 at 50–940 Mbps; pass = zero kernel packet drops at or below 250 Mbps.
- **False positives:** seven-day clean-traffic baseline; target fewer than five unexplained alerts per day.
- **Unit tests:** pytest for scoring, deduplication, and card assembly, run by GitHub Actions on every pull request.
- **Usability:** 10 non-technical reviewers; pass = at least 80% correctly identify what happened and the next step.

<!-- How to run unit tests and traffic tests -->

## Team Workflow

<!-- Branching, pull requests, reviews -->

## Privacy

- Only alert metadata is stored.
- Credentials are redacted before they reach an alert card.
- Logs are deleted after a set retention period (TBD).
- Testing uses only our own isolated network, so no one else's data is captured.