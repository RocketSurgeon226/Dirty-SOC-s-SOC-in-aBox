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

<!-- Steps to install and run the system -->

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