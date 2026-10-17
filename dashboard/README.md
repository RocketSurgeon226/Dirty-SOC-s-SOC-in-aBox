# Dashboard (Owner: Aron)

The web dashboard for SOC-In-a-Box: alert cards, the network health score with a 7-day
trend, and the device list with first-connect naming. It's a Flask app. The pages draw
themselves from a JSON API and refresh every 5 seconds. Nothing loads from the internet,
so it works on an isolated test network.

## Run it

From the repo root, in a virtual environment (this avoids the "externally managed" pip error on Macs):

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python3 dashboard/app.py --demo        # fake data, works on any computer
```

Open http://localhost:8080. The pill at the top right says "Demo data".

On the Pi, with Brady's service running:

```bash
python3 -m analysis.main               # Brady's service (watches eve.json, writes cards)
python3 dashboard/app.py               # the dashboard (reads the same database)
```

The port, the host and the `eve.json` path come from `config/settings.yaml`; `--port`, `--host`
and `--eve` override them. Check the connection to the analysis service any time with
`python3 dashboard/app.py --check`.

## What's in the folder

| File | What it does |
|---|---|
| `app.py` | The Flask app: three pages, the JSON API, and the command line |
| `dashboard_state.py` | Builds what the pages show, and saves names. Falls back to basic alerts from `eve.json` if the analysis service isn't there |
| `analysis_bridge.py` | The only file that talks to Brady's code (`analysis/storage/db.py`, `analysis/health_score.py`) |
| `templates/index.html` | Alerts page: cards, health score and trend, device summary |
| `templates/devices.html` | Every device, with rename |
| `templates/setup.html` | First-connect flow: name the devices that are new |
| `templates/base.html` | Shared top bar and navigation |
| `static/js/app.js` | Draws all three pages and runs the naming form |
| `static/css/dashboard.css` | Styles. Red/amber/green are used only for severity |
| `../tests/test_dashboard.py` | pytest tests (pages, API, naming, "Got it", health) |

## API

`GET /api/state` (everything), `/api/alerts`, `/api/devices`, `/api/health`.
`POST /api/devices/<mac>/name` with `{"name": "Kid's Xbox", "icon": "device-tv"}`,
`POST /api/devices/<mac>/skip`, `POST /api/cards/<id>/ack` ("Got it").

## How it connects to Brady's service

The two programs share one SQLite file. The dashboard reads cards, devices and the health
score from it, and writes two things back: a device's name and "Got it" on a card.

- A name given in the dashboard is saved in Brady's device inventory, so cards show it,
  including older cards.
- A card marked "Got it" leaves the page and stops counting against the health score.
- If his code or the database can't be read, the dashboard stays up, shows basic Suricata
  alerts instead, and explains why at the top of the page.
- On the Pi, Brady's config loader needs PyYAML: `sudo apt install python3-yaml`.

## Things to know

- The dashboard saves the icon you pick for a device in `dashboard/device_names.json`.
  It holds device names and MAC addresses, so keep it out of git:
  add `dashboard/device_names.json` and `__pycache__/` to `.gitignore`.
- The health score is Brady's 0-100 number with a Good/Fair/At risk label. The proposal says
  A+ to F letter grades. The team should pick one (the dashboard shows whichever it's given).
- There is no login. The server listens on `dashboard.host` from the settings (0.0.0.0 by
  default), so anyone on the network can open it. Use `--host 127.0.0.1` to limit it to the Pi.
- In basic mode (no analysis service) the device list comes from the Pi's ARP table
  (`ip neigh`), which only works on Linux.