# vakt — network watchtower

A small, **read-only** security monitor for the home UniFi network. It polls the
UniFi cloud API, keeps a registry of known devices in SQLite, and raises events
when something changes. Dashboard on port 8080.

## What v1 detects

| Event | Severity | Meaning |
|---|---|---|
| `new_device` | critical on Default, warning on IoT, info on Free WiFi | A MAC never seen before joined the network |
| `network_change` | warning | A known device switched VLANs |
| `protect_down` / `protect_up` | critical / info | A Protect camera, sensor, or SuperLink changed state (needs `UNIFI_NVR_CONSOLE_ID`) |
| `config_added` / `config_changed` / `config_removed` | critical for firewall rules, port forwards, NAT rules, and UPnP flips; warning for WLAN/network/settings drift | Gateway config drifted from the stored golden state (checked every 5 min; WiFi passphrases and other secrets are compared as hashes, never stored; runtime pointers that move on their own, like the IPS engine's `last_alert_id`, are excluded — they are not configuration) |
| `ips_alert` | info | The gateway's IPS engine logged a new alert. Dashboard only: the alert log itself isn't readable through the API, so open Settings → Security on the console to see what it caught |
| `traffic_anomaly` | critical on IoT, warning elsewhere | A device's upload ran >2 Mbit/s AND 8× its own learned baseline, sustained 10+ min (learns ~30 min first; max one alert per device per 6 h; exempt devices via `TRAFFIC_EXEMPT`) |
| `poller_error` / `poller_ok` | warning / info | The API polling itself broke or recovered |
| `baseline` | info | First run: all current devices registered as known (no alert storm) |

On the first run everything currently online becomes the baseline; alerts start
from the second poll onward.

## Deploy with Coolify

1. Push this `vakt/` directory to a git repo Coolify can reach.
2. Coolify → New resource → **Docker Compose** (or Dockerfile), point at the repo.
3. Set the environment variables from `.env.example` in Coolify's UI
   (mark `UNIFI_API_KEY` as a secret). Values live in the parent project's
   `memory.md` / `.env` — never commit them.
4. Deploy. The dashboard is published on host port 8181; keep it LAN-only (don't put a public
   domain on it) or protect it behind Coolify's auth/proxy if you expose it.

## Run locally (dev)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; source .env; set +a         # your real values, based on .env.example
cd app && ../.venv/bin/uvicorn main:app --port 8080
```

## Push notifications (optional)

Set `NTFY_URL` to an [ntfy](https://ntfy.sh) topic URL (public ntfy.sh with a
long random topic name, or self-host ntfy in Coolify). Warning/critical events
are pushed; info events only show on the dashboard.

Notifications are written to be read on a lock screen: the title says what
happened, the body names the device, where it is, and why it alerted.

```
🚨🆕  New device on Default
      Galaxy-S23 · Wi-Fi · 192.168.1.94
      aa:bb:cc:dd:ee:ff
      Never seen before — tap to review.
```

Critical events carry 🚨 plus a symbol for the kind; warnings carry the kind
symbol alone, so severity and type are both readable without opening the
notification. Set `DASHBOARD_URL` (e.g. `http://192.168.1.33:8181`) and tapping
a notification opens the dashboard; leave it empty and the link is dropped.

An event whose structured detail is missing or malformed still pushes — it
falls back to the same one-line message the dashboard shows. A badly worded
alert beats a missing one.

## Design notes

- **Read-only by construction** — the app only performs GET requests. It can
  never change network config, so a compromised dashboard can't reconfigure
  anything.
- Polls: clients every 60 s, Protect every 120 s → ~1.5 requests/min, far under
  the 100 req/min per-console cloud limit.
- The device registry keys on MAC. Phones with per-network private WiFi
  addresses use a stable MAC per SSID, so they baseline once per network.

## Dashboard auth & event triage

Set `DASHBOARD_PASSWORD` to require HTTP Basic auth on the dashboard (any
username). Warning/critical events get **OK** / **Not OK** buttons: OK dims the
event and marks the related device as verified (✓ in the device table); Not OK
flags the event and device in red and counts on the "to review / flagged"
card until resolved (press OK later to clear). Note: wired byte counters are
unreliable for devices sharing one switch port (see `../memory.md`), so traffic
anomalies mostly matter for WiFi clients.

## Tests

No dependencies beyond the standard library:

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

`test_alerts.py` covers notification rendering; `test_detect_renders.py` covers
the detector → renderer contract, so a renamed field can't silently downgrade
every notification to its raw-message fallback.

## Roadmap

- Local-mode polling against `https://192.168.1.1` with a console-local API key
  (works with internet down; needs a local key created on the console first).
