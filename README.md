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
4. Deploy. The dashboard is on port 8080; keep it LAN-only (don't put a public
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

## Design notes

- **Read-only by construction** — the app only performs GET requests. It can
  never change network config, so a compromised dashboard can't reconfigure
  anything.
- Polls: clients every 60 s, Protect every 120 s → ~1.5 requests/min, far under
  the 100 req/min per-console cloud limit.
- The device registry keys on MAC. Phones with per-network private WiFi
  addresses use a stable MAC per SSID, so they baseline once per network.

## Roadmap (not in v1)

- Config-drift detection: diff firewall rules, port forwards, UPnP, WLAN and
  NAT settings against a stored golden state.
- Traffic anomaly detection from per-client byte counters (note: counters are
  unreliable for multiple wired clients sharing one switch port — see
  `../memory.md`).
- Local-mode polling against `https://192.168.1.1` with a console-local API key
  (works with internet down; needs testing of which endpoints accept local keys).
- Dashboard auth + event acknowledge/mute.
