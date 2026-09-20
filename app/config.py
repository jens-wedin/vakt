import os

UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
UNIFI_CONSOLE_ID = os.environ.get("UNIFI_CONSOLE_ID", "")
# Optional: the NVR's own console id — enables Protect (camera/sensor/SuperLink) health polling
UNIFI_NVR_CONSOLE_ID = os.environ.get("UNIFI_NVR_CONSOLE_ID", "")

POLL_CLIENTS_SEC = int(os.environ.get("POLL_CLIENTS_SEC", "60"))
POLL_PROTECT_SEC = int(os.environ.get("POLL_PROTECT_SEC", "120"))
POLL_CONFIG_SEC = int(os.environ.get("POLL_CONFIG_SEC", "300"))

DB_PATH = os.environ.get("DB_PATH", "./vakt.db")

# Optional ntfy topic URL, e.g. https://ntfy.sh/jens-vakt or a self-hosted instance
NTFY_URL = os.environ.get("NTFY_URL", "")

# Optional HTTP Basic auth for the dashboard (any username). Empty = no auth.
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

# Optional: the dashboard's LAN address, e.g. http://192.168.1.33:8181. Set it and
# notifications become tappable (ntfy Click header); leave empty to drop the link.
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")

# MACs excluded from traffic-anomaly checks (comma-separated), e.g. a camera
# that legitimately uploads at high rates in bursts.
TRAFFIC_EXEMPT = {m.strip().lower() for m in
                  os.environ.get("TRAFFIC_EXEMPT", "").split(",") if m.strip()}


def validate():
    missing = [n for n, v in [("UNIFI_API_KEY", UNIFI_API_KEY),
                              ("UNIFI_CONSOLE_ID", UNIFI_CONSOLE_ID)] if not v]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
