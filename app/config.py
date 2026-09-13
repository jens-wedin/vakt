import os

UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
UNIFI_CONSOLE_ID = os.environ.get("UNIFI_CONSOLE_ID", "")
# Optional: the NVR's own console id — enables Protect (camera/sensor/SuperLink) health polling
UNIFI_NVR_CONSOLE_ID = os.environ.get("UNIFI_NVR_CONSOLE_ID", "")

POLL_CLIENTS_SEC = int(os.environ.get("POLL_CLIENTS_SEC", "60"))
POLL_PROTECT_SEC = int(os.environ.get("POLL_PROTECT_SEC", "120"))

DB_PATH = os.environ.get("DB_PATH", "./vakt.db")

# Optional ntfy topic URL, e.g. https://ntfy.sh/jens-vakt or a self-hosted instance
NTFY_URL = os.environ.get("NTFY_URL", "")


def validate():
    missing = [n for n, v in [("UNIFI_API_KEY", UNIFI_API_KEY),
                              ("UNIFI_CONSOLE_ID", UNIFI_CONSOLE_ID)] if not v]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
