"""UniFi Site Manager cloud connector client (read-only, GET requests only)."""
import httpx

import config

BASE = "https://api.ui.com/v1/connector/consoles"


def _headers():
    return {"X-API-KEY": config.UNIFI_API_KEY}


async def get_clients() -> list[dict]:
    """All currently-connected network clients (legacy stat/sta — richest data)."""
    url = f"{BASE}/{config.UNIFI_CONSOLE_ID}/proxy/network/api/s/default/stat/sta"
    async with httpx.AsyncClient(timeout=30) as cx:
        r = await cx.get(url, headers=_headers())
        r.raise_for_status()
        return r.json()["data"]


async def get_config_state() -> dict[str, list[dict]]:
    """Security-relevant gateway config, grouped by collection, for drift detection."""
    base = f"{BASE}/{config.UNIFI_CONSOLE_ID}/proxy/network"
    out: dict[str, list[dict]] = {}
    async with httpx.AsyncClient(timeout=30) as cx:
        async def legacy(path):
            r = await cx.get(f"{base}/api/s/default/{path}", headers=_headers())
            r.raise_for_status()
            return r.json()["data"]

        out["firewallrule"] = await legacy("rest/firewallrule")
        out["portforward"] = await legacy("rest/portforward")
        out["wlanconf"] = await legacy("rest/wlanconf")
        out["networkconf"] = await legacy("rest/networkconf")
        # Full settings dump is huge; watch the sections that matter for security.
        out["setting"] = [s for s in await legacy("get/setting")
                          if s.get("key") in ("usg", "ips", "mgmt")]
        r = await cx.get(f"{base}/v2/api/site/default/nat", headers=_headers())
        r.raise_for_status()
        out["nat"] = r.json()
    return out


async def get_protect_devices() -> list[dict]:
    """Protect device states from the NVR console: cameras, sensors, link stations.

    Returns [{id, kind, name, state}] — state is Protect's own, e.g. CONNECTED/DISCONNECTED.
    """
    url = f"{BASE}/{config.UNIFI_NVR_CONSOLE_ID}/proxy/protect/api/bootstrap"
    async with httpx.AsyncClient(timeout=30) as cx:
        r = await cx.get(url, headers=_headers())
        r.raise_for_status()
        boot = r.json()
    # Protect 7.x lists the SuperLink under both "bridges" and "linkstations";
    # key on MAC and let the later collection win so it appears once.
    by_key: dict[str, dict] = {}
    for coll, kind in [("cameras", "camera"), ("sensors", "sensor"),
                       ("chimes", "chime"), ("lights", "light"),
                       ("bridges", "bridge"), ("linkstations", "linkstation")]:
        for d in boot.get(coll) or []:
            key = d.get("mac") or d.get("id")
            by_key[key] = {
                "id": key,
                "kind": kind,
                "name": d.get("name") or d.get("marketName") or d.get("mac", "?"),
                "state": d.get("state") or "UNKNOWN",
            }
    return list(by_key.values())
