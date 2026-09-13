"""Detection rules. Each processor takes fresh API data, updates the store,
and returns the list of newly created events (already persisted)."""
import hashlib
import json

import store

CONFIG_LABEL = {
    "firewallrule": "Firewall rule",
    "portforward": "Port forward",
    "nat": "NAT rule",
    "wlanconf": "WLAN",
    "networkconf": "Network",
    "setting": "Setting",
}
# Changes here can open the network to the outside — always critical.
CRITICAL_COLLECTIONS = {"firewallrule", "portforward", "nat"}


def _client_name(c: dict) -> str:
    return c.get("name") or c.get("hostname") or c.get("oui") or "unknown device"


def _new_device_severity(network: str) -> str:
    # A stranger on the trusted LAN is the alarm; guest churn is expected.
    if network == "Default":
        return "critical"
    if network == "Free WiFi":
        return "info"
    return "warning"


def process_clients(clients: list[dict]) -> list[dict]:
    events = []
    known = store.get_devices()
    baseline = store.get_meta("baseline_done") != "1"
    seen = store.now_iso()

    for c in clients:
        mac = c.get("mac")
        if not mac:
            continue
        network = c.get("network") or "?"
        ip = c.get("ip") or ""
        name = _client_name(c)
        prev = known.get(mac)

        if prev is None:
            store.upsert_device(mac, name, network, ip, c.get("is_wired"), seen)
            if not baseline:
                kind = "wired" if c.get("is_wired") else "WiFi"
                events.append(store.add_event(
                    "new_device", _new_device_severity(network), mac,
                    f"New {kind} device \"{name}\" ({mac}) joined {network} with IP {ip or '—'}"))
        else:
            if prev["last_network"] and network != "?" and network != prev["last_network"]:
                events.append(store.add_event(
                    "network_change", "warning", mac,
                    f"\"{name}\" moved from {prev['last_network']} to {network}"))
            store.upsert_device(mac, name, network, ip, c.get("is_wired"), seen)

    if baseline:
        store.set_meta("baseline_done", "1")
        events.append(store.add_event(
            "baseline", "info", None,
            f"Baseline created: {len(clients)} devices registered as known"))
    return events


def process_protect(devices: list[dict]) -> list[dict]:
    events = []
    known = store.get_protect_devices()
    for d in devices:
        prev = known.get(d["id"])
        if prev is not None and prev["state"] != d["state"]:
            if d["state"] == "CONNECTED":
                events.append(store.add_event(
                    "protect_up", "info", None,
                    f"Protect {d['kind']} \"{d['name']}\" is back: {d['state']}"))
            else:
                events.append(store.add_event(
                    "protect_down", "critical", None,
                    f"Protect {d['kind']} \"{d['name']}\" changed to {d['state']}"))
        store.upsert_protect_device(d["id"], d["kind"], d["name"], d["state"])
    return events


def _cfg_id(obj: dict) -> str:
    return str(obj.get("_id") or obj.get("id") or obj.get("key") or "?")


def _cfg_name(obj: dict) -> str:
    return obj.get("name") or obj.get("description") or obj.get("key") or _cfg_id(obj)


def _cfg_normalize(obj: dict) -> dict:
    out = {}
    for k, v in obj.items():
        if k.startswith("attr_"):
            continue
        if k.startswith("x_") and v:  # secrets (passphrases etc.): keep only a digest
            out[k] = "sha256:" + hashlib.sha256(str(v).encode()).hexdigest()[:16]
        else:
            out[k] = v
    return out


def _cfg_severity(coll: str, obj: dict, changed_fields: list[str] | None) -> str:
    if coll in CRITICAL_COLLECTIONS:
        return "critical"
    if coll == "setting" and obj.get("key") == "usg" and \
            any("upnp" in f for f in changed_fields or []):
        return "critical"  # UPnP flipped — inbound exposure possible
    return "warning"


def process_config(state: dict[str, list[dict]]) -> list[dict]:
    events = []
    baseline = store.get_meta("config_baseline_done") != "1"
    stored = store.get_config_objects()
    seen = set()
    total = 0

    for coll, objs in state.items():
        label = CONFIG_LABEL.get(coll, coll)
        for o in objs:
            total += 1
            oid = _cfg_id(o)
            seen.add((coll, oid))
            norm = _cfg_normalize(o)
            data = json.dumps(norm, sort_keys=True, default=str)
            name = _cfg_name(o)
            prev = stored.get((coll, oid))
            if prev is None:
                store.upsert_config_object(coll, oid, name, data)
                if not baseline:
                    events.append(store.add_event(
                        "config_added", _cfg_severity(coll, norm, None), None,
                        f"{label} \"{name}\" was added"))
            elif prev["data"] != data:
                old = json.loads(prev["data"])
                changed = sorted(k for k in set(old) | set(norm)
                                 if old.get(k) != norm.get(k))
                detail = "; ".join(
                    f"{k}: {json.dumps(old.get(k), default=str)} → "
                    f"{json.dumps(norm.get(k), default=str)}"[:120]
                    for k in changed[:3])
                if len(changed) > 3:
                    detail += f" (+{len(changed) - 3} more)"
                store.upsert_config_object(coll, oid, name, data)
                events.append(store.add_event(
                    "config_changed", _cfg_severity(coll, norm, changed), None,
                    f"{label} \"{name}\" changed — {detail}"))

    for (coll, oid), row in stored.items():
        if (coll, oid) not in seen:
            store.delete_config_object(coll, oid)
            events.append(store.add_event(
                "config_removed",
                "critical" if coll in CRITICAL_COLLECTIONS else "warning", None,
                f"{CONFIG_LABEL.get(coll, coll)} \"{row['name']}\" was removed"))

    if baseline:
        store.set_meta("config_baseline_done", "1")
        events.append(store.add_event(
            "baseline", "info", None,
            f"Config baseline created: {total} objects across {len(state)} collections"))
    return events


def poller_failed(which: str, consecutive: int, error: str) -> list[dict]:
    # One event when a poller crosses the failure threshold, not one per failure.
    if consecutive == 5:
        return [store.add_event("poller_error", "warning", None,
                                f"{which} polling has failed 5 times in a row: {error[:200]}")]
    return []


def poller_recovered(which: str, was_failing: bool) -> list[dict]:
    if was_failing:
        return [store.add_event("poller_ok", "info", None, f"{which} polling recovered")]
    return []
