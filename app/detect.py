"""Detection rules. Each processor takes fresh API data, updates the store,
and returns the list of newly created events (already persisted)."""
import hashlib
import json
import time

import config
import store

# Traffic anomaly tuning: learn ~30 min, then flag uploads that are both
# absolutely high (>2 Mbit/s) and far above the device's own baseline (8×),
# sustained for 10+ minutes. One alert per device per 6 h.
TRAFFIC_LEARN_SAMPLES = 30
TRAFFIC_ABS_FLOOR_BPS = 250_000          # bytes/s ≈ 2 Mbit/s
TRAFFIC_EWMA_FACTOR = 8
TRAFFIC_SUSTAIN_SEC = 600
TRAFFIC_REALERT_SEC = 6 * 3600
TRAFFIC_EWMA_ALPHA = 0.1

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


def _traffic_check(c: dict, prev, now_ts: float) -> tuple[dict, str | None]:
    """Update per-device upload EWMA from counter deltas; return (field updates,
    anomaly message or None). Counter resets and irregular sample gaps are skipped."""
    pre = "wired-" if c.get("is_wired") else ""
    rx = c.get(pre + "rx_bytes")  # rx_* = FROM the client = upload
    tx = c.get(pre + "tx_bytes")
    upd: dict = {"last_rx_bytes": rx, "last_tx_bytes": tx, "last_counter_ts": now_ts}
    if rx is None or prev is None or prev["last_rx_bytes"] is None \
            or prev["last_counter_ts"] is None:
        return upd, None
    dt = now_ts - prev["last_counter_ts"]
    drx = rx - prev["last_rx_bytes"]
    if not (10 <= dt <= 600) or drx < 0:  # gap too odd, or counter reset (reboot)
        return upd, None
    rate = drx / dt
    ewma = prev["ewma_up"] or 0.0
    samples = prev["samples"] or 0
    learning = samples < TRAFFIC_LEARN_SAMPLES
    is_high = (not learning) and \
        rate > max(TRAFFIC_ABS_FLOOR_BPS, TRAFFIC_EWMA_FACTOR * ewma)

    # Learn only from normal samples — a baseline that keeps learning during an
    # anomaly chases the attack traffic and dissolves the alert condition.
    if not is_high:
        upd |= {"ewma_up": ewma + TRAFFIC_EWMA_ALPHA * (rate - ewma),
                "samples": samples + 1, "high_since": None}
        return upd, None

    high_since = prev["high_since"]
    if not high_since:
        upd["high_since"] = now_ts
    elif now_ts - high_since >= TRAFFIC_SUSTAIN_SEC:
        upd["high_since"] = None
        last_alert = prev["last_traffic_alert"]
        if last_alert is None or now_ts - last_alert >= TRAFFIC_REALERT_SEC:
            # Adopt the new level so a legitimately changed usage pattern
            # alerts once instead of every 6 hours.
            upd |= {"last_traffic_alert": now_ts, "ewma_up": rate}
            return upd, (f"uploading {rate * 8 / 1e6:.1f} Mbps sustained for 10+ min "
                         f"(its normal baseline is {ewma * 8 / 1e6:.2f} Mbps)")
    return upd, None


def process_clients(clients: list[dict]) -> list[dict]:
    events = []
    known = store.get_devices()
    baseline = store.get_meta("baseline_done") != "1"
    seen = store.now_iso()
    now_ts = time.time()

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

        if mac.lower() in config.TRAFFIC_EXEMPT:
            continue
        upd, anomaly = _traffic_check(c, prev, now_ts)
        store.update_device_fields(mac, **upd)
        if anomaly:
            sev = "critical" if network == "IoT" else "warning"
            events.append(store.add_event("traffic_anomaly", sev, mac,
                                          f"\"{name}\" is {anomaly}"))

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
