"""Detection rules. Each processor takes fresh API data, updates the store,
and returns the list of newly created events (already persisted)."""
import store


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
