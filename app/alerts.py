"""Push notifications via ntfy (optional — set NTFY_URL). Only warning/critical.

Events carry a `detail` dict from the detectors; render() turns it into a
notification a human reads on a lock screen: what happened in the title, the
device and the reason in the body. Events without detail fall back to their
raw message — a notification that reads badly still beats a missing alert.
"""
import logging

import httpx

import config

log = logging.getLogger("vakt.alerts")

# One symbol per event kind. Critical events get the siren in front of it, so
# severity and kind are both readable without opening the notification.
KIND_TAG = {
    "new_device": "new",
    "network_change": "arrows_counterclockwise",
    "traffic_anomaly": "chart_with_upwards_trend",
    "protect_down": "no_entry",
    "protect_up": "white_check_mark",
    "config_added": "wrench",
    "config_changed": "wrench",
    "config_removed": "wrench",
    "poller_error": "warning",
    "poller_ok": "white_check_mark",
    "baseline": "clipboard",
}

CONFIG_VERB = {"config_added": "added", "config_changed": "changed",
               "config_removed": "removed"}


def _tap(invite: str = "tap to review") -> str:
    """End a line with an invitation to tap — only if there's somewhere to go."""
    return f" — {invite}." if config.DASHBOARD_URL else "."


def _where(d: dict) -> str:
    return f"{d['name']} · {d['link']} · {d['ip'] or 'no IP yet'}"


def _new_device(d):
    return (f"New device on {d['network']}",
            [_where(d), d["mac"], "Never seen before" + _tap()])


def _network_change(d):
    return (f"{d['name']} switched to {d['network']}",
            [_where(d), d["mac"], f"Previously on {d['prev_network']}" + _tap()])


def _traffic_anomaly(d):
    return (f"Unusual upload from {d['name']}",
            [f"{d['name']} · {d['network']} · {d['ip'] or 'no IP'}",
             f"Uploading {d['rate_mbps']} Mbit/s for {d['minutes']} min",
             f"Normally {d['baseline_mbps']} Mbit/s" + _tap()])


def _protect_title(d, ending):
    # "Front Door" + sensor -> "Front Door sensor"; "Garage Camera" + camera
    # -> "Garage Camera" (don't stutter).
    kind = d["kind"]
    name = d["name"] if kind.lower() in d["name"].lower() else f"{d['name']} {kind}"
    return f"{name} {ending}"


def _protect_down(d):
    return (_protect_title(d, "offline"),
            [f"Protect {d['kind']} — {d['state']}", "Tap to review." if config.DASHBOARD_URL else ""])


def _protect_up(d):
    return _protect_title(d, "is back"), [f"Protect {d['kind']} — {d['state']}"]


def _config(kind):
    def render(d):
        lines = [f'"{d["name"]}"'] + list(d.get("changes") or [])
        if d.get("more"):
            lines.append(f"+{d['more']} more changes")
        if config.DASHBOARD_URL:
            lines.append("Tap to open vakt.")
        return f"{d['label']} {CONFIG_VERB[kind]}", lines
    return render


def _poller_error(d):
    return ("vakt lost contact with UniFi",
            [f"{d['which']} polling has failed {d['consecutive']} times in a row.",
             str(d["error"])[:160]])


def _poller_ok(d):
    return f"{d['which']} polling recovered", []


RENDERERS = {
    "new_device": _new_device,
    "network_change": _network_change,
    "traffic_anomaly": _traffic_anomaly,
    "protect_down": _protect_down,
    "protect_up": _protect_up,
    "config_added": _config("config_added"),
    "config_changed": _config("config_changed"),
    "config_removed": _config("config_removed"),
    "poller_error": _poller_error,
    "poller_ok": _poller_ok,
}


def render(event: dict) -> dict:
    """Event -> {title, body, tags, priority, click} for ntfy."""
    kind, severity = event["kind"], event["severity"]
    detail = event.get("detail") or {}
    renderer = RENDERERS.get(kind)

    title, lines = f"vakt: {kind}", [event["message"]]
    if renderer and detail:
        try:
            title, lines = renderer(detail)
        except Exception as ex:  # a malformed detail must never lose the alert
            log.warning("could not render %s (%s) — falling back to raw message", kind, ex)

    tag = KIND_TAG.get(kind, "warning")
    return {
        "title": title,
        "body": "\n".join(ln for ln in lines if ln),
        "tags": f"rotating_light,{tag}" if severity == "critical" else tag,
        "priority": "high" if severity == "critical" else "default",
        "click": config.DASHBOARD_URL,
    }


async def notify(events: list[dict]):
    if not config.NTFY_URL:
        return
    for e in events:
        if e["severity"] not in ("warning", "critical"):
            continue
        n = render(e)
        headers = {"Title": n["title"], "Priority": n["priority"], "Tags": n["tags"]}
        if n["click"]:
            headers["Click"] = n["click"]
        try:
            async with httpx.AsyncClient(timeout=10) as cx:
                await cx.post(config.NTFY_URL, content=n["body"].encode(), headers=headers)
        except Exception as ex:  # alerting must never kill the poller
            log.warning("ntfy notification failed: %s", ex)
