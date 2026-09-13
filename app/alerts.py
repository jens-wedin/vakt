"""Push notifications via ntfy (optional — set NTFY_URL). Only warning/critical."""
import logging

import httpx

import config

log = logging.getLogger("vakt.alerts")


async def notify(events: list[dict]):
    if not config.NTFY_URL:
        return
    for e in events:
        if e["severity"] not in ("warning", "critical"):
            continue
        try:
            async with httpx.AsyncClient(timeout=10) as cx:
                await cx.post(
                    config.NTFY_URL,
                    content=e["message"].encode(),
                    headers={
                        "Title": f"vakt: {e['kind']}",
                        "Priority": "high" if e["severity"] == "critical" else "default",
                        "Tags": "rotating_light" if e["severity"] == "critical" else "warning",
                    })
        except Exception as ex:  # alerting must never kill the poller
            log.warning("ntfy notification failed: %s", ex)
