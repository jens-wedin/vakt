import asyncio
import contextlib
import logging
import secrets as pysecrets
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import alerts
import config
import detect
import store
import unifi
import web

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("vakt")

_fail = {"clients": 0, "protect": 0, "config": 0}


async def _poll(which: str, interval: int, fetch, process):
    while True:
        try:
            data = await fetch()
            events = process(data)
            events += detect.poller_recovered(which, _fail[which] >= 5)
            _fail[which] = 0
            store.set_meta(f"last_{which}_poll", store.now_iso())
            await alerts.notify(events)
            for e in events:
                log.info("event [%s] %s", e["severity"], e["message"])
        except Exception as ex:
            _fail[which] += 1
            log.warning("%s poll failed (%d in a row): %s", which, _fail[which], ex)
            await alerts.notify(detect.poller_failed(which, _fail[which], str(ex)))
        await asyncio.sleep(interval)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    config.validate()
    store.db()
    tasks = [
        asyncio.create_task(
            _poll("clients", config.POLL_CLIENTS_SEC, unifi.get_clients, detect.process_clients)),
        asyncio.create_task(
            _poll("config", config.POLL_CONFIG_SEC, unifi.get_config_state, detect.process_config)),
    ]
    if config.UNIFI_NVR_CONSOLE_ID:
        tasks.append(asyncio.create_task(
            _poll("protect", config.POLL_PROTECT_SEC, unifi.get_protect_devices, detect.process_protect)))
    else:
        log.info("UNIFI_NVR_CONSOLE_ID not set — Protect polling disabled")
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(lifespan=lifespan)
_basic = HTTPBasic(auto_error=False)


def require_auth(request: Request, creds: HTTPBasicCredentials | None = Depends(_basic)):
    """HTTP Basic auth when DASHBOARD_PASSWORD is set (any username), plus a
    same-origin check on state-changing methods (CSRF: browsers always send
    Origin on cross-site POSTs; absent Origin+Referer means a non-browser
    client like curl, which CSRF cannot drive)."""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin") or request.headers.get("referer") or ""
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(status_code=403, detail="cross-origin request rejected")
    if not config.DASHBOARD_PASSWORD:
        return
    if creds is None or not pysecrets.compare_digest(
            creds.password.encode(), config.DASHBOARD_PASSWORD.encode()):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic realm=vakt"})


@app.get("/", response_class=HTMLResponse)
def dashboard(_=Depends(require_auth)):
    return web.render()


@app.post("/verdict/{event_id}/{verdict}")
def verdict(event_id: int, verdict: str, _=Depends(require_auth)):
    if verdict not in ("ok", "not_ok"):
        raise HTTPException(status_code=400, detail="verdict must be ok or not_ok")
    e = store.set_event_verdict(event_id, verdict)
    # A verdict on a device-related event also sets that device's trust status.
    if e and e["mac"] and e["kind"] in ("new_device", "network_change", "traffic_anomaly"):
        store.set_device_status(e["mac"], "ok" if verdict == "ok" else "flagged")
    return RedirectResponse("/", status_code=303)


@app.get("/healthz")
def healthz():
    return JSONResponse({
        "last_clients_poll": store.get_meta("last_clients_poll"),
        "last_protect_poll": store.get_meta("last_protect_poll"),
        "last_config_poll": store.get_meta("last_config_poll"),
        "consecutive_failures": _fail,
    })
