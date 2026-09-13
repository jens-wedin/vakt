import asyncio
import contextlib
import logging

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

import alerts
import config
import detect
import store
import unifi
import web

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("vakt")

_fail = {"clients": 0, "protect": 0}


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
    tasks = [asyncio.create_task(
        _poll("clients", config.POLL_CLIENTS_SEC, unifi.get_clients, detect.process_clients))]
    if config.UNIFI_NVR_CONSOLE_ID:
        tasks.append(asyncio.create_task(
            _poll("protect", config.POLL_PROTECT_SEC, unifi.get_protect_devices, detect.process_protect)))
    else:
        log.info("UNIFI_NVR_CONSOLE_ID not set — Protect polling disabled")
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return web.render()


@app.get("/healthz")
def healthz():
    return JSONResponse({
        "last_clients_poll": store.get_meta("last_clients_poll"),
        "last_protect_poll": store.get_meta("last_protect_poll"),
        "consecutive_failures": _fail,
    })
