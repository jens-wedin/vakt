"""Dashboard: one server-rendered page, auto-refreshing. Read-only."""
from datetime import datetime, timezone
from html import escape

import store

SEV_COLOR = {"critical": "#e5484d", "warning": "#e2a336", "info": "#5a9e6f"}


def _age(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return iso
    s = int((datetime.now(timezone.utc) - dt).total_seconds())
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60}m ago"
    if s < 172800:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def render() -> str:
    devices = sorted(store.get_devices().values(),
                     key=lambda r: (r["last_network"] or "", r["last_ip"] or ""))
    events = store.recent_events(100)
    protect = sorted(store.get_protect_devices().values(), key=lambda r: r["kind"])

    nets: dict[str, int] = {}
    for d in devices:
        nets[d["last_network"] or "?"] = nets.get(d["last_network"] or "?", 0) + 1
    protect_down = [p for p in protect if p["state"] != "CONNECTED"]
    unreviewed = sum(1 for e in events
                     if e["severity"] != "info" and not e["verdict"] and not e["acked"])
    flagged = sum(1 for e in events if e["verdict"] == "not_ok")

    cards = f"""
      <div class="card"><div class="num">{len(devices)}</div><div>known devices</div></div>
      <div class="card"><div class="num">{escape(', '.join(f'{n}: {c}' for n, c in sorted(nets.items())) or '—')}</div><div>by network</div></div>
      <div class="card {'bad' if protect_down else 'ok'}"><div class="num">{len(protect_down)}</div><div>Protect devices down</div></div>
      <div class="card {'bad' if flagged else ('warn' if unreviewed else 'ok')}"><div class="num">{unreviewed} / {flagged}</div><div>to review / flagged</div></div>
      <div class="card"><div class="num">{len(store.get_config_objects())}</div><div>config objects watched</div></div>
      <div class="card"><div class="num">{_age(store.get_meta('last_clients_poll'))}</div><div>last client poll</div></div>
      <div class="card"><div class="num">{_age(store.get_meta('last_protect_poll'))}</div><div>last Protect poll</div></div>
      <div class="card"><div class="num">{_age(store.get_meta('last_config_poll'))}</div><div>last config poll</div></div>
    """

    protect_rows = "".join(
        f"<tr><td>{escape(p['kind'])}</td><td>{escape(p['name'])}</td>"
        f"<td class='{'okc' if p['state'] == 'CONNECTED' else 'badc'}'>{escape(p['state'])}</td>"
        f"<td>{_age(p['last_change'])}</td></tr>"
        for p in protect) or "<tr><td colspan=4>no Protect data (set UNIFI_NVR_CONSOLE_ID)</td></tr>"

    def _verdict_cell(e):
        if e["severity"] == "info":
            return "<td></td>"
        ok_btn = (f"<form method='post' action='/verdict/{e['id']}/ok'>"
                  f"<button class='ackbtn'>OK</button></form>")
        if e["verdict"] == "ok" or (e["acked"] and not e["verdict"]):
            return "<td class='dim'>✓ ok</td>"
        if e["verdict"] == "not_ok":
            return f"<td><span class='flag'>⚠ flagged</span> {ok_btn}</td>"
        no_btn = (f"<form method='post' action='/verdict/{e['id']}/not_ok'>"
                  f"<button class='ackbtn no'>Not OK</button></form>")
        return f"<td class='btns'>{ok_btn}{no_btn}</td>"

    def _row_class(e):
        if e["verdict"] == "not_ok":
            return "flagrow"
        if e["verdict"] == "ok" or e["acked"]:
            return "dim"
        return ""

    event_rows = "".join(
        f"<tr class='{_row_class(e)}'><td>{_age(e['ts'])}</td>"
        f"<td><span class='sev' style='background:{SEV_COLOR.get(e['severity'], '#888')}'>{escape(e['severity'])}</span></td>"
        f"<td>{escape(e['kind'])}</td><td>{escape(e['message'])}</td>{_verdict_cell(e)}</tr>"
        for e in events) or "<tr><td colspan=5>no events yet</td></tr>"

    def _dev_status(d):
        ok_btn = (f"<form method='post' action='/device/{escape(d['mac'])}/ok'>"
                  f"<button class='ackbtn'>OK</button></form>")
        no_btn = (f"<form method='post' action='/device/{escape(d['mac'])}/not_ok'>"
                  f"<button class='ackbtn no'>Not OK</button></form>")
        if d["status"] == "flagged":
            return f"<span class='flag'>⚠ flagged</span> {ok_btn}"
        if d["status"] == "ok":
            return f"<span class='okc'>✓</span> {no_btn}"
        return f"{ok_btn}{no_btn}"

    device_rows = "".join(
        f"<tr class='{'flagrow' if d['status'] == 'flagged' else ''}'>"
        f"<td>{escape(d['last_network'] or '?')}</td><td>{escape(d['last_ip'] or '—')}</td>"
        f"<td>{escape(d['name'] or '?')}</td><td class='btns'>{_dev_status(d)}</td>"
        f"<td class='mono'>{escape(d['mac'])}</td>"
        f"<td>{'wired' if d['is_wired'] else 'WiFi'}</td>"
        f"<td>{_age(d['last_seen'])}</td><td>{_age(d['first_seen'])}</td></tr>"
        for d in devices)

    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>vakt</title>
<style>
  body {{ font: 14px/1.5 -apple-system, system-ui, sans-serif; margin: 0; background: #14161a; color: #d7dae0; }}
  header {{ padding: 14px 22px; border-bottom: 1px solid #2a2e35; display: flex; gap: 10px; align-items: baseline; }}
  h1 {{ font-size: 18px; margin: 0; }} h1 span {{ color: #5a9e6f; }}
  header small {{ color: #8b909a; }}
  main {{ padding: 18px 22px; max-width: 1100px; margin: 0 auto; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 22px; }}
  .card {{ background: #1c1f25; border: 1px solid #2a2e35; border-radius: 8px; padding: 12px 16px; min-width: 130px; }}
  .card .num {{ font-size: 17px; font-weight: 600; }}
  .card div:last-child {{ color: #8b909a; font-size: 12px; }}
  .card.bad {{ border-color: #e5484d; }} .card.ok .num {{ color: #5a9e6f; }} .card.bad .num {{ color: #e5484d; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: .06em; color: #8b909a; margin: 26px 0 8px; }}
  .tblwrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #23262d; white-space: nowrap; }}
  td:last-child, th:last-child {{ width: 100%; white-space: normal; }}
  th {{ color: #8b909a; font-weight: 500; font-size: 12px; }}
  .sev {{ color: #0d0e10; border-radius: 4px; padding: 1px 7px; font-size: 12px; font-weight: 600; }}
  .okc {{ color: #5a9e6f; }} .badc {{ color: #e5484d; font-weight: 600; }}
  .mono {{ font-family: ui-monospace, monospace; font-size: 13px; }}
  .dim {{ opacity: .45; }}
  .ackbtn {{ background: #2a2e35; color: #d7dae0; border: 1px solid #3a3f48; border-radius: 4px;
             padding: 1px 8px; font-size: 12px; cursor: pointer; }}
  .ackbtn:hover {{ border-color: #5a9e6f; }}
  .ackbtn.no:hover {{ border-color: #e5484d; }}
  .btns form {{ display: inline-block; margin-right: 5px; }}
  .flag {{ color: #e5484d; font-weight: 600; }}
  .flagrow td {{ background: rgba(229, 72, 77, .07); }}
  .card.warn .num {{ color: #e2a336; }}
</style></head><body>
<header><h1><span>●</span> vakt</h1><small>network watchtower · read-only · refreshes every 30 s</small></header>
<main>
  <div class="cards">{cards}</div>
  <h2>Protect devices</h2>
  <div class="tblwrap"><table><tr><th>Kind</th><th>Name</th><th>State</th><th>Changed</th></tr>{protect_rows}</table></div>
  <h2>Events</h2>
  <div class="tblwrap"><table><tr><th>When</th><th>Severity</th><th>Kind</th><th>Message</th><th></th></tr>{event_rows}</table></div>
  <h2>Known devices{f" — {sum(1 for d in devices if not d['status'])} unreviewed" if any(not d['status'] for d in devices) else ""}</h2>
  <div class="tblwrap"><table><tr><th>Network</th><th>IP</th><th>Name</th><th>Status</th><th>MAC</th><th>Link</th><th>Seen</th><th>First seen</th></tr>{device_rows}</table></div>
</main>
<script>
async function refreshMain() {{
  try {{
    const r = await fetch(location.pathname, {{cache: 'no-store'}});
    if (!r.ok) return;
    const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
    const cur = document.querySelector('main'), next = doc.querySelector('main');
    if (cur && next) cur.replaceWith(next);
  }} catch (e) {{}}
}}
document.addEventListener('submit', async (e) => {{
  const f = e.target;
  if (f.matches && f.matches('form[action^="/verdict/"], form[action^="/device/"]')) {{
    e.preventDefault();
    const b = f.querySelector('button');
    if (b) b.disabled = true;
    try {{ await fetch(f.action, {{method: 'POST'}}); }} catch (err) {{}}
    refreshMain();
  }}
}});
setInterval(refreshMain, 30000);
</script>
</body></html>"""
