from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import secrets
from threading import Thread
from urllib.parse import urlsplit

from .blocklist import RuleManager
from .stats import StatsStore
from .updater import BlocklistUpdater

LOG = logging.getLogger("qproxy")

DASHBOARD_HTML = r'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Qproxy V3.3</title><style>
:root{color-scheme:dark;--bg:#07101d;--panel:#101b2d;--line:#23344f;--text:#e9f1ff;--muted:#93a6c6;--green:#39d98a;--red:#ff6577;--blue:#5b91ff}*{box-sizing:border-box}body{margin:0;font:14px/1.45 Inter,Segoe UI,system-ui;background:linear-gradient(135deg,#07101d,#0d1728);color:var(--text)}main{max-width:1280px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center}.brand h1{margin:0;font-size:28px}.brand p{margin:4px 0;color:var(--muted)}button,input{font:inherit}.btn{background:#16243b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 12px;cursor:pointer}.btn.primary{background:var(--blue);border-color:var(--blue)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}.card{background:rgba(16,27,45,.94);border:1px solid var(--line);border-radius:14px;padding:16px}.metric{font-size:30px;font-weight:800}.label,.muted,.status{color:var(--muted)}.row{display:flex;gap:9px;align-items:center}.between{justify-content:space-between}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:9px;border-bottom:1px solid var(--line);text-align:left}.blocked{color:var(--red)}.allowed{color:var(--green)}.tag{font-size:11px;padding:3px 7px;border-radius:999px;background:#172844}.whitelist{display:flex;gap:8px;margin:10px 0 14px}.whitelist input{flex:1;background:#0c1626;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px}@media(max-width:850px){.grid,.two{grid-template-columns:1fr 1fr}}@media(max-width:560px){.grid,.two{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main><div class="top"><div class="brand"><h1>Qproxy V3.3</h1><p>Proxy local • anúncios e trackers por domínio • sem MITM</p></div><div class="row"><button class="btn" id="pauseButton" onclick="togglePause()">Pausar bloqueio (10 min)</button><button class="btn primary" onclick="updateLists()">Atualizar listas agora</button></div></div>
<div class="grid"><div class="card"><div class="label">Bloqueios</div><div class="metric" id="blocked">0</div></div><div class="card"><div class="label">Anúncios</div><div class="metric" id="ads">0</div></div><div class="card"><div class="label">Trackers</div><div class="metric" id="trackers">0</div></div><div class="card"><div class="label">Tráfego retransmitido</div><div class="metric" id="bytes">0 B</div></div></div>
<div class="two"><section class="card"><div class="between row"><h3>Mais bloqueados</h3><span class="tag" id="rules">0 regras</span></div><table class="table"><thead><tr><th>Domínio</th><th>Bloqueios</th></tr></thead><tbody id="top"></tbody></table></section><section class="card"><h3>Whitelist</h3><div class="whitelist"><input id="domain" placeholder="exemplo.com"><button class="btn" onclick="addWhitelist()">Liberar</button></div><div id="whitelist" class="muted"></div><div id="updateStatus" class="status"></div></section></div>
<p class="muted">Imagem ou site com problema? Pause o bloqueio por 10 minutos para comparar. Se o problema desaparecer, veja o domínio na atividade recente e use <b>liberar</b>. Para anúncios dentro do YouTube, a extensão do navegador precisa estar instalada e ativa.</p>
<section class="card" style="margin-top:14px"><h3>Atividade recente</h3><table class="table"><thead><tr><th>Ação</th><th>Host</th><th>Protocolo</th><th>Tipo</th><th></th></tr></thead><tbody id="recent"></tbody></table></section>
</main><script>
const TOKEN=__TOKEN__;const headers={'Content-Type':'application/json','X-Qproxy-Admin':TOKEN};
let blockingPaused=false;
function humanBytes(n){const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
function esc(v){return String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]))}
async function api(url,opts={}){const r=await fetch(url,opts);if(!r.ok)throw new Error(await r.text());return r.json()}
async function refresh(){try{const d=await api('/api/status');const s=d.stats;blockingPaused=!!d.rules.blocking_paused;pauseButton.textContent=blockingPaused?'Retomar bloqueio ('+(d.rules.pause_remaining_seconds||0)+'s)':'Pausar bloqueio (10 min)';blocked.textContent=s.blocked_requests;ads.textContent=s.blocked_ads;trackers.textContent=s.blocked_trackers;bytes.textContent=humanBytes(s.bytes_relayed);rules.textContent=`${d.rules.blocked_domains||0} domínios`;top.innerHTML=s.top_blocked.map(([h,n])=>`<tr><td>${esc(h)}</td><td>${n}</td></tr>`).join('')||'<tr><td colspan=2 class=muted>Nenhum bloqueio ainda.</td></tr>';whitelist.innerHTML=(d.rules.whitelist||[]).map(h=>`<span class=tag>${esc(h)}</span>`).join(' ')||'Nenhum domínio liberado manualmente.';recent.innerHTML=s.recent.slice(0,30).map(e=>`<tr><td class=${e.action==='blocked'?'blocked':'allowed'}>${esc(e.action)}</td><td>${esc(e.host)}</td><td>${esc(e.protocol)}</td><td>${esc(e.category||'-')}</td><td>${e.action==='blocked'?`<button class=btn data-host="${encodeURIComponent(e.host)}" onclick="allowHost(decodeURIComponent(this.dataset.host))">liberar</button>`:''}</td></tr>`).join('');updateStatus.textContent=(d.updates||[]).map(x=>`${x.name}: ${x.ok?'OK':'falhou'}`).join(' • ')}catch(e){updateStatus.textContent='Erro: '+e.message}}
async function togglePause(){try{await api(blockingPaused?'/api/resume':'/api/pause',{method:'POST',headers,body:'{}'});await refresh()}catch(e){updateStatus.textContent='Erro: '+e.message}}
async function allowHost(host){await api('/api/whitelist',{method:'POST',headers,body:JSON.stringify({domain:host})});refresh()}
async function addWhitelist(){const host=domain.value.trim();if(!host)return;await allowHost(host);domain.value=''}
async function updateLists(){updateStatus.textContent='Atualizando listas...';try{await api('/api/update-lists',{method:'POST',headers,body:'{}'});await refresh()}catch(e){updateStatus.textContent='Falha: '+e.message}}
refresh();setInterval(refresh,2500);
</script></body></html>'''


class DashboardServer:
    def __init__(self, host: str, port: int, stats: StatsStore, rules: RuleManager, updater: BlocklistUpdater, token: str | None = None) -> None:
        self.host = host
        self.port = port
        self.stats = stats
        self.rules = rules
        self.updater = updater
        self.token = token or secrets.token_urlsafe(24)
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: Thread | None = None

    def start(self) -> None:
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "QproxyDashboard/0.2"

            def log_message(self, fmt, *args):
                LOG.debug("dashboard " + fmt, *args)

            def _json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                return secrets.compare_digest(self.headers.get("X-Qproxy-Admin", ""), dashboard.token)

            def _body_json(self) -> dict:
                length = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
                raw = self.rfile.read(length) if length else b"{}"
                return json.loads(raw.decode("utf-8"))

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == "/":
                    body = DASHBOARD_HTML.replace("__TOKEN__", json.dumps(dashboard.token)).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == "/api/status":
                    self._json(200, {"stats": dashboard.stats.snapshot(), "rules": dashboard.rules.snapshot(), "updates": dashboard.updater.status()})
                    return
                self._json(404, {"error": "not_found"})

            def do_POST(self):
                path = urlsplit(self.path).path
                if not self._authorized():
                    self._json(403, {"error": "forbidden"})
                    return
                try:
                    if path == "/api/pause":
                        dashboard.rules.pause_for(600)
                        self._json(200, {"ok": True, "rules": dashboard.rules.snapshot()})
                        return
                    if path == "/api/resume":
                        dashboard.rules.resume()
                        self._json(200, {"ok": True, "rules": dashboard.rules.snapshot()})
                        return
                    if path == "/api/whitelist":
                        domain = dashboard.rules.add_to_whitelist(str(self._body_json().get("domain", "")))
                        self._json(200, {"ok": True, "domain": domain})
                        return
                    if path == "/api/whitelist/remove":
                        domain = dashboard.rules.remove_from_whitelist(str(self._body_json().get("domain", "")))
                        self._json(200, {"ok": True, "domain": domain})
                        return
                    if path == "/api/update-lists":
                        dashboard.updater.refresh()
                        dashboard.rules.reload()
                        self._json(200, {"ok": True, "updates": dashboard.updater.status(), "rules": dashboard.rules.snapshot()})
                        return
                except (ValueError, json.JSONDecodeError) as exc:
                    self._json(400, {"error": str(exc)})
                    return
                except Exception as exc:
                    LOG.exception("Erro no dashboard")
                    self._json(500, {"error": str(exc)})
                    return
                self._json(404, {"error": "not_found"})

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = Thread(target=self.httpd.serve_forever, name="qproxy-dashboard", daemon=True)
        self.thread.start()
        LOG.info("Dashboard em http://%s:%s", self.host, self.port)

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=2)
