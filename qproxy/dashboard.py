from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import secrets
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from .blocklist import RuleManager
from .stats import StatsStore
from .updater import BlocklistUpdater

LOG = logging.getLogger("qproxy")

DASHBOARD_HTML = r'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Qproxy V3.5 · Controle de anúncios</title>
<style>
:root{color-scheme:dark;--bg:#07101d;--panel:#101b2d;--line:#293951;--text:#e9f1ff;--muted:#aabbd6;--green:#39d98a;--red:#ff6577;--blue:#5b91ff}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 Segoe UI,system-ui,sans-serif;background:linear-gradient(135deg,#07101d,#0d1728);color:var(--text)}
main{max-width:1240px;margin:auto;padding:24px}.top{display:flex;gap:14px;justify-content:space-between;align-items:center;flex-wrap:wrap}
h1{font-size:27px;margin:0}h2{font-size:18px;margin:0 0 12px}p{margin:7px 0;color:var(--muted)}button,input,select{font:inherit}
button{cursor:pointer}.btn{padding:9px 12px;border-radius:8px;background:#182740;color:var(--text);border:1px solid var(--line)}
.btn.primary{background:#315ad5;border-color:#315ad5}.btn.danger{color:#ffb2bf}.btn:disabled{opacity:.5;cursor:not-allowed}
input,select{background:#0c1728;border:1px solid #364962;border-radius:8px;padding:9px;color:var(--text);min-width:0}
input{flex:1}.row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:17px;margin-bottom:15px}
.metric{font-size:28px;font-weight:750}.label,.muted{color:var(--muted)}.table-wrap{overflow:auto}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;border-bottom:1px solid #27344b;padding:9px 6px}
td:first-child{word-break:break-word}.ok{color:var(--green)}.bad{color:var(--red)}
#message{min-height:23px;font-weight:600}.secondary{font-size:12px} .pill{border-radius:40px;padding:3px 8px;background:#203151}
@media(max-width:850px){.grid,.two{grid-template-columns:1fr 1fr}}
@media(max-width:620px){.grid,.two{grid-template-columns:1fr}.top{align-items:flex-start}.row input{min-width:100%}}
</style></head>
<body><main>
<div class="top"><div><h1>Qproxy · Central de bloqueios</h1><p>Bloqueio por domínio, regras manuais e listas online atualizadas</p></div>
<div class="row"><button class="btn" id="pause" data-action="pause">Pausar bloqueio (10 min)</button><button class="btn primary" id="update" data-action="update">Atualizar listas agora</button></div></div>
<div class="grid">
<div class="panel"><div class="label">Requisições bloqueadas</div><div class="metric" id="blocked">0</div></div>
<div class="panel"><div class="label">Domínios nas listas</div><div class="metric" id="count">0</div></div>
<div class="panel"><div class="label">Bloqueados por você</div><div class="metric" id="manualCount">0</div></div>
<div class="panel"><div class="label">Tráfego retransmitido</div><div class="metric" id="bytes">0 B</div></div>
</div>
<div id="message" role="status" aria-live="polite"></div>
<div class="two">
<section class="panel"><h2>Bloquear um domínio</h2><p>Use somente o host, por exemplo <code>ads.exemplo.com</code>. O bloqueio vale para todos os sites que usam esse host.</p>
<form class="row" id="blockForm"><input id="blockDomain" placeholder="ads.exemplo.com" required autocomplete="off"><button class="btn primary" type="submit">Bloquear</button></form></section>
<section class="panel"><h2>Liberar um domínio</h2><p>Se imagens ou páginas deixarem de carregar, adicione o domínio aqui. A whitelist prevalece sobre as listas externas.</p>
<form class="row" id="allowForm"><input id="allowDomain" placeholder="imagens.exemplo.com" required autocomplete="off"><button class="btn" type="submit">Liberar</button></form></section>
</div>
<section class="panel"><h2>Consultar lista de bloqueios</h2><div class="row"><input id="search" placeholder="Buscar domínio na lista" autocomplete="off">
<select id="scope" aria-label="Tipo de lista"><option value="all">Todas as listas</option><option value="manual">Bloqueados por mim</option></select><button class="btn" data-action="search">Buscar</button></div>
<p id="resultSummary"></p><div class="table-wrap"><table><thead><tr><th>Domínio</th><th>Origem</th><th>Tipo</th><th>Ação</th></tr></thead><tbody id="rulesTable"></tbody></table></div>
<div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" data-action="prev">Anterior</button><span id="pageLabel"></span><button class="btn" data-action="next">Próxima</button></div></section>
<div class="two">
<section class="panel"><h2>Atividade recente</h2><p>Uma conexão permitida não significa necessariamente propaganda. Confira o host antes de bloquear.</p>
<div class="table-wrap"><table><thead><tr><th>Estado</th><th>Domínio</th><th>Ação</th></tr></thead><tbody id="recent"></tbody></table></div></section>
<section class="panel"><h2>Fontes e atualizações</h2><p>As listas são verificadas automaticamente a cada 6 horas enquanto o programa está aberto. Se uma atualização falhar, o cache anterior é preservado.</p>
<div id="sources"></div><hr style="border:0;border-top:1px solid #293951;margin:16px 0"><h2>Domínios liberados por você</h2><div id="whitelist"></div></section>
</div><p class="secondary">Importante: o proxy enxerga domínios, não o conteúdo de HTTPS. Anúncios dentro do vídeo do YouTube dependem do complemento instalado e ativo no navegador. Bloquear <code>googlevideo.com</code> quebraria vídeos; por isso é protegido.</p>
</main><script>
const TOKEN=__TOKEN__;
const headers={'Content-Type':'application/json','X-Qproxy-Admin':TOKEN};
const el=id=>document.getElementById(id);
let page=1,total=0,limit=40,paused=false,refreshing=false;
function esc(value){return String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function setMessage(value,error=false){el('message').textContent=value;el('message').className=error?'bad':'ok'}
function humanBytes(n){let i=0;const u=['B','KB','MB','GB'];while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]}
async function api(url,options={}){const response=await fetch(url,options);const data=await response.json();if(!response.ok)throw Error(data.error||response.statusText);return data}
async function post(url,data){return api(url,{method:'POST',headers,body:JSON.stringify(data||{})})}
function actionButton(action,host,text){return '<button class="btn" data-action="'+esc(action)+'" data-domain="'+esc(host)+'">'+esc(text)+'</button>'}
function renderRecent(recent){
 el('recent').innerHTML=(recent||[]).slice(0,35).map(x=>{
 const blocked=x.action==='blocked';
 return '<tr><td class="'+(blocked?'bad':'ok')+'">'+(blocked?'Bloqueado':'Permitido')+'</td><td>'+esc(x.host)+'</td><td>'+actionButton(blocked?'allow':'block',x.host,blocked?'Liberar':'Bloquear')+'</td></tr>'
 }).join('')||'<tr><td colspan="3">Nenhuma conexão registrada</td></tr>';
}
async function refreshStatus(){
 if(refreshing)return;refreshing=true;
 try{
 const d=await api('/api/status');paused=!!d.rules.blocking_paused;
 el('pause').textContent=paused?'Retomar bloqueio ('+(d.rules.pause_remaining_seconds||0)+'s)':'Pausar bloqueio (10 min)';
 el('blocked').textContent=d.stats.blocked_requests;el('count').textContent=d.rules.blocked_domains||0;
 el('manualCount').textContent=d.rules.manual_domains||0;el('bytes').textContent=humanBytes(d.stats.bytes_relayed||0);
 renderRecent(d.stats.recent);
 const sources=d.updates||[];
 el('sources').innerHTML=sources.map(x=>'<p><b>'+esc(x.name)+'</b> · <span class="'+(x.ok?'ok':'bad')+'">'+(x.ok?'OK':x.cached?'Cache em uso':'Falha')+'</span> · '+(x.updated_at?esc(new Date(x.updated_at).toLocaleString('pt-BR')):'Aguardando download')+(x.rules?' · '+x.rules+' regras':'')+(x.error?'<span class="secondary"> · '+esc(x.error)+'</span>':'')+'</p>').join('')||'Nenhuma fonte configurada';
 el('whitelist').innerHTML=(d.rules.whitelist||[]).map(host=>'<p>'+esc(host)+' '+actionButton('unallow',host,'Remover liberação')+'</p>').join('')||'<p>Nenhuma liberação manual.</p>';
 }catch(e){setMessage('Falha ao consultar estado: '+e.message,true)}finally{refreshing=false}
}
async function refreshRules(){
 const q=new URLSearchParams({search:el('search').value.trim(),scope:el('scope').value,page:String(page),limit:String(limit)});
 try{
 const d=await api('/api/rules?'+q.toString());total=d.total;
 el('resultSummary').textContent=d.total+' domínio(s) encontrado(s)';
 el('pageLabel').textContent='Página '+page+' / '+Math.max(1,Math.ceil(total/limit));
 el('rulesTable').innerHTML=d.items.map(x=>'<tr><td>'+esc(x.domain)+(x.whitelisted?' <span class="pill">liberado</span>':'')+'</td><td>'+esc(x.source)+'</td><td>'+esc(x.category)+'</td><td>'+(x.manual?actionButton('unblock',x.domain,'Remover meu bloqueio'):actionButton('allow',x.domain,'Liberar'))+'</td></tr>').join('')||'<tr><td colspan="4">Nenhuma regra encontrada</td></tr>';
 }catch(e){setMessage('Erro ao consultar lista: '+e.message,true)}
}
async function perform(action,domain){
 try{
 if(action==='block'){await post('/api/blocklist',{domain});setMessage(domain+' bloqueado por você')}
 else if(action==='unblock'){await post('/api/blocklist/remove',{domain});setMessage('Bloqueio manual removido: '+domain+'. Se uma lista externa também bloquear esse host, use Liberar.')}
 else if(action==='allow'){await post('/api/whitelist',{domain});setMessage('Domínio liberado: '+domain)}
 else if(action==='unallow'){await post('/api/whitelist/remove',{domain});setMessage('Liberação removida: '+domain)}
 else if(action==='pause'){await post(paused?'/api/resume':'/api/pause');setMessage(paused?'Bloqueio retomado':'Bloqueio pausado por 10 minutos')}
 else if(action==='update'){el('update').disabled=true;setMessage('Atualizando listas externas...');await post('/api/update-lists');setMessage('Verificação concluída. Confira o estado de cada fonte.')}
 else if(action==='search'){page=1}
 else if(action==='prev'){page=Math.max(1,page-1)}
 else if(action==='next'){if(page*limit<total)page+=1}
 await refreshStatus();await refreshRules();
 }catch(e){setMessage(e.message,true)}finally{el('update').disabled=false}
}
document.addEventListener('click',event=>{
 const button=event.target.closest('button[data-action]');if(!button)return;
 perform(button.dataset.action,button.dataset.domain||'');
});
el('blockForm').addEventListener('submit',event=>{event.preventDefault();const domain=el('blockDomain').value.trim();perform('block',domain);el('blockDomain').value=''});
el('allowForm').addEventListener('submit',event=>{event.preventDefault();const domain=el('allowDomain').value.trim();perform('allow',domain);el('allowDomain').value=''});
el('scope').addEventListener('change',()=>{page=1;refreshRules()});
el('search').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();page=1;refreshRules()}});
refreshStatus();refreshRules();setInterval(refreshStatus,5000);
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
            server_version = "QproxyDashboard/0.3.5"

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
                size = int(self.headers.get("Content-Length", "0") or 0)
                if size < 0 or size > 4096:
                    raise ValueError("Conteúdo inválido ou grande demais")
                raw = self.rfile.read(size) if size else b"{}"
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("Esperado um objeto JSON")
                return data

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
                if path == "/api/rules":
                    try:
                        params = parse_qs(urlsplit(self.path).query)
                        q = params.get("search", [""])[0]
                        scope = params.get("scope", ["all"])[0]
                        page = int(params.get("page", ["1"])[0])
                        limit = int(params.get("limit", ["40"])[0])
                        self._json(200, dashboard.rules.list_rules(q, scope, page, limit))
                    except (ValueError, TypeError) as exc:
                        self._json(400, {"error": str(exc)})
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
                    if path == "/api/blocklist":
                        domain = dashboard.rules.add_to_blocklist(str(self._body_json().get("domain", "")))
                        self._json(200, {"ok": True, "domain": domain})
                        return
                    if path == "/api/blocklist/remove":
                        domain = dashboard.rules.remove_from_blocklist(str(self._body_json().get("domain", "")))
                        self._json(200, {"ok": True, "domain": domain})
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
                except Exception:
                    LOG.exception("Erro no dashboard")
                    self._json(500, {"error": "Falha interna ao executar ação"})
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
