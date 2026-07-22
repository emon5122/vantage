"""
kb/viewer.py — build a self-contained static HTML viewer + search interface from
the KB (no external deps; data embedded as JSON; vanilla-JS filtering), and an
optional local http server. Read-only.
"""
import json
import os
import http.server
import socketserver


def snapshot(db, version=None, limit=5000):
    where = "WHERE version=?" if version else ""
    args = (version,) if version else ()
    commands = [dict(r) for r in db.q(f"SELECT * FROM commands {where} ORDER BY obs_count DESC LIMIT {limit}", args)]
    schemas = {}
    for c in commands:
        s = db.q1("SELECT id, samples, overall_confidence FROM schemas WHERE command_id=?", (c["id"],))
        if s:
            schemas[c["command_key"]] = {
                "samples": s["samples"], "confidence": s["overall_confidence"],
                "fields": [dict(r) for r in db.q(
                    "SELECT field,types,present_in,of_samples,optional,confidence FROM schema_fields WHERE schema_id=?", (s["id"],))],
            }
    classes = [dict(r) for r in db.q(f"SELECT assembly,namespace,name,role,confidence,tier FROM classes {where} "
                                     f"ORDER BY confidence DESC LIMIT {limit}", args)]
    actions = [dict(r) for r in db.q("SELECT label,version,packet_count,session_id FROM gameplay_actions")]
    stats = {
        "commands": db.q1("SELECT COUNT(*) n FROM commands")["n"],
        "packets": db.q1("SELECT COUNT(*) n, COALESCE(SUM(obs_count),0) o FROM packets")["n"],
        "packet_obs": db.q1("SELECT COALESCE(SUM(obs_count),0) o FROM packets")["o"],
        "classes": db.q1("SELECT COUNT(*) n FROM classes")["n"],
        "sessions": db.q1("SELECT COUNT(*) n FROM sessions")["n"],
        "versions": [r["version"] for r in db.q("SELECT version FROM versions ORDER BY version")],
    }
    return {"version": version or "all", "stats": stats, "commands": commands,
            "schemas": schemas, "classes": classes, "actions": actions}


HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>the target application Protocol KB</title>
<style>
:root{color-scheme:light dark}
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e7e9ee}
header{padding:14px 18px;background:#161a22;border-bottom:1px solid #2a2f3a;position:sticky;top:0}
h1{font-size:16px;margin:0 0 6px}
.stats{display:flex;gap:16px;flex-wrap:wrap;color:#9aa4b2;font-size:12px}
.stats b{color:#7fd1a3}
main{padding:16px 18px;max-width:1200px;margin:0 auto}
input,select{background:#0b0d12;color:#e7e9ee;border:1px solid #2a2f3a;border-radius:6px;padding:7px 9px;font-size:13px}
input{width:340px}
.tabs{display:flex;gap:6px;margin:14px 0}
.tab{padding:6px 12px;border:1px solid #2a2f3a;border-radius:6px;cursor:pointer;color:#9aa4b2}
.tab.on{background:#1d2430;color:#e7e9ee}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:10px}
th,td{border-bottom:1px solid #232833;padding:6px 8px;text-align:left;vertical-align:top}
th{color:#9aa4b2;position:sticky;top:96px;background:#0f1115}
code{background:#1a1f29;padding:1px 5px;border-radius:4px}
.grade-Verified,.g-verified{color:#7fd1a3}.grade-Likely,.g-observed{color:#e3c86b}.grade-Unknown{color:#c98a8a}
.muted{color:#6b7482}
tr:hover{background:#141922}
.panel{overflow-x:auto}
.pill{font-size:11px;border:1px solid #2a2f3a;border-radius:10px;padding:1px 7px;color:#9aa4b2}
</style></head><body>
<header>
<h1>the target application Protocol Knowledge Base <span class=pill id=ver></span></h1>
<div class=stats id=stats></div>
</header>
<main>
<input id=q placeholder="filter (command, class, field, category, role) …" oninput=render()>
<select id=cat onchange=render()><option value="">all categories</option></select>
<div class=tabs>
 <div class=tab data-t=commands onclick=tab('commands')>Commands</div>
 <div class=tab data-t=schemas onclick=tab('schemas')>Schemas</div>
 <div class=tab data-t=classes onclick=tab('classes')>Classes</div>
 <div class=tab data-t=actions onclick=tab('actions')>Actions</div>
</div>
<div class=panel id=out></div>
</main>
<script>
const DATA=__DATA__;let T='commands';
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function tab(t){T=t;document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('on',e.dataset.t===t));render()}
function init(){
 document.getElementById('ver').textContent='v '+DATA.version;
 const s=DATA.stats;
 document.getElementById('stats').innerHTML=
  `commands <b>${s.commands}</b>`+` · packets <b>${s.packets}</b>`+` · observations <b>${s.packet_obs}</b>`+
  ` · classes <b>${s.classes}</b>`+` · sessions <b>${s.sessions}</b>`+` · versions <b>${(s.versions||[]).join(', ')||'—'}</b>`;
 const cats=[...new Set(DATA.commands.map(c=>c.category).filter(Boolean))].sort();
 const sel=document.getElementById('cat');cats.forEach(c=>{const o=document.createElement('option');o.value=o.textContent=c;sel.appendChild(o)});
 document.querySelector('.tab[data-t=commands]').classList.add('on');render();
}
function render(){
 const q=document.getElementById('q').value.toLowerCase();
 const cat=document.getElementById('cat').value;
 const out=document.getElementById('out');let h='';
 if(T==='commands'){
  h='<table><tr><th>command</th><th>cmdid</th><th>category</th><th>dir</th><th>conf</th><th>obs</th><th>rtt_med</th><th>hb_s</th></tr>';
  DATA.commands.filter(c=>(!cat||c.category===cat)&&JSON.stringify(c).toLowerCase().includes(q)).forEach(c=>{
   h+=`<tr><td><code>${esc(c.command_key)}</code></td><td>${esc(c.request_cmd_id)}</td><td>${esc(c.category)}</td>`+
      `<td>${esc(c.direction)}</td><td class=grade-${esc(c.confidence_grade)}>${esc(c.confidence_grade)}</td>`+
      `<td>${c.obs_count}</td><td>${c.rtt_med_ms??''}</td><td>${c.heartbeat_s??''}</td></tr>`});
  h+='</table>';
 }else if(T==='schemas'){
  h='';Object.entries(DATA.schemas).filter(([k,v])=>(k+JSON.stringify(v)).toLowerCase().includes(q)).forEach(([k,v])=>{
   h+=`<h3><code>${esc(k)}</code> <span class=muted>${v.samples} samples · ${esc(v.confidence)}</span></h3>`;
   h+='<table><tr><th>field</th><th>types</th><th>present</th><th>optional</th><th>confidence</th></tr>';
   v.fields.forEach(f=>{h+=`<tr><td><code>${esc(f.field)}</code></td><td>${esc(Object.keys(JSON.parse(f.types||'{}')).join(','))}</td>`+
     `<td>${f.present_in}/${f.of_samples}</td><td>${f.optional?'yes':'no'}</td><td class=grade-${esc(f.confidence)}>${esc(f.confidence)}</td></tr>`});
   h+='</table>'});
  if(!h)h='<p class=muted>no schemas match</p>';
 }else if(T==='classes'){
  h='<table><tr><th>assembly</th><th>namespace</th><th>class</th><th>role</th><th>conf</th></tr>';
  DATA.classes.filter(c=>JSON.stringify(c).toLowerCase().includes(q)).slice(0,2000).forEach(c=>{
   h+=`<tr><td class=muted>${esc(c.assembly)}</td><td>${esc(c.namespace)}</td><td><code>${esc(c.name)}</code></td>`+
      `<td>${esc(c.role)}</td><td>${(c.confidence??'')}</td></tr>`});
  h+='</table>';
 }else{
  h='<table><tr><th>label</th><th>version</th><th>packets</th></tr>';
  DATA.actions.filter(a=>JSON.stringify(a).toLowerCase().includes(q)).forEach(a=>{
   h+=`<tr><td>${esc(a.label)}</td><td>${esc(a.version)}</td><td>${a.packet_count}</td></tr>`});
  h+='</table>';
 }
 out.innerHTML=h;
}
init();
</script></body></html>"""


def build(db, outdir, version=None):
    os.makedirs(outdir, exist_ok=True)
    data = snapshot(db, version)
    html = HTML.replace("__DATA__", json.dumps(data, ensure_ascii=False))
    path = os.path.join(outdir, "index.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join(outdir, "snapshot.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def serve(directory, port=8765):
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"[*] serving {directory} at http://127.0.0.1:{port} (Ctrl+C to stop)")
        httpd.serve_forever()
