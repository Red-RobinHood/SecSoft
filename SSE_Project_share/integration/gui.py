"""Local web GUI for the RAG -> PhishFuzzer -> gophish bridge."""
import argparse
import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from integration import config as config_mod
    from integration import htmlize, orchestrator, rag_adapter
    from integration.gophish_client import GophishClient, GophishError
else:
    from . import config as config_mod
    from . import htmlize, orchestrator, rag_adapter
    from .gophish_client import GophishClient, GophishError

CATEGORIES = ["credential_phishing", "fake_degree", "scholarship_grant_scam", "job_internship_scam"]

_CORPUS = None
_CORPUS_LOCK = threading.Lock()
_RUN_LOCK = threading.Lock()


def _get_corpus():
    global _CORPUS
    with _CORPUS_LOCK:
        if _CORPUS is None:
            _CORPUS = rag_adapter.load_corpus()
    return _CORPUS


def _client(cfg):
    return GophishClient(cfg.gophish_base_url, cfg.gophish_api_key,
                         cfg.gophish_verify_tls, cfg.cert_path)


def _overrides_from(data):
    n = data.get("n")
    return {
        "gophish_base_url": data.get("gophish_url") or None,
        "gen_model": data.get("gen_model") or None,
        "detector_model": data.get("det_model") or None,
        "detector_backend": data.get("det_backend") or None,
        "selection_policy": data.get("policy") or None,
        "n": int(n) if n not in (None, "", 0) else None,
        "inject_url": (False if data.get("no_inject_url") else None),
    }


def _serialize_report(report, cfg):
    cands = []
    for sc in report.scored:
        preview, warns = htmlize.htmlize(
            sc.candidate.body, inject_url=cfg.inject_url, inject_tracking=cfg.inject_tracking,
        )
        cands.append({
            "subject": sc.candidate.subject,
            "body": sc.candidate.body,
            "verdict": sc.score.verdict,
            "evaded": sc.score.evaded,
            "per_mode": sc.score.per_mode,
            "votes": dict(sc.score.votes),
            "template_name": sc.template_name,
            "pushed": bool(sc.pushed),
            "error": sc.error,
            "warnings": sc.warnings or warns,
            "red_flags": list(getattr(sc.candidate, "red_flags", []) or []),
            "html_preview": preview,
        })
    return {
        "scenario": report.scenario,
        "candidates": cands,
        "pushed": len(report.pushed),
        "errors": report.errors,
        "ok": report.ok,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "phishbridge-gui/1.0"

    def _send(self, code, payload, ctype="application/json"):
        if ctype == "application/json":
            body = json.dumps(payload).encode("utf-8")
        else:
            body = payload.encode("utf-8") if isinstance(payload, str) else payload
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "html" in ctype or "json" in ctype else ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML, "text/html")
        if path == "/favicon.ico":
            return self._send(204, b"", "application/octet-stream")
        if path == "/api/config":
            cfg = config_mod.load_config()
            return self._send(200, {
                "gophish_url": cfg.gophish_base_url,
                "key_set": bool(cfg.gophish_api_key),
                "n": cfg.n,
                "policy": cfg.selection_policy,
                "inject_url": cfg.inject_url,
                "gen_model": cfg.gen_model,
                "det_model": cfg.detector_model,
                "categories": CATEGORIES,
                "policies": list(config_mod.SELECTION_POLICIES),
                "difficulties": ["obvious", "moderate", "subtle"],
            })
        if path == "/api/ping":
            cfg = config_mod.load_config()
            try:
                _client(cfg).ping()
                return self._send(200, {"ok": True, "url": cfg.gophish_base_url,
                                        "key_set": bool(cfg.gophish_api_key)})
            except GophishError as e:
                return self._send(200, {"ok": False, "error": str(e),
                                        "key_set": bool(cfg.gophish_api_key)})
        if path == "/api/templates":
            cfg = config_mod.load_config()
            try:
                tpls = _client(cfg).list_templates()
            except GophishError as e:
                return self._send(200, {"ok": False, "error": str(e)})
            rows = [{"id": t.get("id"), "name": t.get("name"),
                     "subject": t.get("subject", "")} for t in tpls]
            return self._send(200, {"ok": True, "templates": rows})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/run":
            return self._send(404, {"error": "not found"})

        try:
            data = self._read_json()
        except ValueError:
            return self._send(400, {"error": "invalid JSON body"})

        scenario = (data.get("scenario") or "").strip()
        if not scenario:
            return self._send(400, {"error": "scenario is required"})

        if not _RUN_LOCK.acquire(blocking=False):
            return self._send(409, {"error": "a generation is already running; please wait for it to finish"})
        try:
            cfg = config_mod.load_config(cli_overrides=_overrides_from(data))
            push = bool(data.get("push"))
            if push and not cfg.gophish_api_key:
                return self._send(400, {"error": "cannot push: no gophish API key set "
                                        "(set GOPHISH_API_KEY or config.json)."})
            try:
                corpus = _get_corpus()
            except SystemExit as e:
                return self._send(200, {"ok": False, "errors": [str(e)], "candidates": [],
                                        "scenario": scenario})
            except Exception as e:
                return self._send(200, {"ok": False, "candidates": [], "scenario": scenario,
                                        "errors": [f"could not load generator corpus: {e}"]})

            report = orchestrator.run(
                cfg, scenario,
                category=(data.get("category") or None),
                risk=(data.get("risk") or None),
                difficulty=(data.get("difficulty") or "moderate"),
                recipient=(data.get("recipient") or "a student"),
                sender=(data.get("sender") or None),
                institution=(data.get("institution") or None),
                seed=(int(data["seed"]) if str(data.get("seed") or "").strip() else None),
                with_red_flags=bool(data.get("red_flags")),
                push=push,
                corpus=corpus,
            )
            return self._send(200, _serialize_report(report, cfg))
        except Exception as e:
            return self._send(200, {"ok": False, "candidates": [], "scenario": scenario,
                                    "errors": [f"{type(e).__name__}: {e}"]})
        finally:
            _RUN_LOCK.release()


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishBridge</title>
<style>
  :root{
    --bg:#f6f7f9; --panel:#fff; --ink:#1b1f24; --muted:#5b6672; --line:#e3e7ec;
    --accent:#2f6df6; --accent-ink:#fff; --ok:#17864a; --ok-bg:#e4f5ea;
    --bad:#c02626; --bad-bg:#fbe6e6; --warn:#8a5a00; --warn-bg:#fbf0d8; --gray-bg:#eceff3;
    --shadow:0 1px 3px rgba(20,30,50,.08),0 6px 20px rgba(20,30,50,.05);
  }
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
    --bg:#0f1318; --panel:#161c23; --ink:#e8edf3; --muted:#9aa6b2; --line:#263039;
    --accent:#4f86ff; --ok:#49c07d; --ok-bg:#12331f; --bad:#ff6b6b; --bad-bg:#3a1414;
    --warn:#e0b25a; --warn-bg:#3a2e12; --gray-bg:#1d242c;
    --shadow:0 1px 3px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.3);
  }}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  header{display:flex;align-items:center;gap:12px;padding:14px 20px;
    border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
  header h1{font-size:17px;margin:0;font-weight:650;letter-spacing:-.2px}
  header .sub{color:var(--muted);font-size:12.5px}
  .status{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:13px}
  .dot{width:9px;height:9px;border-radius:50%;background:#b9c0c9}
  .dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)}
  .wrap{display:grid;grid-template-columns:340px 1fr;gap:18px;max-width:1200px;margin:18px auto;padding:0 16px}
  @media(max-width:860px){.wrap{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
  .card.pad{padding:16px}
  label{display:block;font-size:12.5px;color:var(--muted);margin:10px 0 4px;font-weight:550}
  input,select,textarea,button{font:inherit;color:inherit}
  input,select,textarea{width:100%;background:var(--bg);border:1px solid var(--line);
    border-radius:8px;padding:8px 10px}
  textarea{min-height:76px;resize:vertical}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .btns{display:flex;gap:10px;margin-top:16px}
  button{cursor:pointer;border:1px solid var(--line);background:var(--panel);
    border-radius:8px;padding:9px 14px;font-weight:600}
  button.primary{background:var(--accent);color:var(--accent-ink);border-color:transparent}
  button.ghost{background:transparent}
  button:disabled{opacity:.55;cursor:not-allowed}
  .banner{font-size:12px;color:var(--muted);background:var(--gray-bg);border-radius:8px;
    padding:8px 10px;margin-bottom:12px}
  .badge{display:inline-block;font-size:11.5px;font-weight:700;padding:2px 8px;border-radius:999px;
    text-transform:uppercase;letter-spacing:.3px}
  .b-evaded{color:var(--bad);background:var(--bad-bg)}
  .b-caught{color:var(--ok);background:var(--ok-bg)}
  .b-unknown{color:var(--muted);background:var(--gray-bg)}
  .cand{border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px;background:var(--panel)}
  .cand h3{margin:0 0 6px;font-size:15px}
  .meta{font-size:12px;color:var(--muted);display:flex;flex-wrap:wrap;gap:6px 14px;margin:6px 0}
  .body{white-space:pre-wrap;background:var(--bg);border:1px solid var(--line);border-radius:8px;
    padding:10px;font-size:13px;margin-top:8px;max-height:230px;overflow:auto}
  .tag{font-size:11px;color:var(--muted);background:var(--gray-bg);border-radius:6px;padding:1px 7px}
  .pushed{color:var(--ok);font-weight:600}
  .warn{color:var(--warn);background:var(--warn-bg);border-radius:6px;padding:6px 8px;font-size:12px;margin-top:8px}
  .err{color:var(--bad);background:var(--bad-bg);border-radius:8px;padding:10px;font-size:13px;margin-bottom:10px}
  .muted{color:var(--muted)} .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  details>summary{cursor:pointer;color:var(--accent);font-size:12.5px;margin-top:8px;user-select:none}
  .tmpl{display:flex;gap:8px;align-items:baseline;padding:7px 0;border-bottom:1px solid var(--line);font-size:13px}
  .tmpl:last-child{border-bottom:0}
  .spin{display:inline-block;width:15px;height:15px;border:2px solid var(--line);
    border-top-color:var(--accent);border-radius:50%;animation:s .7s linear infinite;vertical-align:-3px}
  @keyframes s{to{transform:rotate(360deg)}}
  .section-title{font-size:13px;font-weight:650;margin:0 0 10px;display:flex;align-items:center;gap:8px}
  .section-title .count{font-weight:500;color:var(--muted)}
</style>
</head>
<body>
<header>
  <div>
    <h1>PhishBridge <span class="sub">· RAG → PhishFuzzer → gophish</span></h1>
  </div>
  <div class="status">
    <span class="dot" id="dot"></span><span id="statusText" class="muted">checking gophish…</span>
    <button class="ghost" id="pingBtn" style="padding:5px 10px">Recheck</button>
  </div>
</header>

<div class="wrap">
  <form class="card pad" id="form" autocomplete="off">
    <div class="banner">Authorized security-awareness training only. Generated content stays on the
      <span class="mono">training.invalid</span> dead domain until a consented campaign swaps in gophish’s
      <span class="mono">{{.URL}}</span>.</div>

    <label for="scenario">Scenario</label>
    <textarea id="scenario" placeholder="e.g. mailbox over quota, verify to keep access">mailbox over quota, verify to keep access</textarea>

    <div class="row">
      <div><label for="category">Category</label><select id="category"></select></div>
      <div><label for="difficulty">Difficulty</label><select id="difficulty"></select></div>
    </div>
    <div class="row">
      <div><label for="n">Candidates (n)</label><input id="n" type="number" min="1" max="10" value="2"></div>
      <div><label for="policy">Selection policy</label><select id="policy"></select></div>
    </div>
    <div class="row">
      <div><label for="institution">Institution</label><input id="institution" placeholder="(optional)"></div>
      <div><label for="sender">Sender persona</label><input id="sender" placeholder="(optional)"></div>
    </div>
    <div class="row">
      <div><label for="recipient">Recipient</label><input id="recipient" value="a student"></div>
      <div><label for="seed">Seed</label><input id="seed" type="number" placeholder="(optional)"></div>
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin-top:12px;color:var(--ink)">
      <input type="checkbox" id="red_flags" style="width:auto"> annotate red flags (extra model call)</label>
    <label style="display:flex;align-items:center;gap:8px;color:var(--ink)">
      <input type="checkbox" id="no_inject_url" style="width:auto"> keep training.invalid link (don’t inject {{.URL}})</label>

    <div class="btns">
      <button type="button" class="ghost" id="genBtn">Generate &amp; score</button>
      <button type="button" class="primary" id="pushBtn">Generate &amp; push</button>
    </div>
    <div id="formMsg" class="muted" style="font-size:12.5px;margin-top:10px"></div>
  </form>

  <div>
    <div class="card pad" style="margin-bottom:18px">
      <div class="section-title">Results <span class="count" id="resCount"></span></div>
      <div id="results"><div class="muted">Enter a scenario and choose <b>Generate &amp; score</b> (dry run)
        or <b>Generate &amp; push</b>. Scoring runs the detector model, so a run takes a little while.</div></div>
    </div>
    <div class="card pad">
      <div class="section-title">Templates in gophish <span class="count" id="tmplCount"></span>
        <button class="ghost" id="refreshTmpl" style="margin-left:auto;padding:4px 10px">Refresh</button></div>
      <div id="templates" class="muted">—</div>
    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => (s||"").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function opt(sel, items, cur, allowBlank){
  sel.innerHTML = (allowBlank ? '<option value="">(any)</option>' : '') +
    items.map(i => `<option${i===cur?' selected':''}>${i}</option>`).join('');
}

async function loadConfig(){
  const c = await (await fetch('/api/config')).json();
  opt($('category'), c.categories, '', true);
  opt($('difficulty'), c.difficulties, 'subtle', false);
  opt($('policy'), c.policies, c.policy, false);
  $('n').value = c.n;
}

async function ping(){
  $('statusText').textContent = 'checking gophish…';
  $('dot').className = 'dot';
  try{
    const r = await (await fetch('/api/ping')).json();
    if(r.ok){ $('dot').className='dot ok';
      $('statusText').innerHTML = 'gophish connected <span class="muted">· '+esc(r.url)+'</span>'; }
    else { $('dot').className='dot bad';
      $('statusText').innerHTML = esc(r.error || 'unreachable') + (r.key_set?'':' <span class="muted">(no API key)</span>'); }
  }catch(e){ $('dot').className='dot bad'; $('statusText').textContent='GUI error: '+e; }
}

function verdictBadge(v, evaded){
  if(v==='unknown') return '<span class="badge b-unknown">unknown</span>';
  const cls = evaded ? 'b-evaded' : 'b-caught';
  const label = esc(v) + ' · ' + (evaded ? 'evaded detector' : 'caught');
  return `<span class="badge ${cls}">${label}</span>`;
}

function candCard(c){
  const perMode = Object.entries(c.per_mode||{}).map(([k,v])=>`${esc(k)}=${esc(v)}`).join(', ');
  const flags = (c.red_flags&&c.red_flags.length)
    ? `<details><summary>red flags (${c.red_flags.length})</summary><div class="body">${esc(c.red_flags.join('\n'))}</div></details>` : '';
  const warns = (c.warnings&&c.warnings.length)
    ? c.warnings.map(w=>`<div class="warn">⚠ ${esc(w)}</div>`).join('') : '';
  const err = c.error ? `<div class="warn" style="color:var(--bad);background:var(--bad-bg)">push error: ${esc(c.error)}</div>` : '';
  const pushed = c.pushed
    ? `<div class="pushed" style="margin-top:8px">✓ pushed as <span class="mono">${esc(c.template_name)}</span></div>`
    : (c.template_name ? `<div class="meta">would be named <span class="mono">${esc(c.template_name)}</span></div>` : '');
  return `<div class="cand">
    <div style="display:flex;justify-content:space-between;gap:10px;align-items:start">
      <h3>${esc(c.subject)}</h3>${verdictBadge(c.verdict, c.evaded)}
    </div>
    <div class="meta"><span class="tag">per-mode: ${perMode||'—'}</span>
      <span class="tag">votes: ${esc(JSON.stringify(c.votes||{}))}</span></div>
    ${pushed}${err}${warns}${flags}
    <details><summary>email body</summary><div class="body">${esc(c.body)}</div></details>
    <details><summary>gophish HTML preview</summary><div class="body mono">${esc(c.html_preview)}</div></details>
  </div>`;
}

function renderResults(r){
  const el = $('results');
  let html = '';
  if(r.errors && r.errors.length) html += r.errors.map(e=>`<div class="err">${esc(e)}</div>`).join('');
  const cands = r.candidates||[];
  $('resCount').textContent = cands.length ? `· ${cands.length} candidate(s)` + (r.pushed?`, ${r.pushed} pushed`:'') : '';
  if(cands.length) html += cands.map(candCard).join('');
  else if(!r.errors || !r.errors.length) html += '<div class="muted">No candidates returned.</div>';
  el.innerHTML = html;
}

async function run(push){
  const payload = {
    scenario: $('scenario').value, category: $('category').value,
    difficulty: $('difficulty').value, n: $('n').value, policy: $('policy').value,
    institution: $('institution').value, sender: $('sender').value,
    recipient: $('recipient').value, seed: $('seed').value,
    red_flags: $('red_flags').checked, no_inject_url: $('no_inject_url').checked,
    push: push,
  };
  if(!payload.scenario.trim()){ $('formMsg').textContent='Enter a scenario first.'; return; }
  $('genBtn').disabled = $('pushBtn').disabled = true;
  $('formMsg').innerHTML = `<span class="spin"></span> ${push?'generating + scoring + pushing':'generating + scoring'}… (may take a few minutes)`;
  $('results').innerHTML = '<div class="muted"><span class="spin"></span> working…</div>';
  try{
    const res = await fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const r = await res.json();
    if(res.status===409){ $('formMsg').textContent = r.error; $('results').innerHTML=''; return; }
    renderResults(r);
    $('formMsg').textContent = r.ok===false ? 'Finished with errors.' : 'Done.';
    if(push) refreshTemplates();
  }catch(e){ $('formMsg').textContent = 'Request failed: '+e; $('results').innerHTML=''; }
  finally{ $('genBtn').disabled = $('pushBtn').disabled = false; }
}

async function refreshTemplates(){
  const el = $('templates');
  el.innerHTML = '<span class="spin"></span>';
  try{
    const r = await (await fetch('/api/templates')).json();
    if(!r.ok){ el.innerHTML = `<div class="err">${esc(r.error)}</div>`; $('tmplCount').textContent=''; return; }
    const t = r.templates||[];
    $('tmplCount').textContent = `· ${t.length}`;
    el.innerHTML = t.length ? t.map(x=>`<div class="tmpl"><span class="muted">#${x.id}</span>
      <span class="mono">${esc(x.name)}</span><span class="muted" style="margin-left:auto">${esc(x.subject)}</span></div>`).join('')
      : '<div class="muted">No templates in gophish yet.</div>';
  }catch(e){ el.innerHTML = 'error: '+e; }
}

$('genBtn').onclick = ()=>run(false);
$('pushBtn').onclick = ()=>run(true);
$('pingBtn').onclick = ping;
$('refreshTmpl').onclick = refreshTemplates;
loadConfig(); ping(); refreshTemplates();
</script>
</body>
</html>"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local web GUI for the gophish bridge.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")
    args = ap.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"PhishBridge GUI serving at {url}  (Ctrl-C to stop)")
    print("gophish API key is read from GOPHISH_API_KEY / config.json, not the browser.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
