// Cloudflare Worker: open/click/submit tracking for an authorized awareness exercise.
// Bindings (set in the Worker's Settings):
//   KV namespace binding: EVENTS
//   Variables:            LANDING_URL (the evaluator-hosted page), DASH_KEY (dashboard password)
//
// Endpoints:
//   GET  /p?id=TOKEN  -> log "open",  return a 1x1 gif
//   GET  /c?id=TOKEN  -> log "click", 302 redirect to LANDING_URL?id=TOKEN
//   POST /s           -> body {id, event} -> log "submit"
//   GET  /dash?key=   -> summary table (per token: open/click/submit) + raw log

const GIF = Uint8Array.from(
  atob("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"),
  (c) => c.charCodeAt(0)
);
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS" };

async function logEvent(env, type, id, req) {
  if (!id) return;
  const rec = {
    ts: new Date().toISOString(),
    type,
    id,
    ip: req.headers.get("cf-connecting-ip") || "",
    ua: req.headers.get("user-agent") || "",
  };
  const key = `${Date.now()}-${crypto.randomUUID()}`;
  await env.EVENTS.put(key, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 90 });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const id = url.searchParams.get("id") || "";

    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (url.pathname === "/p") {
      await logEvent(env, "open", id, req);
      return new Response(GIF, {
        headers: { "Content-Type": "image/gif", "Cache-Control": "no-store, max-age=0" },
      });
    }

    if (url.pathname === "/c") {
      await logEvent(env, "click", id, req);
      const dest = new URL(env.LANDING_URL);
      if (id) dest.searchParams.set("id", id);
      return Response.redirect(dest.toString(), 302);
    }

    if (url.pathname === "/s" && req.method === "POST") {
      let body = {};
      try { body = await req.json(); } catch (e) {
        try { body = JSON.parse(await req.text()); } catch (e2) {}
      }
      await logEvent(env, "submit", body.id || "", req);
      return new Response("ok", { headers: CORS });
    }

    if (url.pathname === "/dash") {
      if ((url.searchParams.get("key") || "") !== env.DASH_KEY) {
        return new Response("forbidden", { status: 403 });
      }
      const list = await env.EVENTS.list({ limit: 1000 });
      const events = [];
      for (const k of list.keys) {
        const v = await env.EVENTS.get(k.name);
        if (v) events.push(JSON.parse(v));
      }
      events.sort((a, b) => a.ts.localeCompare(b.ts));
      const per = {};
      for (const e of events) {
        per[e.id] = per[e.id] || { open: 0, click: 0, submit: 0 };
        per[e.id][e.type] = (per[e.id][e.type] || 0) + 1;
      }
      const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
      const sumRows = Object.keys(per).sort().map((id) =>
        `<tr><td>${esc(id)}</td><td>${per[id].open}</td><td>${per[id].click}</td><td>${per[id].submit}</td></tr>`
      ).join("");
      const rawRows = events.slice(-300).reverse().map((e) =>
        `<tr><td>${esc(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.id)}</td><td>${esc(e.ip)}</td></tr>`
      ).join("");
      const html =
        `<!doctype html><meta charset=utf-8><title>tracking</title>` +
        `<style>body{font:14px system-ui;margin:24px}table{border-collapse:collapse;margin:12px 0}` +
        `th,td{border:1px solid #ccc;padding:4px 10px;text-align:left}th{background:#f3f3f3}</style>` +
        `<h2>Per recipient</h2><table><tr><th>token</th><th>opens</th><th>clicks</th><th>submits</th></tr>${sumRows}</table>` +
        `<h2>Raw events (latest 300)</h2><table><tr><th>time</th><th>event</th><th>token</th><th>ip</th></tr>${rawRows}</table>`;
      return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    return new Response("not found", { status: 404 });
  },
};
