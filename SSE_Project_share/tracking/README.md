# tracking — opens/clicks without gophish

Replaces gophish's tracking for the case where the landing page is a **static HTML file
hosted by someone else** and you have **no server and no access logs** of your own.

```
email (open pixel + click link) ──► your Cloudflare Worker (free) ──► logs ──► /dash
                                          │ click: 302 redirect
                                          ▼
                              evaluator-hosted login.html
```

The Worker is a free serverless endpoint you own. The evaluator only hosts one HTML file.
Authorized security-awareness training only — no passwords/OTPs are collected.

## Files

| File | Who uses it | Role |
|---|---|---|
| `login.html` | **send to the evaluator to host** | the landing page (IITH DISHA portal) |
| `worker.js` | you (Cloudflare) | logs opens/clicks/submits, redirects clicks, serves the dashboard |
| `send.py` | you (your laptop) | personalises + sends the email via Hostinger SMTP, writes `tokens.csv` |
| `recipients.example.csv` | you | template: `email,first_name` |

## 1. Deploy the Worker (free, ~10 min)

1. Cloudflare dashboard → **Workers & Pages → Create → Worker**. Paste `worker.js`, deploy.
   Note its URL, e.g. `https://phish-track.<you>.workers.dev`.
2. **Storage → KV → Create namespace** (e.g. `EVENTS`). In the Worker → **Settings → Bindings**,
   add a **KV namespace** binding named `EVENTS` → that namespace.
3. In the Worker → **Settings → Variables**, add:
   - `LANDING_URL` = the evaluator's page URL, e.g. `https://evaluator-site/login.html`
   - `DASH_KEY` = any secret string (for the dashboard).
4. Re-deploy.

## 2. Give the evaluator the page

Send the evaluator **`login.html`** and ask them to host it at the URL you put in `LANDING_URL`.
That is all they do.
(Optional: to also track who *submits* the form, edit `login.html` and set
`var TRACK = "https://phish-track.<you>.workers.dev";` before sending it. Submission logs the
token only — never the typed value.)

## 3. Build the email body

Use the generator/GUI output, or any HTML, containing these placeholders:
- `{{.URL}}` — becomes the tracked click link
- `{{.Tracker}}` — becomes the open pixel
- `{{.FirstName}}` — recipient's name

## 4. Send

```bash
export TRACK_SECRET='pick-a-long-random-string'   # derives tokens; keep it stable
export SMTP_PASS='your-hostinger-mailbox-password'

# preview first — no mail sent:
python send.py --recipients recipients.csv --html email.html \
    --subject "Action required: verify your account" \
    --worker-base https://phish-track.<you>.workers.dev \
    --from "IT Helpdesk <you@yourdomain.com>" \
    --smtp-user you@yourdomain.com --dry-run

# then drop --dry-run to send.
```

`--smtp-host`/`--smtp-port` default to `smtp.hostinger.com:465` (SSL). `--rate` spaces sends
out (default 3s) to stay under mailbox limits. `tokens.csv` maps each token back to a person.

## 5. Read results

- Live: `https://phish-track.<you>.workers.dev/dash?key=YOUR_DASH_KEY`
- It lists opens/clicks/submits per **token**; join with `tokens.csv` for names.

## Notes / limits

- **Clicks are the reliable signal.** Opens are soft: Gmail proxies the pixel and Apple Mail
  pre-loads it, so expect some false/empty opens.
- Send a test to yourself first; confirm the click redirects to the page and `/dash` shows it.
- Authorization + recipient scoping must be in place before sending to real inboxes.
