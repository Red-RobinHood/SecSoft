"""Send a generated email to a recipient list via SMTP, with per-recipient open/click tracking.

Each recipient gets a token. The email's {{.URL}} becomes a tracked click link through the
Worker, {{.Tracker}} becomes an open-pixel, {{.FirstName}} is personalised. A tokens.csv is
written so Worker dashboard tokens can be mapped back to people.

Authorized security-awareness training only.

  export TRACK_SECRET=...        # same value used nowhere else; ties tokens to emails
  export SMTP_PASS=...           # Hostinger mailbox password
  python send.py --recipients recipients.csv --html email.html --subject "Action required" \
      --worker-base https://xxx.workers.dev --from "IT Helpdesk <you@yourdomain.com>" \
      --smtp-user you@yourdomain.com --dry-run
"""
import argparse
import csv
import hashlib
import hmac
import os
import smtplib
import sys
import time
from email.message import EmailMessage


def token_for(email, secret):
    return hmac.new(secret.encode(), email.strip().lower().encode(), hashlib.sha256).hexdigest()[:16]


def load_recipients(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            email = (r.get("email") or "").strip()
            if email:
                rows.append({"email": email, "first_name": (r.get("first_name") or "").strip()})
    return rows


def personalize(template, first_name, click_url, pixel_url):
    pixel = f'<img src="{pixel_url}" width="1" height="1" alt="" style="display:none">'
    return (template.replace("{{.URL}}", click_url)
                    .replace("{{.Tracker}}", pixel)
                    .replace("{{.FirstName}}", first_name or "there"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--recipients", required=True, help="CSV with columns: email, first_name")
    ap.add_argument("--html", required=True, help="email body HTML (with {{.URL}}/{{.Tracker}}/{{.FirstName}})")
    ap.add_argument("--subject", required=True)
    ap.add_argument("--worker-base", required=True, help="Worker base URL, e.g. https://xxx.workers.dev")
    ap.add_argument("--from", dest="sender", required=True, help='From header, e.g. "IT Helpdesk <you@domain>"')
    ap.add_argument("--smtp-host", default="smtp.hostinger.com")
    ap.add_argument("--smtp-port", type=int, default=465)
    ap.add_argument("--smtp-user", required=True)
    ap.add_argument("--rate", type=float, default=3.0, help="seconds between sends (stay under mailbox limits)")
    ap.add_argument("--tokens-out", default="tokens.csv", help="write token->recipient map here")
    ap.add_argument("--dry-run", action="store_true", help="print, do not send")
    args = ap.parse_args()

    secret = os.environ.get("TRACK_SECRET", "")
    if not secret:
        raise SystemExit("set TRACK_SECRET (used to derive per-recipient tokens)")
    base = args.worker_base.rstrip("/")
    with open(args.html, encoding="utf-8") as fh:
        template = fh.read()
    recipients = load_recipients(args.recipients)
    if not recipients:
        raise SystemExit("no recipients found")

    password = os.environ.get("SMTP_PASS", "")
    server = None
    if not args.dry_run:
        if not password:
            raise SystemExit("set SMTP_PASS (mailbox password)")
        server = smtplib.SMTP_SSL(args.smtp_host, args.smtp_port, timeout=60)
        server.login(args.smtp_user, password)

    tok_rows, sent, errors = [], 0, 0
    try:
        for r in recipients:
            token = token_for(r["email"], secret)
            tok_rows.append({"token": token, "email": r["email"], "first_name": r["first_name"]})
            click_url = f"{base}/c?id={token}"
            pixel_url = f"{base}/p?id={token}"
            html = personalize(template, r["first_name"], click_url, pixel_url)

            msg = EmailMessage()
            msg["From"] = args.sender
            msg["To"] = r["email"]
            msg["Subject"] = args.subject
            msg.set_content("This message requires an HTML-capable email client.")
            msg.add_alternative(html, subtype="html")

            if args.dry_run:
                print(f"[dry-run] {r['email']}  token={token}  click={click_url}")
            else:
                try:
                    server.send_message(msg)
                    sent += 1
                    print(f"sent {r['email']}  token={token}")
                    time.sleep(args.rate)
                except Exception as e:
                    errors += 1
                    print(f"ERROR {r['email']}: {e}")
    finally:
        if server:
            server.quit()

    with open(args.tokens_out, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["token", "email", "first_name"])
        w.writeheader()
        w.writerows(tok_rows)

    print(f"\n{'[dry-run] ' if args.dry_run else ''}{sent} sent, {errors} error(s); "
          f"token map -> {args.tokens_out}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
