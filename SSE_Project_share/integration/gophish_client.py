"""Minimal gophish admin REST API client (stdlib only)."""
import json
import ssl
import urllib.error
import urllib.request


class GophishError(RuntimeError):
    pass


class GophishClient:
    def __init__(self, base_url="https://127.0.0.1:3333", api_key="",
                 verify_tls=False, cert_path="", timeout=30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        if verify_tls:
            self._ctx = ssl.create_default_context(cafile=cert_path or None)
        else:
            self._ctx = ssl._create_unverified_context()

    def _req(self, method, path, body=None):
        if not self.api_key:
            raise GophishError(
                "no gophish API key set. Copy it from the gophish admin UI "
                "(Settings page) and set GOPHISH_API_KEY or config.json."
            )
        url = f"{self.base_url}/api{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            if e.code in (401, 403):
                raise GophishError(
                    f"gophish rejected the API key (HTTP {e.code}). Check the key "
                    f"on the Settings page. Detail: {detail}"
                )
            raise GophishError(f"gophish {method} {path} -> HTTP {e.code}: {detail}")
        except urllib.error.URLError as e:
            raise GophishError(
                f"cannot reach gophish at {self.base_url} ({e.reason}). "
                f"Is ./gophish running and is the admin URL correct?"
            )

    def ping(self):
        self._req("GET", "/templates/")
        return True

    def list_templates(self):
        return self._req("GET", "/templates/")

    def create_template(self, name, subject, html, text, envelope_sender=""):
        body = {
            "name": name,
            "subject": subject,
            "text": text,
            "html": html,
            "envelope_sender": envelope_sender,
            "attachments": [],
        }
        return self._req("POST", "/templates/", body)
