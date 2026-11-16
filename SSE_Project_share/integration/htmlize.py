"""Convert a plain-text email body to gophish-ready HTML."""
import html
import re

DEAD_DOMAIN = "training.invalid"
URL_RX = re.compile(r"https?://[^\s\"'<>)\]]+|www\.[^\s\"'<>)\]]+", re.I)
DEAD_URL_RX = re.compile(r"https?://[^\s\"'<>)\]]*" + re.escape(DEAD_DOMAIN) + r"[^\s\"'<>)\]]*", re.I)
NAME_PLACEHOLDER_RX = re.compile(r"\[(?:student\s+name|name|student|recipient)\]", re.I)

TRACKER_PIXEL = "{{.Tracker}}"
DEFAULT_CTA = 'If the link above does not work, verify here: <a href="{{.URL}}">{{.URL}}</a>.'


def _escape_keep_vars(text):
    """HTML-escape text but keep gophish {{.Var}} placeholders intact."""
    placeholders = {}
    def stash(m):
        key = f"\x00{len(placeholders)}\x00"
        placeholders[key] = m.group(0)
        return key
    protected = re.sub(r"\{\{\.[A-Za-z0-9_]+\}\}", stash, text)
    escaped = html.escape(protected)
    for key, val in placeholders.items():
        escaped = escaped.replace(key, val)
    return escaped


def htmlize(body, *, inject_url=True, inject_tracking=True, first_name=True,
            cta_if_no_url=DEFAULT_CTA):
    """Return (html_string, warnings_list) for a plain-text body."""
    warnings = []
    text = body

    if first_name:
        text = NAME_PLACEHOLDER_RX.sub("{{.FirstName}}", text)

    had_dead_url = bool(DEAD_URL_RX.search(text))
    if inject_url:
        text = DEAD_URL_RX.sub("{{.URL}}", text)

    text = _escape_keep_vars(text)

    paras = re.split(r"\n\s*\n", text.strip())
    html_paras = []
    for p in paras:
        p = p.strip()
        if not p:
            continue
        html_paras.append("<p>" + p.replace("\n", "<br>\n") + "</p>")
    content = "\n".join(html_paras)

    if inject_url and not had_dead_url:
        warnings.append(
            "body contained no training.invalid link; appended a {{.URL}} CTA so "
            "the template stays trackable"
        )
        if cta_if_no_url:
            content += f"\n<p>{cta_if_no_url}</p>"

    if inject_tracking:
        content += f"\n{TRACKER_PIXEL}"

    doc = (
        "<html>\n<head><meta charset=\"utf-8\"></head>\n<body>\n"
        f"{content}\n</body>\n</html>"
    )
    return doc, warnings
