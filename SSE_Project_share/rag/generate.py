"""Generate simulated academic risky emails from a scenario via retrieval-augmented generation."""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "dataset", "academic_risky_emails.csv")
INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.npz")
OUT_DIR = os.path.join(ROOT, "simulated_outputs")

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5:7b-instruct"
EMBED_MODEL = "all-MiniLM-L6-v2"
DEAD_DOMAIN = "training.invalid"
DEAD_LINK = f"https://portal.{DEAD_DOMAIN}/verify"
CATEGORIES = ["credential_phishing", "fake_degree", "scholarship_grant_scam", "job_internship_scam"]

EXAMPLE_CHARS = 900
NEAR_DUP_SIM = 0.9     
MIN_BODY_WORDS = 25
MAX_ATTEMPTS = 3

URL_RX = re.compile(r"https?://[^\s\"'<>)\]]+|www\.[^\s\"'<>)\]]+", re.I)
EMAIL_RX = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
BRACKET_DOMAIN_RX = re.compile(r"@\[[^\]]+\](?:\.[A-Za-z.]+)?")
HEADER_LINE_RX = re.compile(r"^\s*(?:from|sent|to|cc|bcc|date|reply-to)\s*:.*$", re.I | re.M)
RULE_LINE_RX = re.compile(r"^\s*[_\-=*]{5,}\s*$", re.M)
DISCLAIMER_RX = re.compile(
    r"simulat|training (?:purposes?|exercise|email)|security training|awareness (?:training|exercise)|"
    r"phishing (?:test|exercise|awareness)|this is a test|suspicious links?|do not click",
    re.I,
)
INSTITUTION_PLACEHOLDER_RX = re.compile(r"\[(?:the )?(?:university|college|institution|institute)(?: name)?\]", re.I)

DIFFICULTY = {
    "obvious": "Make it easy to spot: generic greeting, heavy urgency, a threat of losing something that fits "
               "the scenario (access, the offer, the money, a deadline), "
               "clumsy or slightly off wording.",
    "moderate": "Make it plausible: addressed to the recipient's role, professional tone, a clear "
                "deadline, and two or three cues a careful reader could notice.",
    "subtle": "Make it polished and routine-looking: professional tone, a believable administrative "
              "pretext, mild urgency, and only one or two small cues a careful reader could notice.",
}

SYSTEM_PROMPT = f"""You write realistic SIMULATED phishing and scam emails for a university's \
security-awareness programme. They are used in consented training exercises and as labelled \
training data for a detection model. They are never sent as real attacks.

Rules:
- Take structure, tone and social-engineering hooks from the reference emails, but write a NEW \
message for the scenario. Never copy a reference email.
- Any link must be exactly {DEAD_LINK}
- Use bracketed placeholders for people and organisations ([Student Name], [University Name]). \
Never use a real person, brand, or address. Email addresses must end in @{DEAD_DOMAIN}.
- No attachments, scripts, or working code.
- Do NOT mention that the email is a simulation, a test, or training. Write it as the sender would.
- Do NOT include From/To/Sent/Date header lines, forwarded text, or a reply chain.
- Output exactly: a first line "Subject: <subject>", a blank line, then the body. Nothing else."""


def scrub(text):
    text = HEADER_LINE_RX.sub("", text)
    text = URL_RX.sub("<LINK>", text)
    text = EMAIL_RX.sub("<EMAIL>", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def usable_mask(df):
    def ok(body):
        n = len(body)
        if not 200 <= n <= 3000:
            return False
        ascii_ratio = sum(c.isascii() for c in body) / n
        alpha_ratio = sum(c.isalpha() for c in body) / n
        return ascii_ratio > 0.95 and alpha_ratio > 0.6
    return df["body"].map(ok).to_numpy()


def retrieve(df, emb, qvec, k, usable, category=None, risk=None):
    mask = usable.copy()
    for col, val in (("category", category), ("risk_level", risk)):
        if val:
            m = mask & (df[col] == val).to_numpy()
            if m.sum() >= 1:
                mask = m
    idx = np.where(mask)[0]
    if len(idx) == 0:
        idx = np.arange(len(df))
    order = idx[np.argsort(-(emb[idx] @ qvec))]
    chosen = []
    for i in order:
        if all(emb[i] @ emb[j] < NEAR_DUP_SIM for j in chosen):
            chosen.append(i)
        if len(chosen) == k:
            break
    return df.iloc[chosen]


def build_user_prompt(scenario, examples, difficulty, recipient, sender, institution):
    blocks = []
    for n, (_, r) in enumerate(examples.iterrows(), 1):
        subject = scrub(r["subject"]) or "(no subject)"
        blocks.append(f"[Reference {n}: {r['category']}]\nSubject: {subject}\n{scrub(r['body'])[:EXAMPLE_CHARS]}")
    lines = [
        "Reference emails (historical, for style only; identifiers removed):",
        "\n\n".join(blocks),
        "",
        f"Scenario: {scenario}",
        f"Recipient: {recipient}",
    ]
    if sender:
        lines.append(f"Sender persona: {sender}")
    if institution:
        lines.append(f"Institution: {institution} (use this name instead of [University Name])")
    lines.append(f"Difficulty: {DIFFICULTY[difficulty]}")
    lines.append("\nWrite the email now.")
    return "\n".join(lines)


def chat(model, system, user, temperature=0.8, seed=None, num_predict=700):
    options = {"temperature": temperature, "num_ctx": 4096, "num_predict": num_predict}
    if seed is not None:
        options["seed"] = seed
    payload = json.dumps({
        "model": model, "stream": False, "keep_alive": "10m", "options": options,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read())["message"]["content"]
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise SystemExit(f"Ollama returned HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not reach Ollama at {OLLAMA_URL} ({e}). Is `ollama serve` running?")


def postprocess(raw, institution=None):
    text = re.sub(r"```\w*", "", raw).strip()
    m = re.search(r"^\s*subject\s*:\s*(.+)$", text, re.I | re.M)
    if not m:
        return None
    subject = m.group(1).strip()
    body = text[m.end():]

    body = HEADER_LINE_RX.sub("", body)
    body = RULE_LINE_RX.sub("", body)
    body = "\n".join(ln for ln in body.split("\n") if not DISCLAIMER_RX.search(ln))

    def safe(t):
        t = BRACKET_DOMAIN_RX.sub(f"@{DEAD_DOMAIN}", t)
        t = EMAIL_RX.sub(lambda mm: mm.group(0).split("@")[0] + f"@{DEAD_DOMAIN}", t)
        t = URL_RX.sub(lambda mm: mm.group(0) if DEAD_DOMAIN in mm.group(0) else DEAD_LINK, t)
        if institution:
            t = INSTITUTION_PLACEHOLDER_RX.sub(institution, t)
        return t

    subject, body = safe(subject), re.sub(r"\n{3,}", "\n\n", safe(body)).strip()
    subject = re.sub(r"^(?:re|fwd?)\s*:\s*", "", subject, flags=re.I)
    if not subject or len(body.split()) < MIN_BODY_WORDS:
        return None
    return subject, body


def red_flags(model, subject, body):
    out = chat(
        model,
        "You are a security-awareness trainer writing a debrief for a phishing exercise.",
        f"Here is the simulated email.\n\nSubject: {subject}\n\n{body}\n\n"
        "List 3 to 5 specific red flags that should make a recipient suspicious. "
        "One short line each, no preamble.",
        temperature=0.2, num_predict=300,
    )
    flags = [re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", ln).strip() for ln in out.split("\n")]
    return [f for f in flags if f]


def read_jobs(args):
    if not args.batch:
        if not args.scenario:
            raise SystemExit("Give a scenario, or --batch FILE.")
        return [(args.scenario, args.category)]
    jobs = []
    with open(args.batch, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cat, sep, scen = line.partition("|")
            if sep and cat.strip() in CATEGORIES:
                jobs.append((scen.strip(), cat.strip()))
            else:
                jobs.append((line, args.category))
    return jobs


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", nargs="?", help="plain-language description of the email to simulate")
    ap.add_argument("--batch", help="text file with one scenario per line ('category | scenario' optional)")
    ap.add_argument("--category", choices=CATEGORIES)
    ap.add_argument("--risk", choices=["low", "medium", "high", "critical"])
    ap.add_argument("--difficulty", choices=list(DIFFICULTY), default="moderate")
    ap.add_argument("--recipient", default="a student", help="who it is addressed to (default: a student)")
    ap.add_argument("--sender", help="sender persona, e.g. 'IT Helpdesk' or 'Dean of Academic Affairs'")
    ap.add_argument("--institution", help="name to use in place of [University Name]")
    ap.add_argument("-n", type=int, default=1, help="variants per scenario (default 1)")
    ap.add_argument("-k", type=int, default=4, help="reference examples to retrieve (default 4)")
    ap.add_argument("--temperature", type=float, default=0.8)
    ap.add_argument("--seed", type=int, help="base seed for reproducible output")
    ap.add_argument("--red-flags", action="store_true", help="also generate a debrief list of red flags")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model tag (default {DEFAULT_MODEL})")
    args = ap.parse_args()
    jobs = read_jobs(args)

    if not os.path.exists(INDEX):
        raise SystemExit("rag/index.npz not found - run `python rag/build_index.py` first.")
    df = pd.read_csv(CSV).fillna("")
    emb = np.load(INDEX)["embeddings"]
    if len(emb) != len(df):
        raise SystemExit("index.npz is out of sync with the CSV - rebuild with build_index.py.")
    usable = usable_mask(df)
    # CPU: GPU memory is needed by the Ollama model.
    embedder = SentenceTransformer(EMBED_MODEL, device="cpu")

    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    saved = 0
    for j, (scenario, category) in enumerate(jobs, 1):
        qvec = embedder.encode([scenario], normalize_embeddings=True, convert_to_numpy=True)[0]
        examples = retrieve(df, emb, qvec, args.k, usable, category, args.risk)
        user = build_user_prompt(scenario, examples, args.difficulty, args.recipient, args.sender, args.institution)
        print(f"\n=== [{j}/{len(jobs)}] {scenario}\n    references: {', '.join(examples['id'])}")

        for v in range(1, args.n + 1):
            result = None
            for attempt in range(MAX_ATTEMPTS):
                seed = None if args.seed is None else args.seed + 1000 * v + attempt
                raw = chat(args.model, SYSTEM_PROMPT, user, args.temperature, seed)
                result = postprocess(raw, args.institution)
                if result:
                    break
                print(f"    variant {v}: attempt {attempt + 1} unusable, retrying")
            if not result:
                print(f"    variant {v}: gave up after {MAX_ATTEMPTS} attempts")
                continue
            subject, body = result
            flags = red_flags(args.model, subject, body) if args.red_flags else []

            base = os.path.join(OUT_DIR, f"sim_{stamp}_{j:02d}_{v:02d}")
            with open(base + ".txt", "w", encoding="utf-8") as fh:
                fh.write(f"Subject: {subject}\n\n{body}\n")
            with open(base + ".json", "w", encoding="utf-8") as fh:
                json.dump({
                    "generated_at": stamp, "scenario": scenario, "category_filter": category,
                    "risk_filter": args.risk, "difficulty": args.difficulty, "recipient": args.recipient,
                    "sender": args.sender, "institution": args.institution, "model": args.model,
                    "temperature": args.temperature, "retrieved_ids": examples["id"].tolist(),
                    "subject": subject, "body": body, "red_flags": flags,
                    "purpose": "security-awareness simulation / classifier training data - not for real use",
                }, fh, indent=2)
            saved += 1
            print(f"\n--- variant {v} ---\nSubject: {subject}\n\n{body}")
            if flags:
                print("\nRed flags:\n" + "\n".join(f"  - {f}" for f in flags))
            print(f"[saved {os.path.basename(base)}.txt/.json]")
    print(f"\nDone: {saved} email(s) in {OUT_DIR}")


if __name__ == "__main__":
    main()
