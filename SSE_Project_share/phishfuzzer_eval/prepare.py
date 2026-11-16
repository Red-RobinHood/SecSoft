"""Convert generated emails into PhishFuzzer's email schema, with optional real-email controls."""
import argparse
import csv
import glob
import json
import os
import random
import re
import sys

csv.field_size_limit(sys.maxsize)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM_DIR = os.path.join(ROOT, "simulated_outputs")
DATASET = os.path.join(ROOT, "dataset")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails_generated.json")

URL_RX = re.compile(r"https?://[^\s\"'<>)\]]+|www\.[^\s\"'<>)\]]+", re.I)
EMAIL_RX = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
SIM_NAME_RX = re.compile(r"sim_(\d{8}T\d{6}Z)_(\d+)_(\d+)\.json$")
MAX_BODY = 4000


def neutral(text):
    text = URL_RX.sub("[LINK]", text)
    return EMAIL_RX.sub("[EMAIL]", text)


def load_generated(neutralise):
    rows = []
    for path in sorted(glob.glob(os.path.join(SIM_DIR, "*.json"))):
        m = SIM_NAME_RX.search(os.path.basename(path))
        if not m:
            continue
        stamp, job, variant = m.groups()
        with open(path, encoding="utf-8") as fh:
            g = json.load(fh)
        body, subject = g.get("body", ""), g.get("subject", "")
        urls = sorted(set(URL_RX.findall(body)))
        sender_name = g.get("sender") or "[Sender]"
        if neutralise:
            body, subject = neutral(body), neutral(subject)
            url_field = ["[LINK]"] * len(urls)
            sender = f"{sender_name} <[SENDER ADDRESS]>"
        else:
            url_field = urls
            sender = f"{sender_name} <{re.sub(r'[^a-z]+', '.', sender_name.lower()).strip('.')}@training.invalid>"
        rows.append({
            "Original_ID": f"gen_{stamp}_{job}",
            "Subject": subject,
            "Body": body,
            "Sender": sender,
            "URL": str(url_field),
            "File": "None",
            "Type": "Phishing",
            "Motivation": "Follow the link" if urls else "Unknown",
            "Created by": "model",
            "Source": "generated",
            "group": "generated",
            "scenario": g.get("scenario"),
            "category": g.get("category_filter") or "unspecified",
            "difficulty": g.get("difficulty"),
            "gen_model": g.get("model"),
            "gen_file": os.path.basename(path),
            "uid": os.path.basename(path)[:-5],
        })
    return rows


def load_controls(path, n, group, type_label, neutralise, seed):
    if n <= 0:
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        lines = (ln.replace("\0", "") for ln in fh)
        data = [r for r in csv.DictReader(lines) if 80 <= len(r["body"]) <= MAX_BODY]
    random.Random(seed).shuffle(data)
    rows = []
    for r in data[:n]:
        subject, body = r["subject"], r["body"]
        urls = sorted(set(URL_RX.findall(body)))
        if neutralise:
            subject, body = neutral(subject), neutral(body)
            urls = ["[LINK]"] * len(urls)
        rows.append({
            "Original_ID": r["id"],
            "Subject": subject,
            "Body": body,
            "Sender": "[Sender] <[SENDER ADDRESS]>" if neutralise else r.get("sender", ""),
            "URL": str(urls),
            "File": "None",
            "Type": type_label,
            "Motivation": "Unknown",
            "Created by": "Human",
            "Source": r.get("sources", ""),
            "group": group,
            "scenario": None,
            "category": r.get("category") or "benign",
            "difficulty": None,
            "uid": r["id"],
        })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--real-risky", type=int, default=0, help="real academic phishing emails to add as positive control")
    ap.add_argument("--benign", type=int, default=0, help="real benign academic emails to add as negative control")
    ap.add_argument("--keep-dead-domain", action="store_true", help="do not replace training.invalid links/addresses")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    neutralise = not args.keep_dead_domain

    rows = load_generated(neutralise)
    if not rows:
        raise SystemExit(f"No sim_*.json files found in {SIM_DIR} - generate some emails first.")
    rows += load_controls(os.path.join(DATASET, "academic_risky_emails.csv"), args.real_risky,
                          "control_real_risky", "Phishing", neutralise, args.seed)
    rows += load_controls(os.path.join(DATASET, "academic_benign_emails.csv"), args.benign,
                          "control_benign", "Valid", neutralise, args.seed)
    for i, r in enumerate(rows, 1):
        r["No."] = i

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1, ensure_ascii=False)

    counts = {}
    for r in rows:
        counts[r["group"]] = counts.get(r["group"], 0) + 1
    templates = len({r["Original_ID"] for r in rows if r["group"] == "generated"})
    print(f"wrote {len(rows)} emails to {OUT}")
    print(f"  {counts}  |  generated templates (scenario runs): {templates}  |  neutralised: {neutralise}")


if __name__ == "__main__":
    main()
