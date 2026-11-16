"""Summarise results.jsonl: did PhishFuzzer's classifier flag the generated emails?"""
import csv
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
EMAILS = os.path.join(HERE, "emails_generated.json")
RESULTS = os.path.join(HERE, "results.jsonl")
REPORT = os.path.join(HERE, "report.md")
EVADED = os.path.join(HERE, "evaded.csv")
LABELS = ["phishing", "spam", "valid", "unknown"]
DIFF_ORDER = ["obvious", "moderate", "subtle"]


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "-"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def verdict_rows(verdicts, key):
    groups = defaultdict(Counter)
    for e, lab in verdicts:
        groups[key(e)][lab] += 1
    order = sorted(groups, key=lambda g: (DIFF_ORDER.index(g) if g in DIFF_ORDER else 99, str(g)))
    rows = []
    for g in order:
        c = groups[g]
        n = sum(c.values())
        rows.append([g, n, pct(c["phishing"], n), pct(c["spam"], n), pct(c["valid"] + c["unknown"], n)])
    return rows


def main():
    with open(EMAILS, encoding="utf-8") as fh:
        emails = {e["uid"]: e for e in json.load(fh)}
    runs = defaultdict(list)
    with open(RESULTS, encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            if r.get("uid") in emails:
                detector = f'{r["model"]} @ T={r.get("temperature", 0)}'
                runs[(detector, r["prompt_type"], r["uid"])].append(r["prediction"])

    configs = sorted({(m, p) for m, p, _ in runs})
    md = ["# PhishFuzzer check of generated emails", ""]
    md.append("Detector prompts and answer parsing are PhishFuzzer's own "
              "([classify_Qwen.py](https://github.com/DataPhish/PhishFuzzer)). "
              "*Got through* = the detector answered `valid`. `spam` means it was flagged, but as junk rather than an attack.")
    evaded = []

    for model, mode in configs:
        verdicts = []
        unstable = 0
        for (m, p, no), preds in runs.items():
            if (m, p) != (model, mode):
                continue
            c = Counter(preds)
            label = c.most_common(1)[0][0]
            if len(c) > 1:
                unstable += 1
            verdicts.append((emails[no], label))
            if emails[no]["group"] == "generated" and label != "phishing":
                e = emails[no]
                evaded.append({"detector": model, "mode": mode, "verdict": label, "votes": dict(c),
                               "difficulty": e.get("difficulty"), "category": e.get("category"),
                               "scenario": e.get("scenario"), "file": e.get("gen_file"),
                               "subject": e["Subject"], "body": e["Body"]})

        gen = [(e, l) for e, l in verdicts if e["group"] == "generated"]
        md += ["", f"## {model} - `{mode}` prompt", ""]
        if gen:
            n = len(gen)
            c = Counter(l for _, l in gen)
            md.append(f"**Generated emails: {c['phishing']}/{n} flagged as phishing ({pct(c['phishing'], n)}), "
                      f"{c['valid'] + c['unknown']} got through ({pct(c['valid'] + c['unknown'], n)}), "
                      f"{c['spam']} called spam.**")
            md += ["", "By difficulty:", "",
                   table(["difficulty", "emails", "phishing", "spam", "got through"],
                         verdict_rows(gen, lambda e: e.get("difficulty") or "-"))]
            md += ["", "By category:", "",
                   table(["category", "emails", "phishing", "spam", "got through"],
                         verdict_rows(gen, lambda e: e.get("category") or "-"))]

            tmpl = defaultdict(list)
            for e, l in gen:
                tmpl[e["Original_ID"]].append((e.get("difficulty"), l == "phishing"))
            rows = []
            for d in DIFF_ORDER + [None]:
                ts = [v for v in tmpl.values() if v[0][0] == d]
                if not ts:
                    continue
                tsr = sum(sum(x for _, x in v) / len(v) for v in ts) / len(ts)
                conf = sum(all(x for _, x in v) for v in ts)
                tfs = sum(not any(x for _, x in v) for v in ts)
                ks = sorted({len(v) for v in ts})
                rows.append([d or "-", len(ts), "/".join(map(str, ks)), f"{100 * tsr:.1f}%",
                             pct(conf, len(ts)), pct(tfs, len(ts))])
            md += ["", "Template metrics (variants of one scenario run grouped, as in PhishFuzzer):", "",
                   table(["difficulty", "templates", "K", "TSR", "Conf@K", "TFS@K (fully evades)"], rows)]
            if any(len(v) == 1 for v in tmpl.values()):
                md.append("\n_Some templates have only one variant; generate with `-n 7` to match PhishFuzzer's K=7._")

        ctrl = [(e, l) for e, l in verdicts if e["group"] != "generated"]
        if ctrl:
            rows = verdict_rows(ctrl, lambda e: e["group"])
            md += ["", "Controls (real emails, same prompt):", "",
                   table(["group", "emails", "phishing", "spam", "valid"], rows)]
            ben = [l for e, l in ctrl if e["group"] == "control_benign"]
            if ben:
                fp = sum(l == "phishing" for l in ben)
                md.append(f"\nFalse-alarm rate on benign academic mail: {pct(fp, len(ben))}. "
                          "If this is high, a high catch rate on generated emails means the detector is just strict.")
        many = [p for (m, pm, _), p in runs.items() if (m, pm) == (model, mode)]
        if any(len(p) > 1 for p in many):
            md.append(f"\nVerdict stability: {pct(len(many) - unstable, len(many))} of emails got the same label in every run.")

    with open(REPORT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    with open(EVADED, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["detector", "mode", "verdict", "votes", "difficulty", "category",
                                           "scenario", "file", "subject", "body"], quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(evaded)
    print("\n".join(md))
    print(f"\nwrote {REPORT} and {EVADED} ({len(evaded)} generated emails not flagged as phishing)")


if __name__ == "__main__":
    main()
