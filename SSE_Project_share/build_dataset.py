"""Build the academic risky/benign email dataset from public phishing/spam corpora in raw/ into dataset/."""

import csv
import email
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter
from email import policy

import pandas as pd

csv.field_size_limit(sys.maxsize)

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(ROOT, "raw")
OUT = os.path.join(ROOT, "dataset")


def rx(*terms):
    return re.compile(r"\b(?:" + "|".join(terms) + r")\b", re.I)

ACADEMIC = {
    "institution": rx(r"universit(?:y|ies)", r"college", r"institute of technology",
                      r"campus", r"faculty members?", r"faculty and staff", r"academic", r"academia",
                      r"polytechnic", r"[a-z0-9-]+\.edu", r"[a-z0-9-]+\.ac\.[a-z]{2}"),
    "people":      rx(r"students?", r"undergrad(?:uate)?s?", r"postgrad(?:uate)?s?",
                      r"ph\.?d\.? (?:students?|scholars?|candidates?)", r"professors?", r"prof\.",
                      r"lecturers?", r"dean of \w+", r"the dean", r"registrar", r"vice[- ]chancellor", r"chancellor",
                      r"head of department", r"alumni", r"alumnus", r"freshers?",
                      r"research scholars?", r"teaching assistants?"),
    "activities":  rx(r"semester", r"tuition", r"enrol(?:l)?ment", r"course registration",
                      r"coursework", r"transcripts?", r"grade (?:sheet|report)s?", r"gpa", r"cgpa", r"exams?",
                      r"examinations?", r"thesis", r"dissertation", r"hostel", r"dormitory",
                      r"convocation", r"admissions?", r"scholarships?", r"fellowships?",
                      r"stipend", r"financial aid", r"fafsa", r"research grants?", r"library account",
                      r"moodle", r"blackboard learn", r"student portal", r"academic portal",
                      r"student (?:id|email|account)s?"),
}

THEMES = {
    "credential_phishing": dict(min_hits=2, risk="high", anchor=[1, 2, 5], cues=[
        rx(r"passwords?", r"pass ?code", r"login credentials?", r"user ?name and password"),
        rx(r"web ?mail", r"e-?mail account", r"mail ?box", r"outlook web(?: app| access)?",
           r"owa", r"zimbra", r"squirrel ?mail", r"roundcube", r"ldap", r"sso",
           r"single sign[- ]on", r"office ?365", r"microsoft 365", r"g ?suite", r"exchange server"),
        rx(r"(?:storage|quota) (?:limit|exceeded|is full)", r"exceeded (?:its|the|your) (?:storage|quota|limit)",
           r"mailbox (?:is )?(?:full|almost full)", r"over ?quota"),
        rx(r"verify your (?:account|identity|e-?mail)", r"validate your (?:account|mailbox|e-?mail)",
           r"re-?validate", r"re-?activate", r"confirm your (?:account|e-?mail|password)",
           r"update your (?:account|password|e-?mail)", r"upgrade your (?:account|mailbox)",
           r"reset your password", r"password (?:will )?expir\w*"),
        rx(r"(?:account|mailbox|e-?mail) (?:will be |has been )?(?:suspended|deactivated|disabled|closed|terminated|blocked|locked)",
           r"deactivat\w+", r"suspension", r"within (?:24|48|72) hours"),
        rx(r"it (?:help ?desk|service ?desk|support|department|services)", r"help ?desk",
           r"system administrator", r"(?:web)?mail administrator", r"e-?mail admin\w*",
           r"technical support team", r"network administrator", r"postmaster"),
    ]),
    "impersonation_bec": dict(min_hits=2, risk="high", cues=[
        rx(r"gift ?cards?", r"itunes cards?", r"google play cards?", r"amazon cards?", r"steam cards?"),
        rx(r"are you (?:available|on campus|in the office)", r"quick favou?r", r"i need a favou?r",
           r"can you do (?:me )?a favou?r", r"i'?m in a meeting", r"keep (?:this|it) confidential"),
        rx(r"(?:send|email) me the (?:codes?|pins?)", r"scratch (?:off|the back)", r"pictures? of the cards?"),
        rx(r"wire transfer", r"urgent(?:ly)? (?:payment|transfer)", r"process a payment"),
    ]),
    "fee_payment_scam": dict(min_hits=2, risk="high", needs_academic=True, cues=[
        rx(r"tuition (?:fees?|payment|refund)", r"fee (?:payment|refund|reimbursement)",
           r"(?:hostel|exam|registration|library) (?:fees?|fines?|dues)", r"outstanding (?:fees?|balance)",
           r"refund (?:of|for) (?:your )?(?:tuition|fees)", r"payroll", r"salary (?:update|review|increment|adjustment)",
           r"direct deposit", r"pay ?slip"),
        rx(r"click (?:here|the link|below)", r"secure link", r"log ?in", r"sign ?in", r"update (?:your )?(?:information|details|account)",
           r"verify", r"confirm", r"pay (?:now|immediately|online)", r"to (?:receive|claim) (?:your )?refund"),
    ]),
    "scholarship_grant_scam": dict(min_hits=2, risk="low", needs_academic=True, cues=[
        rx(r"scholarships?", r"fellowships?", r"financial aid", r"bursary", r"(?:research|education) grants?",
           r"fafsa", r"pell grant"),
        rx(r"(?:you|your application) (?:have|has) been (?:selected|awarded|approved|shortlisted)", r"congratulations",
           r"apply (?:now|today|online)", r"processing fee", r"application fee", r"free money", r"\$\s?[\d,]{3,}",
           r"claim", r"eligible", r"deadline", r"click (?:here|below)", r"bank (?:details|account)"),
    ]),
    "job_internship_scam": dict(min_hits=3, risk="medium", needs_academic=True, cues=[
        rx(r"part[- ]time (?:job|position|work)", r"work from home", r"internships?",
           r"research assistant", r"personal assistant", r"job offer", r"employment opportunit\w+",
           r"hiring", r"vacanc(?:y|ies)", r"position available"),
        rx(r"\$\s?\d{2,4}\s?(?:per|/|a)\s?(?:week|hour|wk|hr)", r"weekly (?:pay|salary)",
           r"flexible hours", r"no experience", r"earn (?:extra|up to)", r"reshipp\w+",
           r"cheque|check (?:deposit|payment)", r"mobile deposit"),
        rx(r"students?", r"campus", r"universit(?:y|ies)", r"college", r"graduates?"),
    ]),
    "predatory_publishing": dict(min_hits=2, risk="low", needs_academic=True, cues=[
        rx(r"call for papers", r"submit (?:your )?(?:paper|manuscript|abstract)s?",
           r"manuscripts?", r"journals?", r"publication fees?", r"article processing charges?",
           r"conference", r"symposium", r"peer[- ]review\w*", r"impact factor", r"indexed in",
           r"scopus", r"keynote speaker", r"editorial board"),
        rx(r"registration fees?", r"publication fees?", r"open access", r"fast(?:[- ]track)? (?:review|publication)",
           r"accepted for (?:publication|presentation)", r"invite(?:d)? you to (?:submit|speak|join)",
           r"honorarium", r"early bird"),
    ]),
    "fake_degree": dict(min_hits=2, risk="low", cues=[
        rx(r"diplomas?", r"(?:university|college|bachelor'?s?|master'?s?|mba|doctorate|phd) degrees?", r"degrees?", r"doctorates?"),
        rx(r"no (?:required )?(?:tests?|classes|books|exams?|study)", r"non-?accredited",
           r"life experience", r"prestigious", r"within (?:\d+|two|four) weeks",
           r"call (?:now|today|\d)", r"(?:24|twenty[- ]four) hours", r"confidentiality assured",
           r"money[- ]earning power", r"no one is turned down", r"obtain (?:a|your) (?:degree|diploma)"),
    ]),
    "malicious_document": dict(min_hits=2, risk="high", needs_academic=True, cues=[
        rx(r"shared (?:a |the )?(?:document|file|folder)", r"view (?:the )?(?:document|file|attachment)",
           r"open (?:the )?attach\w+", r"docu ?sign", r"one ?drive", r"share ?point", r"google drive",
           r"dropbox", r"we ?transfer", r"download (?:the )?(?:file|document|attachment)",
           r"enable (?:content|macros|editing)", r"secure (?:document|message)"),
        rx(r"(?:exam|class|course|semester) ?(?:time ?table|schedule)", r"syllabus", r"exam results?", r"marks? ?sheet",
           r"grade ?(?:sheet|report)", r"transcripts?", r"assignments?", r"admit card", r"hall ticket",
           r"(?:fee|payment) receipt"),
    ]),
}

NOISE = rx(r"viagra", r"cialis", r"levitra", r"pharmac\w+", r"prescriptions?", r"pills?", r"penis",
           r"erection", r"sex(?:ual|y)?", r"porn\w*", r"xxx", r"casino", r"poker", r"lotto",
           r"replica", r"rolex", r"watches", r"stock (?:alert|pick)", r"penny stock", r"ticker",
           r"weight loss", r"diet", r"mortgage", r"refinanc\w+", r"dating", r"singles", r"meds",
           r"oem software", r"adobe photoshop", r"herbal", r"weight", r"debts?", r"mlm", r"insurance",
           r"psychic", r"otcbb", r"sym:", r"isin", r"wkn", r"shares", r"investors?", r"stock",
           r"newsletter", r"unsubscribe", r"lord jesus", r"god bless")
STRONG_NOISE = rx(r"viagra", r"cialis", r"penis", r"porn\w*", r"casino", r"otcbb", r"penny stock",
                  r"stock (?:alert|pick)", r"sym:", r"isin", r"wkn", r"rolex", r"replica",
                  r"mortgage", r"refinanc\w+", r"psychic", r"weight loss", r"enlarge\w*",
                  r"doctor recommended", r"size doesn'?t matter")

CONSUMER_BRANDS = rx(r"paypal", r"ebay", r"amazon", r"apple id", r"netflix", r"chase", r"wells fargo",
                     r"bank of america", r"citibank", r"barclays", r"hsbc", r"lloyds", r"natwest",
                     r"halifax", r"credit card", r"debit card", r"irs", r"hmrc", r"western union",
                     r"moneygram", r"lottery", r"next of kin", r"inheritance", r"beneficiary",
                     r"aliexpress", r"travelocity", r"expedia", r"visa card", r"mastercard", r"american express",
                     r"widow", r"late husband", r"million (?:united states |us )?dollars", r"nigeria\w*",
                     r"washington mutual", r"wamu", r"\w+ bank", r"online banking", r"facebook", r"linkedin", r"twitter", r"instagram", r"whatsapp", r"dhl", r"fedex",
                     r"ups (?:package|parcel|delivery|shipment)")

EMAIL_RX = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
HEADER_LINE = re.compile(r"^(?:[A-Z][A-Za-z-]{1,30}[^\w\s:]{0,4}\s*:.*|\d{1,6}|From\s*|\s*:.*|\s*[\w.'-]+@[\w.-]+,?\s*)$")
ARTIFACTS = re.compile(r"internal format of your mail folder|CMS Attack Sample is a test|This is a test mail for XSS|"
                       r"bad destination mailbox address|Delivery Status Notification \(Failure\)", re.I)
MIME_JUNK = re.compile(r"^(?:This is a multi-?part (?:message|MIME message).*|You will not see this in a MIME-aware.*|"
                       r"-{2,}[=_A-Za-z0-9.+/-]{6,}-*|[A-Za-z-]*Content-[A-Za-z-]+\s*:.*|\s+(?:charset|boundary|name|filename)\s*=.*|"
                       r"X-[A-Za-z-]+\s*:.*|MIME-Version\s*:.*|Status\s*:.*|thread-index\s*:.*|Thread-Topic\s*:.*|"
                       r"Lines\s*:.*|User-Agent\s*:.*|acceptlanguage\s*:.*|DelSp=.*|\s*format=.*|"
                       r"[A-Za-z0-9+/=]{60,})$", re.I | re.M)

URL_RX = re.compile(r"https?://[^\s\"'<>)]+|www\.[^\s\"'<>)]+", re.I)


def clean(s):
    if not isinstance(s, str):
        return ""
    s = re.sub(r"<[^>]{0,3000}>", " ", s)
    s = re.sub(r"&nbsp;|&#160;", " ", s)
    return re.sub(r"[ \t\r\f\v]+", " ", s).strip()


def load_csv(path, source):
    df = pd.read_csv(path, engine="python", on_bad_lines="skip")
    if "text_combined" in df.columns:
        df = df.rename(columns={"text_combined": "body"})
    for c in ("sender", "receiver", "subject", "body", "urls"):
        if c not in df.columns:
            df[c] = ""
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].isin([0, 1])]
    df["source"] = source
    return df[["source", "sender", "subject", "body", "label"]]


def load_eml_dir(path, source):
    rows = []
    for f in glob.glob(os.path.join(path, "*", "*.eml")):
        try:
            with open(f, "rb") as fh:
                msg = email.message_from_binary_file(fh, policy=policy.default)
            parts = []
            for part in msg.walk():
                if part.get_content_maintype() == "text":
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        parts.append(payload.decode("latin-1", "ignore"))
            rows.append(dict(source=source, sender=str(msg.get("From", "")),
                             subject=str(msg.get("Subject", "")), body="\n".join(parts), label=1))
        except Exception:
            continue
    return pd.DataFrame(rows)


def load_all():
    frames = []
    frames.append(load_csv(os.path.join(RAW, "zenodo", "Merged_Dataset.csv"), "zenodo_merged"))
    for f in sorted(glob.glob(os.path.join(RAW, "figshare", "*.csv"))):
        frames.append(load_csv(f, "figshare_" + os.path.basename(f)[:-4]))
    for f in sorted(glob.glob(os.path.join(RAW, "kaggle", "*.csv"))):
        if f.endswith("phishing_email.csv"):
            continue
        frames.append(load_csv(f, "kaggle_" + os.path.basename(f)[:-4]))
    frames.append(load_eml_dir(os.path.join(RAW, "epvme"), "epvme"))
    df = pd.concat(frames, ignore_index=True)
    for c in ("sender", "subject", "body"):
        df[c] = df[c].fillna("").astype(str)
    print("loaded", len(df), "rows;", df.groupby("source").size().to_dict())
    return df


def norm_key(subject, body):
    t = (subject + " " + body).lower()
    t = URL_RX.sub(" ", t)
    t = re.sub(r"[^a-z]+", "", t)
    return hashlib.md5(t[:3000].encode()).hexdigest()


def dedupe(df):
    df = df.copy()
    df["subject"] = df["subject"].map(clean)
    df["body"] = df["body"].map(clean)
    df = df[df["body"].str.len() > 40]
    df["key"] = [norm_key(s, b) for s, b in zip(df["subject"], df["body"])]
    provenance = df.groupby("key")["source"].agg(lambda s: ";".join(sorted(set(s))))
    lab = df.groupby("key")["label"].nunique()
    df["meta"] = (df["sender"].str.len() > 0).astype(int) + (df["subject"].str.len() > 0).astype(int)
    df = df.sort_values("meta", ascending=False).drop_duplicates("key")
    df["sources"] = df["key"].map(provenance)
    df = df[df["key"].map(lab) == 1]
    return df.drop(columns=["meta"])


def strip_headers(body):
    lines = body.split("\n")
    i = 0
    while i < len(lines) and i < 80:
        ln = lines[i]
        if HEADER_LINE.match(ln) or (ln[:1] in (" ", "\t") and i and HEADER_LINE.match(lines[i - 1])):
            i += 1
        elif not ln.strip() and i + 1 < len(lines) and HEADER_LINE.match(lines[i + 1]) and i < 3:
            i += 1
        else:
            break
    while i < len(lines) and not lines[i].strip():
        i += 1
    return "\n".join(lines[i:]).strip() if i >= 2 else body


def clean_mime(body):
    if not re.search(r"Content-|NextPart|MIME|=\r?\n|=20|=3D|=0A|Lines:|DelSp|[A-Za-z0-9+/]{60}", body):
        return body
    body = body.replace("=0A", "\n")
    body = re.sub(r"(=+\s*\d*)=?(Content-)", r"\1\n\2", body)
    body = re.sub(r"=\r?\n", "", body)
    body = re.sub(r"=([0-9A-F]{2})", lambda m: chr(int(m.group(1), 16)) if m.group(1) in
                  ("20", "3D", "09", "2C", "2E", "21", "3F", "27", "22", "A0") else m.group(0), body)
    body = MIME_JUNK.sub("", body)
    body = re.sub(r"^-{2}=+\s*\d*=?\s*$", "", body, flags=re.M)
    body = re.sub(r"\n{3,}", "\n\n", body)
    return body.strip()


def academic_hits(text):
    text = EMAIL_RX.sub(" ", text)
    hits = {}
    for group, pat in ACADEMIC.items():
        found = {m.lower() for m in pat.findall(text)}
        if found:
            hits[group] = sorted(found)[:8]
    return hits


def theme_hits(text, academic_score):
    fired = {}
    for name, spec in THEMES.items():
        if spec.get("needs_academic") and academic_score == 0:
            continue
        matched = []
        for cue in spec["cues"]:
            m = cue.search(text)
            if m:
                matched.append(m.group(0).lower())
        if spec.get("needs_academic") and academic_score < 2:
            continue
        if len(matched) < spec["min_hits"]:
            continue
        anchor = spec.get("anchor")
        if anchor and not any(spec["cues"][i].search(text) for i in anchor):
            continue
        fired[name] = matched
    return fired


RISK_ORDER = {"high": 3, "medium": 2, "low": 1}
PRIORITY = ["credential_phishing", "impersonation_bec", "malicious_document", "fee_payment_scam",
            "scholarship_grant_scam", "job_internship_scam", "predatory_publishing", "fake_degree"]


def classify(row):
    if ARTIFACTS.search(row["body"]):
        return None
    text = row["subject"] + "\n" + row["body"]
    ac = academic_hits(text)
    ac_score = sum(len(v) for v in ac.values())
    themes = theme_hits(text, ac_score)
    if not themes:
        return None
    noise = len({m.lower() for m in NOISE.findall(text)})
    brands = len({m.lower() for m in CONSUMER_BRANDS.findall(text)})
    primary = next(t for t in PRIORITY if t in themes)

    strong_noise = bool(STRONG_NOISE.search(text))
    if primary == "credential_phishing":
        if brands and ac_score < 2:
            return None
        if noise >= 2 and ac_score < 2:
            return None
    else:
        if strong_noise or noise >= 2:
            return None
        if brands and ac_score < 3:
            return None
    if primary == "fake_degree" and not re.search(r"universit|college|diploma", text, re.I):
        return None
    risk = THEMES[primary]["risk"]
    if primary == "credential_phishing" and ac_score >= 2:
        risk = "critical"
    urls = sorted(set(URL_RX.findall(text)))[:20]
    return dict(
        category=primary,
        secondary_categories=";".join(t for t in themes if t != primary),
        risk_level=risk,
        academic_context_score=ac_score,
        academic_terms=json.dumps(ac),
        matched_cues=json.dumps(themes),
        has_url=int(bool(urls)),
        num_urls=len(urls),
        urls=" ".join(urls),
    )


def main():
    os.makedirs(OUT, exist_ok=True)
    cache = os.path.join(RAW, ".dedup_cache.pkl")
    if os.path.exists(cache):
        df = pd.read_pickle(cache)
    else:
        df = dedupe(load_all())
        df.to_pickle(cache)
    print("after dedupe:", len(df), df["label"].value_counts().to_dict())

    df["body"] = df["body"].map(strip_headers).map(clean_mime).map(strip_headers)
    df["subject"] = df["subject"].replace({"nan": ""})
    df.loc[df["subject"].str.fullmatch(r"(?:\w+ )?Attack Sample", na=False), "subject"] = ""
    bad = df[df["label"] == 1]
    rows = []
    for _, r in bad.iterrows():
        res = classify(r)
        if res:
            rows.append({**{k: r[k] for k in ("subject", "body", "sender", "sources")}, **res})
    risky = pd.DataFrame(rows)
    def near_key(b):
        t = URL_RX.sub(" ", EMAIL_RX.sub(" ", b.lower()))
        return re.sub(r"[^a-z]+", "", t)[:400]
    risky["nk"] = risky["body"].map(near_key)
    prov = risky.groupby("nk")["sources"].agg(lambda s: ";".join(sorted({x for v in s for x in v.split(";")})))
    risky["sources"] = risky["nk"].map(prov)
    risky["near_duplicates"] = risky["nk"].map(risky["nk"].value_counts()) - 1
    risky = risky.drop_duplicates("nk").drop(columns="nk")
    risky = risky.sort_values(["risk_level", "academic_context_score"],
                              key=lambda s: s.map(RISK_ORDER).fillna(4) if s.name == "risk_level" else s,
                              ascending=False).reset_index(drop=True)
    risky.insert(0, "id", [f"ACAD-R-{i:05d}" for i in range(1, len(risky) + 1)])
    risky.insert(1, "label", "risky")
    risky.to_csv(os.path.join(OUT, "academic_risky_emails.csv"), index=False, quoting=csv.QUOTE_ALL)

    good = df[df["label"] == 0]
    ben = []
    for _, r in good.iterrows():
        text = r["subject"] + "\n" + r["body"]
        ac = academic_hits(text)
        score = sum(len(v) for v in ac.values())
        if score >= 3 and len(ac) >= 2:
            ben.append({**{k: r[k] for k in ("subject", "body", "sender", "sources")},
                        "academic_context_score": score, "academic_terms": json.dumps(ac)})
    benign = pd.DataFrame(ben).sort_values("academic_context_score", ascending=False).reset_index(drop=True)
    benign.insert(0, "id", [f"ACAD-B-{i:05d}" for i in range(1, len(benign) + 1)])
    benign.insert(1, "label", "benign")
    benign.to_csv(os.path.join(OUT, "academic_benign_emails.csv"), index=False, quoting=csv.QUOTE_ALL)

    cols = ["id", "is_risky", "category", "risk_level", "subject", "body", "sender", "sources"]
    r2 = risky.assign(is_risky=1)
    b2 = benign.assign(is_risky=0, category="benign", risk_level="none")
    combined = pd.concat([r2[cols], b2[cols]], ignore_index=True).sample(frac=1, random_state=42)
    combined.to_csv(os.path.join(OUT, "academic_emails_labeled.csv"), index=False, quoting=csv.QUOTE_ALL)

    src_counts = Counter()
    for s in risky["sources"]:
        for x in s.split(";"):
            src_counts[x] += 1
    summary = dict(
        risky_total=len(risky),
        benign_total=len(benign),
        by_category=risky["category"].value_counts().to_dict(),
        by_risk=risky["risk_level"].value_counts().to_dict(),
        by_source=dict(src_counts.most_common()),
        with_url=int(risky["has_url"].sum()),
    )
    with open(os.path.join(OUT, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
