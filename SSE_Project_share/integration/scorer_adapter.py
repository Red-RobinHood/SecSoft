"""Thin adapter over phishfuzzer_eval/classify.py that scores a Candidate in memory."""
import importlib.util
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLASSIFY_PATH = os.path.join(ROOT, "phishfuzzer_eval", "classify.py")

URL_RX = re.compile(r"https?://[^\s\"'<>)\]]+|www\.[^\s\"'<>)\]]+", re.I)

_C = None


def _classify():
    global _C
    if _C is None:
        spec = importlib.util.spec_from_file_location("pf_classify", CLASSIFY_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _C = mod
    return _C


@dataclass
class ScoreResult:
    verdict: str
    evaded: bool
    per_mode: dict = field(default_factory=dict)
    votes: Counter = field(default_factory=Counter)


def candidate_to_email(cand, envelope_sender_default="no-reply@training.invalid"):
    """Map a Candidate to PhishFuzzer's email dict."""
    sender = cand.sender
    if sender:
        addr = re.sub(r"[^a-z0-9]+", "", sender.lower())[:24] or "sender"
        sender_field = f"{sender} <{addr}@training.invalid>"
    else:
        sender_field = envelope_sender_default
    urls = sorted(set(URL_RX.findall(cand.body)))
    return {
        "Subject": cand.subject,
        "Body": cand.body,
        "Sender": sender_field,
        "URL": str(urls) if urls else "",
        "File": "None",
    }


def score(cand, *, backend="ollama", model="llama3.1:8b", temperature=0.0,
          modes=("basic", "full"), runs=1,
          envelope_sender_default="no-reply@training.invalid"):
    """Classify one Candidate; return a ScoreResult."""
    C = _classify()
    args = SimpleNamespace(backend=backend, model=model, temperature=temperature)
    email = candidate_to_email(cand, envelope_sender_default)

    votes = Counter()
    per_mode = {}
    for mode in modes:
        prompt = C.build_basic_prompt(email) if mode == "basic" else C.build_full_prompt(email)
        mode_votes = Counter()
        for run in range(1, runs + 1):
            raw = C.query(args, prompt, seed=run)
            v = C.parse(raw)
            mode_votes[v] += 1
            votes[v] += 1
        per_mode[mode] = mode_votes.most_common(1)[0][0]

    verdict = votes.most_common(1)[0][0]
    evaded = verdict in ("valid", "spam")
    return ScoreResult(verdict=verdict, evaded=evaded, per_mode=per_mode, votes=votes)
