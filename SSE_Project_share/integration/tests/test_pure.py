"""Offline unit tests for the bridge's pure functions."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from integration import htmlize
from integration.scorer_adapter import candidate_to_email, ScoreResult
from integration.rag_adapter import Candidate
from integration.orchestrator import make_template_name, select, ScoredCandidate
from collections import Counter


def _cand(subject="Mailbox over quota", body=None):
    body = body or ("Dear [Student Name],\n\nLog in to keep access:\n"
                    "https://portal.training.invalid/verify\n\nIT Helpdesk")
    return Candidate(subject=subject, body=body, scenario="mailbox over quota",
                     category="credential_phishing", difficulty="subtle")


def test_htmlize_injects_url_and_tracker():
    h, w = htmlize.htmlize(_cand().body)
    assert "{{.URL}}" in h
    assert "{{.FirstName}}" in h
    assert "{{.Tracker}}" in h
    assert "training.invalid" not in h
    assert w == []


def test_htmlize_no_inject_keeps_dead_link():
    h, _ = htmlize.htmlize(_cand().body, inject_url=False, inject_tracking=False)
    assert "portal.training.invalid" in h
    assert "{{.URL}}" not in h


def test_htmlize_escapes_but_keeps_vars():
    h, _ = htmlize.htmlize("A <b>bold</b> & risky link {{.URL}}")
    assert "&lt;b&gt;" in h and "&amp;" in h
    assert "{{.URL}}" in h


def test_htmlize_warns_when_no_url():
    h, w = htmlize.htmlize("No link here, just account text.")
    assert w and "{{.URL}}" in h


def test_candidate_to_email_fields():
    e = candidate_to_email(_cand())
    assert e["Subject"] and e["Body"]
    assert "training.invalid" in e["URL"]
    assert e["File"] == "None"


def test_make_template_name_unique_and_annotated():
    cand, sr = _cand(), ScoreResult(verdict="valid", evaded=True)
    n1 = make_template_name(cand, sr)
    assert "valid" in n1 and "credential_phishing" in n1 and "subtle" in n1
    n2 = make_template_name(cand, sr, existing={n1})
    assert n2 != n1 and n2.startswith(n1)


def test_select_policies():
    a = ScoredCandidate(_cand(), ScoreResult(verdict="valid", evaded=True,
                                             votes=Counter({"valid": 2})))
    b = ScoredCandidate(_cand("x"), ScoreResult(verdict="phishing", evaded=False,
                                                votes=Counter({"phishing": 2})))
    pool = [a, b]
    assert select(pool, "all") == pool
    assert select(pool, "evaded") == [a]
    assert select(pool, "caught") == [b]
    assert select(pool, "best_of_n") == [a]


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
