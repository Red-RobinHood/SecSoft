"""Orchestrator: generate -> score -> select -> push to gophish."""
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import htmlize, rag_adapter, scorer_adapter
from .gophish_client import GophishClient, GophishError

_RANK = {"valid": 3, "spam": 2, "unknown": 1, "phishing": 0}


@dataclass
class ScoredCandidate:
    candidate: object
    score: object
    template_name: str = None
    pushed: dict = None
    error: str = None
    warnings: list = field(default_factory=list)


@dataclass
class RunReport:
    scenario: str
    scored: list = field(default_factory=list)
    pushed: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def ok(self):
        return not self.errors


def _slug(text, maxlen=32):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:maxlen].strip("-") or "scenario"


def make_template_name(cand, score, existing=None):
    """Unique, verdict-annotated template name."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h = hashlib.sha1((cand.subject + "\n" + cand.body).encode("utf-8")).hexdigest()[:8]
    cat = cand.category or "uncat"
    base = f"{_slug(cand.scenario)}-{cat}-{cand.difficulty}-{score.verdict}-{stamp}-{h}"
    if not existing:
        return base
    name, i = base, 1
    while name in existing:
        i += 1
        name = f"{base}-{i}"
    return name


def select(scored, policy="all", threshold=0.5):
    """Filter/rank scored candidates per policy."""
    if policy == "all":
        return list(scored)
    if policy == "evaded":
        return [sc for sc in scored if sc.score.evaded]
    if policy == "caught":
        return [sc for sc in scored if not sc.score.evaded]
    if policy == "best_of_n":
        if not scored:
            return []
        return [max(scored, key=lambda sc: (_RANK.get(sc.score.verdict, 0),
                                            sc.score.votes.get(sc.score.verdict, 0)))]
    raise ValueError(f"unknown selection policy: {policy}")


def run(cfg, scenario, *, category=None, risk=None, difficulty="moderate",
        recipient="a student", sender=None, institution=None, seed=None,
        with_red_flags=False, push=True, corpus=None, client=None):
    """Run the full pipeline for one scenario."""
    report = RunReport(scenario=scenario)

    if corpus is None:
        corpus = rag_adapter.load_corpus()
    cands = rag_adapter.generate_candidates(
        corpus, scenario, n=cfg.n, category=category, risk=risk, difficulty=difficulty,
        recipient=recipient, sender=sender, institution=institution,
        model=cfg.gen_model, temperature=cfg.temperature, k=cfg.k, seed=seed,
        with_red_flags=with_red_flags,
    )
    if not cands:
        report.errors.append(f"generator produced 0 usable candidates for: {scenario}")
        return report

    scored = []
    for c in cands:
        sr = scorer_adapter.score(
            c, backend=cfg.detector_backend, model=cfg.detector_model,
            temperature=cfg.detector_temperature, modes=tuple(cfg.detector_modes),
            runs=cfg.detector_runs, envelope_sender_default=cfg.envelope_sender_default,
        )
        scored.append(ScoredCandidate(candidate=c, score=sr))
    report.scored = scored

    chosen = select(scored, policy=cfg.selection_policy)
    if not chosen:
        report.errors.append(
            f"0 of {len(scored)} candidates matched policy={cfg.selection_policy}; "
            f"try --policy all or raise -n"
        )
        return report

    if not push:
        for sc in chosen:
            sc.template_name = make_template_name(sc.candidate, sc.score)
        return report

    if client is None:
        client = GophishClient(cfg.gophish_base_url, cfg.gophish_api_key,
                               cfg.gophish_verify_tls, cfg.cert_path)
    try:
        existing = {t.get("name") for t in client.list_templates()}
    except GophishError as e:
        report.errors.append(str(e))
        return report

    for sc in chosen:
        name = make_template_name(sc.candidate, sc.score, existing)
        html_doc, warns = htmlize.htmlize(
            sc.candidate.body, inject_url=cfg.inject_url,
            inject_tracking=cfg.inject_tracking,
        )
        sc.template_name, sc.warnings = name, warns
        envelope = sc.candidate.sender and f"{sc.candidate.sender} <no-reply@training.invalid>" \
            or cfg.envelope_sender_default
        try:
            resp = client.create_template(
                name=name, subject=sc.candidate.subject, html=html_doc,
                text=sc.candidate.body, envelope_sender=envelope,
            )
            sc.pushed = resp
            existing.add(name)
            report.pushed.append(sc)
        except GophishError as e:
            sc.error = str(e)
            report.errors.append(f"{name}: {e}")

    return report
