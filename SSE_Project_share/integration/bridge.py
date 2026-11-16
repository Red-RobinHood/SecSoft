"""CLI for the RAG -> PhishFuzzer -> gophish bridge."""
import argparse
import json
import sys

if __package__ in (None, ""):
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from integration import config as config_mod
    from integration import orchestrator
    from integration.gophish_client import GophishClient, GophishError
else:
    from . import config as config_mod
    from . import orchestrator
    from .gophish_client import GophishClient, GophishError

CATEGORIES = ["credential_phishing", "fake_degree", "scholarship_grant_scam", "job_internship_scam"]


def _client(cfg):
    return GophishClient(cfg.gophish_base_url, cfg.gophish_api_key,
                         cfg.gophish_verify_tls, cfg.cert_path)


def _cfg_from_args(args):
    overrides = {
        "gophish_base_url": getattr(args, "gophish_url", None),
        "gen_model": getattr(args, "gen_model", None),
        "detector_model": getattr(args, "det_model", None),
        "detector_backend": getattr(args, "det_backend", None),
        "selection_policy": getattr(args, "policy", None),
        "n": getattr(args, "n", None),
        "inject_url": (False if getattr(args, "no_inject_url", False) else None),
    }
    return config_mod.load_config(cli_overrides=overrides)


def _print_table(report, as_json):
    if as_json:
        rows = [{
            "subject": sc.candidate.subject,
            "verdict": sc.score.verdict,
            "evaded": sc.score.evaded,
            "per_mode": sc.score.per_mode,
            "template_name": sc.template_name,
            "pushed": bool(sc.pushed),
            "error": sc.error,
        } for sc in report.scored]
        print(json.dumps({"scenario": report.scenario, "candidates": rows,
                          "pushed": len(report.pushed), "errors": report.errors}, indent=2))
        return
    print(f"\nScenario: {report.scenario}")
    print(f"{'verdict':9} {'evaded':6} {'pushed-as / subject'}")
    print("-" * 72)
    for sc in report.scored:
        tag = sc.template_name or f"(subject) {sc.candidate.subject[:48]}"
        print(f"{sc.score.verdict:9} {str(sc.score.evaded):6} {tag}")
        if sc.warnings:
            for w in sc.warnings:
                print(f"            ! {w}")
        if sc.error:
            print(f"            ERROR: {sc.error}")
    print(f"\npushed {len(report.pushed)} template(s); {len(report.errors)} error(s)")
    for e in report.errors:
        print(f"  - {e}")


def cmd_ping(args):
    cfg = _cfg_from_args(args)
    try:
        _client(cfg).ping()
    except GophishError as e:
        print(f"FAIL: {e}")
        return 1
    print(f"OK: reached gophish at {cfg.gophish_base_url} and the API key works.")
    return 0


def cmd_list(args):
    cfg = _cfg_from_args(args)
    try:
        templates = _client(cfg).list_templates()
    except GophishError as e:
        print(f"FAIL: {e}")
        return 1
    if not templates:
        print("(no templates in gophish yet)")
        return 0
    for t in templates:
        print(f"  [{t.get('id')}] {t.get('name')}  | subject: {t.get('subject','')[:50]}")
    print(f"\n{len(templates)} template(s)")
    return 0


def _run_pipeline(args, push):
    cfg = _cfg_from_args(args)
    report = orchestrator.run(
        cfg, args.scenario, category=args.category, risk=args.risk,
        difficulty=args.difficulty, recipient=args.recipient, sender=args.sender,
        institution=args.institution, seed=args.seed,
        with_red_flags=args.red_flags, push=push,
    )
    _print_table(report, args.json)
    return 0 if report.ok else 1


def cmd_generate(args):
    return _run_pipeline(args, push=False)


def cmd_push(args):
    return _run_pipeline(args, push=True)


def _add_global(p):
    p.add_argument("--gophish-url", dest="gophish_url")
    p.add_argument("--gen-model", dest="gen_model")
    p.add_argument("--det-model", dest="det_model")
    p.add_argument("--det-backend", dest="det_backend", choices=["ollama", "openrouter"])
    p.add_argument("--json", action="store_true", help="machine-readable output")


def _add_pipeline(p):
    p.add_argument("scenario", help="plain-language description of the email to simulate")
    p.add_argument("--category", choices=CATEGORIES)
    p.add_argument("--risk", choices=["low", "medium", "high", "critical"])
    p.add_argument("--difficulty", choices=["obvious", "moderate", "subtle"], default="moderate")
    p.add_argument("--recipient", default="a student")
    p.add_argument("--sender")
    p.add_argument("--institution")
    p.add_argument("-n", type=int, help="candidates to generate (default from config: 3)")
    p.add_argument("--seed", type=int)
    p.add_argument("--policy", choices=config_mod.SELECTION_POLICIES)
    p.add_argument("--red-flags", action="store_true")
    p.add_argument("--no-inject-url", action="store_true",
                   help="keep the training.invalid link instead of gophish {{.URL}}")
    _add_global(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ping = sub.add_parser("ping", help="check gophish reachability + API key")
    _add_global(p_ping); p_ping.set_defaults(func=cmd_ping)

    p_list = sub.add_parser("list", help="list gophish templates")
    _add_global(p_list); p_list.set_defaults(func=cmd_list)

    p_gen = sub.add_parser("generate", help="generate + score + select (no push)")
    _add_pipeline(p_gen); p_gen.set_defaults(func=cmd_generate)

    p_push = sub.add_parser("push", help="generate + score + push templates to gophish")
    _add_pipeline(p_push); p_push.set_defaults(func=cmd_push)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
