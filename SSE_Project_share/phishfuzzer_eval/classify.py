"""Run PhishFuzzer's email classifier (Ollama or OpenRouter) over emails_generated.json."""
import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
IN_FILE = os.path.join(HERE, "emails_generated.json")
OUT_FILE = os.path.join(HERE, "results.jsonl")

OLLAMA_URL = "http://localhost:11434/api/chat"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# SYSTEM_PROMPT, build_basic_prompt, build_full_prompt and parse are verbatim from PhishFuzzer
# (Classification/classify_Qwen.py, https://github.com/DataPhish/PhishFuzzer)
SYSTEM_PROMPT = """You are a cybersecurity email classifier.

Classify the email into ONE of these categories:
- phishing
- spam
- valid

Respond with ONLY ONE WORD.
Do not explain.
"""


def build_basic_prompt(email):
    return f"""
Subject:
{email.get("Subject","")}

Body:
{email.get("Body","")}
"""


def build_full_prompt(email):
    return f"""
Subject:
{email.get("Subject","")}

Body:
{email.get("Body","")}

Sender:
{email.get("Sender","")}

URLs:
{email.get("URL","")}

Attachment:
{email.get("File","")}
"""


def parse(text):
    text = text.strip().lower()
    if "phishing" in text:
        return "phishing"
    elif "spam" in text:
        return "spam"
    elif "valid" in text:
        return "valid"
    return "unknown"


def post(url, payload, headers, timeout=300):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def query(args, prompt, seed):
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
    for attempt in range(6):
        try:
            if args.backend == "ollama":
                out = post(OLLAMA_URL, {
                    "model": args.model, "stream": False, "messages": messages, "keep_alive": "10m",
                    "options": {"temperature": args.temperature, "seed": seed, "num_predict": 10, "num_ctx": 4096},
                }, {"Content-Type": "application/json"})
                return out["message"]["content"]
            out = post(OPENROUTER_URL, {
                "model": args.model, "temperature": args.temperature, "seed": seed, "messages": messages,
            }, {"Content-Type": "application/json", "Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}"})
            return out["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503) and attempt < 5:
                time.sleep(5 * 2 ** attempt + random.random())
                continue
            raise SystemExit(f"{args.backend} returned HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
        except urllib.error.URLError as e:
            if args.backend == "ollama":
                raise SystemExit(f"Could not reach Ollama at {OLLAMA_URL} ({e}). Is `ollama serve` running?")
            if attempt < 5:
                time.sleep(5 * 2 ** attempt)
                continue
            raise


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["ollama", "openrouter"], default="ollama")
    ap.add_argument("--model", default="llama3.1:8b", help="detector model (default llama3.1:8b on Ollama)")
    ap.add_argument("--modes", default="basic,full", help="comma list of basic,full (default both)")
    ap.add_argument("--runs", type=int, default=1, help="repeats per email and mode (majority vote in analyze.py)")
    ap.add_argument("--temperature", type=float, default=0.0, help="0 = repeatable; PhishFuzzer used 0.7")
    ap.add_argument("--workers", type=int, default=1, help="parallel requests (1 for a local GPU, 3 for OpenRouter)")
    args = ap.parse_args()
    if args.backend == "openrouter" and not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("Set OPENROUTER_API_KEY first.")

    with open(IN_FILE, encoding="utf-8") as fh:
        emails = json.load(fh)
    gen_models = {e.get("gen_model") for e in emails if e.get("gen_model")}
    if args.model in gen_models:
        print(f"warning: {args.model} also generated these emails - a model judging its own output is a weak test.\n"
              f"         Prefer a different detector (e.g. llama3.1:8b, mistral, gemma2) or the paper's Qwen-72B.")

    done = set()
    if os.path.exists(OUT_FILE):
        with open(OUT_FILE, encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                done.add((r["uid"], r["model"], r["temperature"], r["prompt_type"], r["run"]))

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    tasks = [(e, m, run) for m in modes for e in emails for run in range(1, args.runs + 1)
             if (e["uid"], args.model, args.temperature, m, run) not in done]
    print(f"{len(tasks)} classifications to run ({len(done)} already in {os.path.basename(OUT_FILE)})")

    def work(task):
        e, mode, run = task
        prompt = build_basic_prompt(e) if mode == "basic" else build_full_prompt(e)
        raw = query(args, prompt, seed=run)
        return {
            "uid": e["uid"], "email_no": e["No."], "original_id": e["Original_ID"], "group": e["group"],
            "scenario": e.get("scenario"), "category": e.get("category"), "difficulty": e.get("difficulty"),
            "ground_truth": e["Type"], "model": args.model, "backend": args.backend,
            "prompt_type": mode, "run": run, "temperature": args.temperature,
            "prediction": parse(raw), "raw": raw.strip()[:80],
        }

    t0 = time.time()
    with open(OUT_FILE, "a", encoding="utf-8") as out, ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(work, t) for t in tasks]
        for n, f in enumerate(as_completed(futures), 1):
            r = f.result()
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
            out.flush()
            if n % 10 == 0 or n == len(tasks):
                rate = n / max(time.time() - t0, 1e-9)
                print(f"  {n}/{len(tasks)}  ({rate:.1f}/s, ~{(len(tasks) - n) / rate / 60:.1f} min left)")
    print(f"done -> {OUT_FILE}\nnext: python phishfuzzer_eval/analyze.py")


if __name__ == "__main__":
    main()
