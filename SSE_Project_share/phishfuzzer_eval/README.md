# PhishFuzzer detector check

Runs the emails from `rag/generate.py` through the classifier from
[PhishFuzzer](https://github.com/DataPhish/PhishFuzzer) ("The Phish, The Spam, and The Valid",
[arXiv 2511.21448](https://arxiv.org/abs/2511.21448)). The system prompt, the two prompt modes and the
answer parsing are copied verbatim from their `Classification/classify_Qwen.py`. Only the API call
differs: a local Ollama model (free) or OpenRouter as in the paper.

The detector answers one word: `phishing`, `spam` or `valid`.

- `phishing`: the generated email was caught.
- `valid`: it **got through**.
- `spam`: it was flagged, but as junk rather than as an attack.

Standard library only (plus what `rag/` already uses).

## Steps (PowerShell, from the project folder)

```powershell
# 0. Detector model; use a different one from the generator (qwen2.5:7b-instruct).
ollama pull llama3.1:8b

# 1. Generate 18 scenarios x 7 variants x 3 difficulties = 378 emails (-n 7 = PhishFuzzer's K).
python rag/generate.py --batch phishfuzzer_eval/scenarios.txt -n 7 --difficulty obvious  --institution "IIT Hyderabad"
python rag/generate.py --batch phishfuzzer_eval/scenarios.txt -n 7 --difficulty moderate --institution "IIT Hyderabad"
python rag/generate.py --batch phishfuzzer_eval/scenarios.txt -n 7 --difficulty subtle   --institution "IIT Hyderabad"

# 2. Convert to PhishFuzzer's schema, adding real emails as controls.
python phishfuzzer_eval/prepare.py --real-risky 50 --benign 100

# 3. Classify (basic + full prompt). Resumable: re-run if it stops.
python phishfuzzer_eval/classify.py --model llama3.1:8b

# 4. Report
python phishfuzzer_eval/analyze.py
```

Outputs:

- `report.md`: catch rates by difficulty and category, PhishFuzzer's template metrics, and the controls.
- `evaded.csv`: every generated email the detector did **not** call phishing, with its text, so you can see what got through.

Optional extras:

```powershell
# Stability: PhishFuzzer sampled at temperature 0.7. Run 5 times, take the majority vote.
python phishfuzzer_eval/classify.py --model llama3.1:8b --runs 5 --temperature 0.7

# The paper's detector (paid, needs an OpenRouter key; ~1,050 calls for the batch above incl. controls)
$env:OPENROUTER_API_KEY = "sk-or-..."
python phishfuzzer_eval/classify.py --backend openrouter --model qwen/qwen-2.5-72b-instruct --workers 3
```

`analyze.py` reports each detector, temperature and prompt mode in `results.jsonl` separately. To start over, delete `results.jsonl`.

## Reading the report

| Metric | Meaning |
|---|---|
| flagged as phishing | share of generated emails the detector caught |
| got through | share it called `valid`; higher = more convincing email |
| TSR | per scenario run, the share of its 7 variants that were caught (averaged) |
| Conf@K | % of scenario runs where **all** variants were caught |
| TFS@K | % of scenario runs where **no** variant was caught, i.e. the scenario fully evades |
| control_real_risky | real academic phishing from `dataset/`; should mostly be caught |
| control_benign | real benign academic mail; should mostly be `valid` (this is the false-alarm check) |

A good result: controls behave sensibly (most real phishing caught, few false alarms on benign mail)
and the share that gets through rises from `obvious` to `subtle`. If benign mail is also flagged a lot,
the detector is just strict and a high catch rate means little.

## Design choices

- **Fake links are neutralised.** The generator sends every link and address to `training.invalid`,
  which the detector would key on instead of the writing. `prepare.py` replaces links with `[LINK]` and
  the sender address with `[SENDER ADDRESS]` in generated and control emails alike. Use
  `--keep-dead-domain` to test the raw output.
- **`basic` is the main result.** In `full` mode the URL and sender fields are placeholders here, so
  `full` mostly tells you whether the bare presence of a link pushes the detector toward phishing.
- **Temperature 0 by default** so a run is repeatable. PhishFuzzer used 0.7 with one run; use
  `--runs 5 --temperature 0.7` to see how stable each verdict is.
- **Templates:** all variants from one `generate.py` scenario run share an `Original_ID`, the same
  way PhishFuzzer groups a seed with its 6 rewrites.

## Files

| File | Role |
|---|---|
| `scenarios.txt` | 18 academic test scenarios (`category \| scenario`) for `generate.py --batch` |
| `prepare.py` | `simulated_outputs/*.json` + controls → `emails_generated.json` (PhishFuzzer schema) |
| `classify.py` | PhishFuzzer prompts → Ollama / OpenRouter → `results.jsonl` |
| `analyze.py` | `results.jsonl` → `report.md`, `evaded.csv` |
