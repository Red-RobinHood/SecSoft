# RAG email simulator

Generates "academic risky email" samples from a plain-language scenario, for
security-awareness simulations and synthetic classifier training data.

## How it works

1. `build_index.py` embeds every row of `dataset/academic_risky_emails.csv`
   with `all-MiniLM-L6-v2` (small, CPU-only) and caches the vectors to `index.npz`.
2. `generate.py` embeds your scenario, retrieves the `k` most similar real
   examples (optionally filtered by `category`/`risk_level`), and passes them to
   a local Ollama model as few-shot references.
3. The model writes a new email. Output goes to `simulated_outputs/` with a JSON
   sidecar recording the scenario, filters and source example IDs.

## Safety choices

- Every link the model writes is forced onto `*.training.invalid`; `.invalid`
  is reserved by RFC 2606 and never resolves.
- No real person, institution or address is used; the model is told to use
  placeholders (`[University Name]`, `[IT Helpdesk]`, ...).
- The email body is **not** watermarked as fake, so recipients react as to real
  mail (as commercial tools like KnowBe4 do). The safety net is the dead link
  and the metadata trail. Keep generated files inside `simulated_outputs/` and
  don't reuse the text outside an authorized exercise.

## Setup (one-time)

```powershell
pip install sentence-transformers
winget install Ollama.Ollama
ollama pull qwen2.5:7b-instruct   # ~4.7GB, fits a 6GB laptop GPU
python rag/build_index.py
```

Re-run `build_index.py` whenever `academic_risky_emails.csv` changes.

## Usage

```powershell
python rag/generate.py "fake LDAP password expiry targeting CS students"
python rag/generate.py "mailbox over quota" --category credential_phishing --difficulty subtle -n 3
python rag/generate.py "password expiry" --institution "IIT Hyderabad" --sender "IT Helpdesk" --recipient "a faculty member"
python rag/generate.py --batch scenarios.txt --red-flags
```

| Option | Meaning |
|---|---|
| `scenario` | what the email is about (or use `--batch`) |
| `--batch FILE` | one scenario per line; optionally `category \| scenario`; `#` comments |
| `--category` | `credential_phishing`, `fake_degree`, `scholarship_grant_scam`, `job_internship_scam` |
| `--risk` | restrict reference examples to `low`/`medium`/`high`/`critical` |
| `--difficulty` | `obvious`, `moderate` (default) or `subtle` |
| `--recipient`, `--sender`, `--institution` | who it is for, who it appears to be from, name to use instead of `[University Name]` |
| `-n` | variants per scenario |
| `-k` | reference examples retrieved (default 4) |
| `--temperature`, `--seed` | creativity; seed makes runs reproducible |
| `--red-flags` | also write a debrief list of cues a trainee should spot (stored in the JSON) |
| `--model` | Ollama model tag |

Beyond a plain prompt:
- Reference examples are quality-filtered and de-duplicated.
- Real URLs and addresses in the examples are scrubbed before the model sees them.
- Replies are cleaned (leftover headers/forwarded text and "training email" disclaimers removed, links and addresses forced to `training.invalid`); unusable replies are retried up to 3 times.
- The JSON sidecar holds the final subject/body plus all parameters, so a batch loads as a dataset.

## Model choice

`qwen2.5:7b-instruct` (q4_K_M, Ollama's default) uses ~4.7GB of VRAM, fits a 6GB
laptop GPU, and follows the placeholder-domain instructions reliably.
`llama3.1:8b-instruct` is an alternative for comparing style. 13B+ models spill
to CPU and are much slower.

## Towards a classifier later

Treat `simulated_outputs/*.json` sidecars as a synthetic-positive manifest:
`category_filter` / `retrieved_ids` give provenance, so near-duplicates of
training examples can be kept out of a test split.
