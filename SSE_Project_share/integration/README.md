# integration — RAG → PhishFuzzer → gophish bridge

Pipeline from the RAG generator and PhishFuzzer grader into gophish (authorized
security-awareness training only):

```
scenario ─► rag/generate.py ─► N candidate emails
                                   │
                                   ▼
                     phishfuzzer_eval/classify.py  (verdict: phishing | spam | valid)
                                   │
                                   ▼
                     select (default: push all, verdict in the name)
                                   │
                                   ▼
                     gophish  POST /api/templates/   ({{.URL}} + {{.Tracker}} injected)
```

The bridge imports `rag/generate.py` and `phishfuzzer_eval/classify.py` unmodified
and adds a stdlib-only gophish REST client. Generated emails keep links/addresses
on the dead domain `training.invalid` until the HTML step swaps the link for
gophish's tracked `{{.URL}}`.

## Setup

1. **Generator/grader prerequisites** (same as `rag/` and `phishfuzzer_eval/`):
   ```bash
   pip install sentence-transformers numpy pandas
   ollama serve &                     # local model host
   ollama pull qwen2.5:7b-instruct    # generator
   ollama pull llama3.1:8b            # detector (use a different model than the generator)
   python rag/build_index.py          # once, if rag/index.npz is missing
   ```
2. **gophish**:
   ```bash
   cd gophish-v0.12.1-osx-64bit && ./gophish      # prints an initial admin password
   # open https://127.0.0.1:3333, log in, Settings → copy the API Key
   export GOPHISH_API_KEY=<paste-key>
   ```
   (gophish's phish server listens on `:80` — start it with the privileges that needs.)
3. **Bridge config** (optional): copy `config.example.json` → `config.json`
   (git-ignored) and set values, or use env vars / CLI flags. Precedence:
   **CLI flag > env var > config.json > default**.

## Usage

```bash
# reachability + API-key check (no model needed)
python -m integration.bridge ping

# list templates already in gophish
python -m integration.bridge list

# generate + score + select, print only (no push) — safe dry run
python -m integration.bridge generate "mailbox over quota, verify to keep access" \
       --category credential_phishing --difficulty subtle -n 5

# generate + score + push every candidate as a gophish template (verdict in the name)
python -m integration.bridge push "LDAP password expiry" \
       --institution "IIT Hyderabad" -n 5
```

Pushed templates are named `<scenario>-<category>-<difficulty>-<verdict>-<utcstamp>-<hash>`, e.g.
`mailbox-over-quota-credential_phishing-subtle-valid-20261019T1630Z-a1b2c3d4`,
so the detector verdict is visible in gophish.

### Options

| Flag | Meaning | Default |
|---|---|---|
| `--category` | one of credential_phishing / fake_degree / scholarship_grant_scam / job_internship_scam | — |
| `--difficulty` | obvious / moderate / subtle | moderate |
| `-n` | candidates per scenario | 3 |
| `--policy` | `all` (push every candidate), `evaded` (only ones that beat the detector), `best_of_n`, `caught` | all |
| `--no-inject-url` | keep the `training.invalid` link instead of gophish `{{.URL}}` | off (URL is injected) |
| `--sender` / `--institution` / `--recipient` | persona / org name / addressee | — / — / a student |
| `--gophish-url` `--gen-model` `--det-model` `--det-backend` `--json` | overrides / machine-readable output | config |

## Files

| File | Role |
|---|---|
| `config.py` | `Config` dataclass + layered loader |
| `gophish_client.py` | stdlib REST client (bearer auth, self-signed TLS bypass) |
| `htmlize.py` | plain-text body → gophish HTML + `{{.URL}}`/`{{.Tracker}}`/`{{.FirstName}}` |
| `rag_adapter.py` | imports `rag/generate.py`; `load_corpus()` + `generate_candidates()` |
| `scorer_adapter.py` | imports `phishfuzzer_eval/classify.py`; `score()` → verdict |
| `orchestrator.py` | `run()` = generate → score → `select` → push; `make_template_name` |
| `bridge.py` | argparse CLI (`ping` / `list` / `generate` / `push`) |
| `tests/test_pure.py` | offline unit tests (no network, no model) |

## Tests

```bash
python integration/tests/test_pure.py      # htmlize, naming, selection, mapping
```

## Scope / safety

The bridge only creates gophish email **templates**; campaigns are built and
launched in the gophish UI. All generated content uses the RFC-2606
`training.invalid` dead domain and is for consented awareness exercises and
classifier training data only — never for real attacks.
