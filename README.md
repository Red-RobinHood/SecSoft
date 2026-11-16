## Repository layout

| Path | Contents |
|---|---|
| `SSE_Project_share/build_dataset.py` | Constructs the academic-risk dataset from fourteen public corpora |
| `SSE_Project_share/dataset/` | Dataset documentation and summary; the generated CSVs are not tracked (see Setup) |
| `SSE_Project_share/rag/` | Retrieval-augmented lure generator (MiniLM retrieval, Ollama generation) |
| `SSE_Project_share/phishfuzzer_eval/` | Detector-evaluation harness and results |
| `SSE_Project_share/integration/` | Component connecting generation and scoring to the GoPhish REST API |
| `SSE_Project_share/tracking/` | Mail-sending utility, landing page and optional tracking components |
| `SSE_Project_share/simulated_outputs/` | Generated lure samples with JSON provenance records |
| `SSE_Project_share/gophish-v0.12.1-osx-64bit/` | Not tracked — vendored GoPhish release (see Setup) |
| `login-demo.html`, `reset-demo.html` | Static interface mock-ups of the portal pages |

## Setup

1. **GoPhish.** Download the matching release from
   [github.com/gophish/gophish/releases](https://github.com/gophish/gophish/releases)
   (this project was built against v0.12.1) and extract it to
   `SSE_Project_share/gophish-v0.12.1-osx-64bit/`. On first launch it generates its own
   self-signed `gophish_admin.crt`/`.key` and a fresh `gophish.db`; none of those are
   tracked, since the database accumulates real campaign and recipient data.
2. **Dataset.** Build it locally rather than pulling it from the repository:
   ```bash
   bash SSE_Project_share/download_raw.sh
   python SSE_Project_share/build_dataset.py
   ```
3. **Embeddings cache.** `rag/index.npz` is derived from the dataset above and is
   regenerated with `python SSE_Project_share/rag/build_index.py`.
4. **Integration config.** Copy `SSE_Project_share/integration/config.example.json` to
   `config.json` in the same directory and fill in the GoPhish API key from its Settings
   page.

## Procedure

```bash
# 1. Dataset construction (one-time; downloads public corpora)
bash SSE_Project_share/download_raw.sh
python SSE_Project_share/build_dataset.py

# 2. Generation (requires a local Ollama installation)
ollama pull qwen2.5:7b-instruct
python SSE_Project_share/rag/build_index.py
python SSE_Project_share/rag/generate.py "mailbox over quota" --category credential_phishing --difficulty subtle

# 3. Realism evaluation against the reference detector
ollama pull llama3.1:8b
python SSE_Project_share/phishfuzzer_eval/prepare.py --real-risky 50 --benign 100
python SSE_Project_share/phishfuzzer_eval/classify.py --model llama3.1:8b
python SSE_Project_share/phishfuzzer_eval/analyze.py

# 4. Upload selected drafts to GoPhish as templates
cd SSE_Project_share/gophish-v0.12.1-osx-64bit && ./gophish   # note the administrative API key from Settings
export GOPHISH_API_KEY=<key>
python -m integration.bridge push "end-semester feedback pending" --institution "IIT Hyderabad" -n 5
```

Offline unit tests, requiring neither network access nor a model:

```bash
python SSE_Project_share/integration/tests/test_pure.py
```

## Models employed

- `all-MiniLM-L6-v2` — scenario and example embeddings
- `qwen2.5:7b-instruct` (Ollama) — lure generation
- `llama3.1:8b` (Ollama) — realism evaluation
