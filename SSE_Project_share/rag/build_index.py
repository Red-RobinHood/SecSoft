"""Build the sentence-embedding retrieval index over the academic risky emails CSV."""
import os

import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "dataset", "academic_risky_emails.csv")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.npz")

MODEL_NAME = "all-MiniLM-L6-v2"
MAX_CHARS = 1200


def doc_text(row):
    body = (row["body"] or "")[:MAX_CHARS]
    return f"{row['subject']}\n{body}"


def main():
    df = pd.read_csv(CSV)
    df = df.fillna("")
    print(f"loaded {len(df)} rows from {CSV}")

    model = SentenceTransformer(MODEL_NAME)
    texts = [doc_text(r) for _, r in df.iterrows()]
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=True,
        normalize_embeddings=True,
        convert_to_numpy=True,
    )

    np.savez_compressed(OUT, embeddings=embeddings.astype(np.float32), model=MODEL_NAME)
    print(f"saved {embeddings.shape} embeddings to {OUT}")


if __name__ == "__main__":
    main()
