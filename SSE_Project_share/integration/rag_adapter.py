"""Thin adapter over rag/generate.py."""
import importlib.util
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN_PATH = os.path.join(ROOT, "rag", "generate.py")

_G = None


def _gen():
    global _G
    if _G is None:
        spec = importlib.util.spec_from_file_location("rag_generate", GEN_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _G = mod
    return _G


@dataclass
class Candidate:
    subject: str
    body: str
    scenario: str
    category: str = None
    risk: str = None
    difficulty: str = "moderate"
    recipient: str = "a student"
    sender: str = None
    institution: str = None
    model: str = None
    temperature: float = None
    seed: int = None
    retrieved_ids: list = field(default_factory=list)
    red_flags: list = field(default_factory=list)


@dataclass
class Corpus:
    df: object
    emb: object
    usable: object
    embedder: object


def load_corpus():
    G = _gen()
    import numpy as np
    import pandas as pd
    from sentence_transformers import SentenceTransformer

    if not os.path.exists(G.INDEX):
        raise SystemExit("rag/index.npz not found - run `python rag/build_index.py` first.")
    df = pd.read_csv(G.CSV).fillna("")
    emb = np.load(G.INDEX)["embeddings"]
    if len(emb) != len(df):
        raise SystemExit("index.npz is out of sync with the CSV - rebuild with build_index.py.")
    usable = G.usable_mask(df)
    embedder = SentenceTransformer(G.EMBED_MODEL, device="cpu")
    return Corpus(df=df, emb=emb, usable=usable, embedder=embedder)


def generate_candidates(corpus, scenario, *, n=3, category=None, risk=None,
                        difficulty="moderate", recipient="a student", sender=None,
                        institution=None, model=None, temperature=0.8, k=4,
                        seed=None, with_red_flags=False):
    """Generate up to n Candidates for one scenario."""
    G = _gen()
    model = model or G.DEFAULT_MODEL
    qvec = corpus.embedder.encode([scenario], normalize_embeddings=True,
                                  convert_to_numpy=True)[0]
    examples = G.retrieve(corpus.df, corpus.emb, qvec, k, corpus.usable, category, risk)
    user = G.build_user_prompt(scenario, examples, difficulty, recipient, sender, institution)
    retrieved_ids = examples["id"].tolist()

    out = []
    for v in range(1, n + 1):
        result = None
        for attempt in range(G.MAX_ATTEMPTS):
            s = None if seed is None else seed + 1000 * v + attempt
            raw = G.chat(model, G.SYSTEM_PROMPT, user, temperature, s)
            result = G.postprocess(raw, institution)
            if result:
                break
        if not result:
            continue
        subject, body = result
        flags = G.red_flags(model, subject, body) if with_red_flags else []
        out.append(Candidate(
            subject=subject, body=body, scenario=scenario, category=category, risk=risk,
            difficulty=difficulty, recipient=recipient, sender=sender, institution=institution,
            model=model, temperature=temperature, seed=seed, retrieved_ids=retrieved_ids,
            red_flags=flags,
        ))
    return out
