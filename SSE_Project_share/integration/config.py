"""Config for the gophish integration bridge."""
import json
import os
from dataclasses import dataclass, fields

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_JSON = os.path.join(HERE, "config.json")

SELECTION_POLICIES = ("all", "evaded", "best_of_n", "caught")


@dataclass
class Config:
    gophish_base_url: str = "https://127.0.0.1:3333"
    gophish_api_key: str = ""
    gophish_verify_tls: bool = False
    cert_path: str = ""

    gen_model: str = "qwen2.5:7b-instruct"
    temperature: float = 0.8
    k: int = 4
    n: int = 3

    detector_backend: str = "ollama"
    detector_model: str = "llama3.1:8b"
    detector_temperature: float = 0.0
    detector_modes: tuple = ("basic", "full")
    detector_runs: int = 1

    selection_policy: str = "all"
    inject_url: bool = True
    inject_tracking: bool = True
    envelope_sender_default: str = "no-reply@training.invalid"

    def validate(self):
        if self.selection_policy not in SELECTION_POLICIES:
            raise ValueError(
                f"selection_policy must be one of {SELECTION_POLICIES}, got {self.selection_policy!r}"
            )
        if self.detector_backend not in ("ollama", "openrouter"):
            raise ValueError("detector_backend must be 'ollama' or 'openrouter'")
        return self


_ENV = {
    "GOPHISH_URL": ("gophish_base_url", str),
    "GOPHISH_API_KEY": ("gophish_api_key", str),
    "GOPHISH_CERT": ("cert_path", str),
    "BRIDGE_GEN_MODEL": ("gen_model", str),
    "BRIDGE_DET_BACKEND": ("detector_backend", str),
    "BRIDGE_DET_MODEL": ("detector_model", str),
}


def _coerce(field_name, raw):
    typ = {f.name: f.type for f in fields(Config)}[field_name]
    if typ is bool or typ == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if typ is int or typ == "int":
        return int(raw)
    if typ is float or typ == "float":
        return float(raw)
    if typ is tuple or typ == "tuple":
        if isinstance(raw, (list, tuple)):
            return tuple(raw)
        return tuple(s.strip() for s in str(raw).split(",") if s.strip())
    return str(raw)


def load_config(cli_overrides=None, config_path=CONFIG_JSON):
    cfg = Config()
    valid = {f.name for f in fields(Config)}

    if config_path and os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as fh:
            data = json.load(fh)
        for key, raw in data.items():
            if key in valid:
                setattr(cfg, key, _coerce(key, raw))

    for env_name, (field_name, _caster) in _ENV.items():
        if os.environ.get(env_name):
            setattr(cfg, field_name, _coerce(field_name, os.environ[env_name]))

    for key, val in (cli_overrides or {}).items():
        if val is not None and key in valid:
            setattr(cfg, key, val)

    return cfg.validate()
