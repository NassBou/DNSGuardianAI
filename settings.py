import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
os.makedirs(CONFIG_DIR, exist_ok=True)

CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(config: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def get_llm_settings(profile_choice: str | None = None) -> dict:
    """
    Returns selected LLM profile + available profiles
    """
    cfg = load_config()
    llm_cfg = cfg.get("llm", {})
    profiles = llm_cfg.get("profiles", {})
    default_profile = llm_cfg.get("default", "local")

    profile = profile_choice or default_profile
    if profile not in profiles:
        profile = default_profile

    return {
        "profile": profile,
        "profiles": list(profiles.keys()),
        **profiles[profile]
    }

# global reference (used by server.py)
config = load_config()
