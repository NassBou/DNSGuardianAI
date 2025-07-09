# settings.py

import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(config: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

# Global reference
config = load_config()
