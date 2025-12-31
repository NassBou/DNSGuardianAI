import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
os.makedirs(CONFIG_DIR, exist_ok=True)

WHITELIST_USER = os.path.join(CONFIG_DIR, "whitelist_user.txt")
BLACKLIST_USER = os.path.join(CONFIG_DIR, "blacklist_user.txt")
WHITELIST_AUTO = os.path.join(CONFIG_DIR, "whitelist_auto.txt")
BLACKLIST_AUTO = os.path.join(CONFIG_DIR, "blacklist_auto.txt")
