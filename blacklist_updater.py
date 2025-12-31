# blacklist_updater.py

import requests
import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

BLACKLIST_FILE = os.path.join(CONFIG_DIR, "blacklist.txt")
WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.txt")

class BlacklistUpdater:
    def __init__(self, blacklist_url, local_file=BLACKLIST_FILE, whitelist_file=WHITELIST_FILE):
        self.blacklist_url = blacklist_url
        self.local_file = local_file
        self.whitelist_file = whitelist_file

    #  NEW — Validate AdGuard-style rules (filter only useful ones)
    def is_valid_rule(self, line):
        line = line.strip()
        if not line or line.startswith('!') or '##' in line or '#@#' in line:
            return False
        return True

    #  MODIFIED — Don't reduce rules to domains, keep raw filter rules
    def fetch_remote_rules(self):
        print(f"Fetching rules from {self.blacklist_url}...")
        try:
            response = requests.get(self.blacklist_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error downloading rules: {e}")
            return set()

        rules = set()
        for line in response.text.splitlines():
            if self.is_valid_rule(line):
                rules.add(line.strip())
        return rules

    #  MODIFIED — load full rules, not just domains
    def load_local_rules(self):
        if not os.path.exists(self.local_file):
            return set()

        with open(self.local_file, 'r') as f:
            return set(line.strip() for line in f if line.strip())

    def load_whitelist_rules(self):
        if not os.path.exists(self.whitelist_file):
            return set()

        with open(self.whitelist_file, 'r') as f:
            return set(line.strip() for line in f if line.strip())

    def save_new_rules(self, new_rules):
        if not new_rules:
            print("No new rules to add.")
            return

        with open(self.local_file, 'a') as f:
            for rule in sorted(new_rules):
                f.write(rule + '\n')

        print(f"Added {len(new_rules)} new rules to {self.local_file}.")

    def add_to_whitelist(self, rules):
        if not rules:
            print("No rules provided.")
            return

        existing = self.load_whitelist_rules()
        new = set(rules) - existing

        if not new:
            print("No new whitelist rules to add.")
            return

        with open(self.whitelist_file, 'a') as f:
            for rule in sorted(new):
                f.write(rule + '\n')

        print(f"Added {len(new)} new rules to {self.whitelist_file}.")

    #  MODIFIED — operate on rules instead of just domains
    def update(self):
        remote_rules = self.fetch_remote_rules()
        local_rules = self.load_local_rules()
        whitelist_rules = self.load_whitelist_rules()

        # Remove already known or whitelisted rules
        filtered_new_rules = remote_rules - local_rules - whitelist_rules

        self.save_new_rules(filtered_new_rules)

