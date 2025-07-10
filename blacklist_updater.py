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

#-----------------------EXTRACT DOMAIN FROM BLACKLIST LINE-----------------------
    def extract_domain(self, line):
        line = line.strip()
        
        if not line or line.startswith(('!', '#', '@@')):
            return None
            
        if line.startswith('||'):
            line = re.split(r'[\^/]', line[2:])[0]
            
        elif line.startswith(('0.0.0.0', '127.0.0.1')):
            parts = line.split()
            if len(parts) > 1:
                line = parts[1]
            else:
                return None

        if '*' in line or line.endswith(('.local', '.lan', '.internal', '.invalid')):
            return None
            
        if re.match(r'^(?!\-)([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', line):
            return line.lower()

        return None

#-----------------------FETCH BLACKLIST FROM REMOTE SOURCE-----------------------
    def fetch_remote_domains(self):
        print(f"Fetching blacklist from {self.blacklist_url}...")
        try:
            response = requests.get(self.blacklist_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error downloading blacklist: {e}")
            return set()

        domains = set()
        for line in response.text.splitlines():
            domain = self.extract_domain(line)
            if domain:
                domains.add(domain)
        return domains

#-----------------------LOAD LOCAL BLACKLIST-----------------------
    def load_local_domains(self):
        if not os.path.exists(self.local_file):
            return set()

        with open(self.local_file, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())

#-----------------------LOAD WHITELIST-----------------------
    def load_whitelist_domains(self):
        if not os.path.exists(self.whitelist_file):
            return set()

        with open(self.whitelist_file, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())

#-----------------------SAVE NEW DOMAINS TO BLACKLIST-----------------------
    def save_new_domains(self, new_domains):
        if not new_domains:
            print("No new domains to add.")
            return

        with open(self.local_file, 'a') as f:
            for domain in sorted(new_domains):
                f.write(domain + '\n')

        print(f"Added {len(new_domains)} new domains to {self.local_file}.")

#-----------------------ADD DOMAINS TO WHITELIST FILE-----------------------
    def add_to_whitelist(self, domains):
        """
        Adds new domains to the whitelist file, avoiding duplicates.
        """
        if not domains:
            print("No domains provided.")
            return

        existing = self.load_whitelist_domains()
        new = set(self.extract_domain(d) for d in domains)
        new = set(d for d in new if d) - existing

        if not new:
            print("No new whitelist domains to add.")
            return

        with open(self.whitelist_file, 'a') as f:
            for domain in sorted(new):
                f.write(domain + '\n')

        print(f"Added {len(new)} new domains to {self.whitelist_file}.")

#-----------------------MAIN UPDATE FUNCTION-----------------------
    def update(self):
        remote_domains = self.fetch_remote_domains()
        local_domains = self.load_local_domains()
        whitelist_domains = self.load_whitelist_domains()

        # Only add domains that are not in local blacklist or whitelist
        filtered_new_domains = remote_domains - local_domains - whitelist_domains

        self.save_new_domains(filtered_new_domains)
