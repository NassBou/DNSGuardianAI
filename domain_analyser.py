# domain_analyser.py


import requests
from bs4 import BeautifulSoup
from llm_client import LLMClient
from simple_verifier import (
    get_san,
    get_domain_creation_date,
    is_recent_domain,
    find_broken_links
)

WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"
RESERVED_TLDS = {"localhost", "test", "example", "invalid", "home", "local", "corp", "internal", "onion" }

class DomainAnalyser:
    def __init__(self, model: str, api_url: str, threshold: int = 1):
        self.llm = LLMClient(model=model, api_url=api_url)
        self.threshold = threshold

    def is_reserved_tld(self, domain: str) -> bool:
        domain = domain.strip().lower()
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        tld = parts[-1]
        return tld in RESERVED_TLDS

    def analyse(self, base_qname: str, threshold=4) -> dict:

#------------------------- DON'T BOTHER ANALYSING RESERVED TLDs -------------------------
        if self.is_reserved_tld(base_qname):
            return {
                "verdict": "allow",
                "reason": "Reserved TLD"
            }

        title = self.fetch_title(base_qname)
        result = self.llm.phishing_check(base_qname, title=title)
        verdict = result.get("verdict", "Not Sure")

        print(f"[LLM Verdict] {base_qname}: {verdict} - Reason: {result.get('reason')}")

        if verdict == "Safe":
            self.add_to_whitelist(base_qname)
            return {
                "verdict": "allow",
                "reason": "LLM marked as Safe"
            }
            
#-------------------------WHOIS CHECK -------------------------
        created = get_domain_creation_date(base_qname)
        if is_recent_domain(created):
            self.add_to_blacklist(base_qname)
            return {
                "verdict": "block",
                "reason": f"Domain recently registered ({created})",
                "source": "whois"
            }
            
#-----------------------BROKEN LINK CHECK -----------------------
        try:
            broken_links = find_broken_links(f"http://{base_qname}")
            if len(broken_links) > self.threshold:
                self.add_to_blacklist(base_qname)
                return {
                    "verdict": "block",
                    "reason": f"Too many broken links ({len(broken_links)})",
                    "source": "links"
                }
        except Exception as e:
            print(f"[LINK CHECK ERROR] {base_qname} - {e}")

        # SAN check
        sans = get_san(base_qname)
        san_verdict = self.llm.san_check(base_qname, sans or [])
        if san_verdict.get("verdict") == "Suspicious":
            self.add_to_blacklist(base_qname)
            return {
                "verdict": "block",
                "reason": f"SANs suspicious: {san_verdict.get('reason')}",
                "source": "san"
            }

#-----------------------ALL CHECKS PASSED -----------------------
        self.add_to_whitelist(base_qname)
        return {
            "verdict": "allow",
            "reason": "Passed all secondary checks"
        }

#-----------------------GET WEBSITE TITLE-----------------------
    def fetch_title(self, domain: str) -> str:
        try:
            url = f"http://{domain}"
            r = requests.get(url, timeout=2)
            soup = BeautifulSoup(r.text, 'html.parser')
            return soup.title.string.strip() if soup.title else ""
        except Exception:
            return ""

#-----------------------LIST MANAGEMENT -----------------------
    def add_to_whitelist(self, domain):
        self._update_list_file(WHITELIST_FILE, domain, label="WHITELIST")

    def add_to_blacklist(self, domain):
        self._update_list_file(BLACKLIST_FILE, domain, label="BLACKLIST")

    def _update_list_file(self, filename, domain, label="LIST"):
        domain = domain.strip().lower()
        if not domain or domain.endswith(".in-addr.arpa"):
            return
        try:
            with open(filename, "r") as f:
                items = set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            items = set()
        if domain not in items:
            with open(filename, "a") as f:
                f.write(f"{domain}\n")
            print(f"[{label} ADDED] {domain}")
