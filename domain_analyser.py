import os
import time
from typing import Optional
from llm_client import LLMClient
from simple_verifier import get_domain_creation_date, is_recent_domain, get_san
from lists import WHITELIST_AUTO, BLACKLIST_AUTO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
os.makedirs(CONFIG_DIR, exist_ok=True)

WHITELIST_FILE = WHITELIST_AUTO
BLACKLIST_FILE = BLACKLIST_AUTO

RESERVED_TLDS = {
    "localhost","test","example","invalid",
    "home","local","corp","internal","lan","intranet","onion"
}

class DomainAnalyser:
    """
    Single source of truth for analysis logic.
    Adds per-check timing metrics.
    """

    def __init__(
        self,
        model: str,
        api_url: str,
        block_score: int = 4,
        *,
        use_blacklists: bool = True,
        timeout: float = 30.0,
        enable_logging: bool = False,
        enable_reasoning_log: bool = False,
        log_dir: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.llm = LLMClient(
            model=model,
            api_url=api_url,
            timeout=timeout,
            enable_logging=enable_logging,
            enable_reasoning_log=enable_reasoning_log,
            log_dir=log_dir,
            api_key=api_key,
        )
        self.block_score = block_score
        self.use_blacklists = use_blacklists

    def analyse(self, domain: str) -> dict:
        t_start = time.perf_counter()

        domain = (domain or "").lower().strip()
        score = 0

        evidence = {
            "llm_verdict": None,
            "recent_domain": None,
            "san_verdict": None,
        }

        timing = {
            "llm_ms": 0.0,
            "whois_ms": 0.0,
            "san_ms": 0.0,
            "total_ms": 0.0,
        }

        # ---------- Reserved TLDs ----------
        tld = domain.split(".")[-1]
        if tld in RESERVED_TLDS:
            verdict = "block" if tld == "onion" else "allow"
            timing["total_ms"] = (time.perf_counter() - t_start) * 1000
            return {
                "verdict": verdict,
                "score": self.block_score if verdict == "block" else 0,
                "evidence": evidence,
                "timing_ms": timing,
            }

        # ---------- LLM phishing ----------
        t0 = time.perf_counter()
        llm = self.llm.phishing_check(domain)
        timing["llm_ms"] = (time.perf_counter() - t0) * 1000

        llm_verdict = llm.get("verdict", "")
        evidence["llm_verdict"] = llm_verdict

        if llm_verdict in {"Malicious", "Likely Phishing"}:
            score += 3
        elif llm_verdict == "Safe":
            timing["total_ms"] = (time.perf_counter() - t_start) * 1000
            return {
                "verdict": "allow",
                "score": 0,
                "evidence": evidence,
                "timing_ms": timing,
            }

        # ---------- WHOIS ----------
        t0 = time.perf_counter()
        try:
            created = get_domain_creation_date(domain)
            recent = bool(created and is_recent_domain(created, 30))
            evidence["recent_domain"] = recent
            if recent:
                score += 3
        finally:
            timing["whois_ms"] = (time.perf_counter() - t0) * 1000

        # ---------- SAN ----------
        t0 = time.perf_counter()
        try:
            sans = get_san(domain) or []
            san = self.llm.san_check(domain, sans)
            san_verdict = san.get("verdict")
            evidence["san_verdict"] = san_verdict
            if san_verdict == "Suspicious":
                score += 1
        finally:
            timing["san_ms"] = (time.perf_counter() - t0) * 1000

        verdict = "block" if score >= self.block_score else "allow"

        timing["total_ms"] = (time.perf_counter() - t_start) * 1000

        return {
            "verdict": verdict,
            "score": score,
            "evidence": evidence,
            "timing_ms": timing,
        }
