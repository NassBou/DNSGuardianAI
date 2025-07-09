# llm_client.py

import requests
import json
import re
import dns.resolver
import tldextract
from urllib.parse import urlparse

class LLMClient:
    def __init__(self, model: str, api_url: str):
        self.model = model
        self.api_url = api_url
        self.headers = {"Content-Type": "application/json"}


    def _call_llm(self, prompt: str, max_tokens=200) -> dict:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.3
        }

        try:
            response = requests.post(self.api_url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()
            content = response.json()['choices'][0]['message']['content']
            #print(f"[LLM RESPONSE] {content}")

            json_match = re.search(r'\{.*?\}', content, re.DOTALL)
            return json.loads(json_match.group()) if json_match else {"verdict": "Error", "reason": "No JSON"}
        except Exception as e:
            return {"verdict": "Error", "reason": str(e)}

    def phishing_check(self, domain: str, title: str = "") -> dict:
        parsed = urlparse(domain)
        domain = parsed.netloc or domain

        prompt = (
            f"Analyze the domain `{domain}`. "
            f"{'Page title: ' + title + '. ' if title else ''}"
            "Respond ONLY in valid JSON. "
            "Use exactly this format: "
            '{"verdict": "Malicious", "mimics": "example.com"} or {"verdict": "Safe", "mimics": null}. '
            "No extra text."
        )

        result = self._call_llm(prompt)
        verdict = result.get("verdict", "Not Sure")
        mimics = result.get("mimics")

        if verdict == "Malicious" and mimics:
            if not self._compare_ns(domain, mimics):
                return {
                    "verdict": "Likely Phishing",
                    "mimics": mimics,
                    "shared_nameservers": False
                }
            return {
                "verdict": "Possibly Legitimate",
                "mimics": mimics,
                "shared_nameservers": True
            }

        return {
            "verdict": verdict,
            "mimics": mimics
        }

    def san_check(self, domain: str, san_list: list[str]) -> dict:
        if not san_list or len(san_list) <= 1:
            return {"verdict": "Safe", "reason": "Single SAN — normal"}

        domain = domain.lower().strip('.')
        san_str = ', '.join([s.strip('.') for s in san_list])

        prompt = (
            f"A TLS certificate for `{domain}` includes the following SANs: {san_str}. "
            "Is this a legitimate set of names or does it seem suspicious? "
            "Reply ONLY in JSON format: "
            '{"verdict": "Safe", "reason": "..."} or {"verdict": "Suspicious", "reason": "..."}'
        )

        return self._call_llm(prompt)

    # DNS helpers
    def _get_base_domain(self, domain: str) -> str:
        ext = tldextract.extract(domain)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    def _get_authoritative_nameservers(self, domain: str) -> set:
        base_domain = self._get_base_domain(domain)
        try:
            answers = dns.resolver.resolve(base_domain, 'NS')
            return {rdata.to_text().strip('.') for rdata in answers}
        except Exception as e:
            print(f"[NS ERROR] {domain}: {e}")
            return set()

    def _compare_ns(self, domain1: str, domain2: str) -> bool:
        ns1 = self._get_authoritative_nameservers(domain1)
        ns2 = self._get_authoritative_nameservers(domain2)
        print(f"[NS COMPARE] {domain1}: {ns1}, {domain2}: {ns2}")
        return not ns1.isdisjoint(ns2)
