#Ζητάμε από το LLM αν το domain μοιάζει με κάποιο γνωστό site.
#Αν μας απαντήσει ότι "μοιάζει με x site", επαληθεύουμε αν εξυπηρετείται από τον ίδιο authoritative NS με αυτό.
#Αν όχι, ενισχύεται η υποψία phishing.
import requests
import json
import re
import dns.resolver
import tldextract
from urllib.parse import urlparse

# CONFIG
MODEL = "Meta-Llama-3-8B-Instruct.Q4_0.gguf"
API_URL = "https://gpt4all.110370.xyz/v1/chat/completions"

# -------------------- DNS HELPERS --------------------

def get_base_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

def get_authoritative_nameservers(domain: str) -> set[str]:
    base_domain = get_base_domain(domain)
    try:
        answers = dns.resolver.resolve(base_domain, 'NS')
        return {rdata.to_text().strip('.') for rdata in answers}
    except Exception as e:
        print(f"Error resolving NS for {domain} (base: {base_domain}): {e}")
        return set()

def compare_ns(domain1: str, domain2: str) -> bool:
    ns1 = get_authoritative_nameservers(domain1)
    ns2 = get_authoritative_nameservers(domain2)

    print(f"NS for {domain1}: {ns1}")
    print(f"NS for {domain2}: {ns2}")

    return not ns1.isdisjoint(ns2)

# -------------------- LLM + NS CHECK --------------------

def llmcheck_with_ns(website: str, title: str = "") -> dict:
    # Καθαρό domain
    parsed = urlparse(website)
    domain = parsed.netloc or website
    # Prompt
    if title=="":
        question = (
            f"Analyze the domain `{domain}`. Respond ONLY in valid JSON. "
            "Use exactly this format: "
            '{"verdict": "Malicious", "mimics": "example.com"} or {"verdict": "Safe", "mimics": null}. '
            "Do not explain. No extra text."
        )
    else:
        question = (
            f"Analyze the website domain: `{domain}`. Respond ONLY in valid JSON. "
            f"{'Page title: ' + title + '. ' if title else ''}"
            "Use exactly this format: "
            '{"verdict": "Malicious", "mimics": "example.com"} or {"verdict": "Safe", "mimics": null}. '
            "Do not explain. No extra text."
        )

    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": question}],
        "max_tokens": 150,
        "temperature": 0.3
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()
        content = result['choices'][0]['message']['content']

        #DEBUG
        print(f"[LLM] Raw response: {content}")

        json_match = re.search(r'\{.*?\}', content, re.DOTALL)
        if not json_match:
            return {"verdict": "Not Sure", "reason": "LLM gave no JSON"}

        data = json.loads(json_match.group())
        verdict = data.get("verdict", "Not Sure")
        mimics = data.get("mimics")

        # Extra validation
        if verdict == "Malicious" and mimics:
            same_ns = compare_ns(domain, mimics)

            #DEBUG
            print(f"[NS Check] Shared nameservers with {mimics}: {same_ns}")

            return {
                "verdict": "Likely Phishing" if not same_ns else "Possibly Legitimate",
                "mimics": mimics,
                "shared_nameservers": same_ns
            }

        return {
            "verdict": verdict,
            "mimics": mimics
        }

    except Exception as e:
        return {"verdict": "Error", "reason": str(e)}

