# server.py

from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver

# === CONFIG ===
MODEL = "Meta-Llama-3-8B-Instruct.Q4_0.gguf"
API_URL = "https://gpt4all.110370.xyz/v1/chat/completions"
UPSTREAM_DNS_PORT = 52

if __name__ == "__main__":
    resolver = FilteringResolver(model=MODEL, api_url=API_URL)
    server = DNSServer(resolver, port=UPSTREAM_DNS_PORT, address="0.0.0.0")
    print(f"DNS Firewall running on port {UPSTREAM_DNS_PORT}...")
    server.start()
