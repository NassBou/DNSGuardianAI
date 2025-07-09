# server.py

from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver

# === CONFIG ===
MODEL = "Add-Model-Here"
API_URL = "Add-API_url-Here"
UPSTREAM_DNS_PORT = 53

if __name__ == "__main__":
    resolver = FilteringResolver(model=MODEL, api_url=API_URL)
    server = DNSServer(resolver, port=UPSTREAM_DNS_PORT, address="0.0.0.0")
    print(f"DNS Firewall running on port {UPSTREAM_DNS_PORT}...")
    server.start()
