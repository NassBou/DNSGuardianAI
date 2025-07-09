# server.py

from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver

# === CONFIG ===
MODEL = "YOUR_CUSTOM_MODEL"
API_URL = "YOUR_API_URL"
UPSTREAM_DNS_PORT = 53

if __name__ == "__main__":
    resolver = FilteringResolver(model=MODEL, api_url=API_URL)
    server = DNSServer(resolver, port=UPSTREAM_DNS_PORT, address="0.0.0.0")
    print("""
██████╗ ███╗   ██╗███████╗   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗   █████╗    ██╗
██╔══██╗████╗  ██║██╔════╝  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║  ██╔══██╗   ██║
██║  ██║██╔██╗ ██║███████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║  ███████║   ██║
██║  ██║██║╚██╗██║╚════██║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║  ██╔══██║   ██║
██████╔╝██║ ╚████║███████║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║  ██║  ██║██╗██║██╗
╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝╚═╝╚═╝
                                                                                                    """)

    print(f"DNS Guardian listening on port {UPSTREAM_DNS_PORT}...")
    server.start()
