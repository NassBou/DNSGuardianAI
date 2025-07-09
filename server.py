# server.py

from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver
from settings import config
from app import Dashboard
from threading import Thread

if __name__ == "__main__":
    # Load all config values
    filtering_enabled = config["filtering_enabled"]
    model = config["model"]
    api_url = config["api_url"]
    port = config["dns_port"]
    upstream_dns = config ["upstream_dns"]
    threshold = config["broken_link_threshold"]

    # Launch dashboard
    Thread(target=lambda: Dashboard().start(), daemon=True).start()

    # Pass all necessary values to FilteringResolver
    resolver = FilteringResolver(filtering_enabled=filtering_enabled, model=model, api_url=api_url, threshold=threshold, port=port, upstream_dns=upstream_dns)
    server = DNSServer(resolver, port=port)
    print("""
██████╗ ███╗   ██╗███████╗   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗   █████╗ ██╗
██╔══██╗████╗  ██║██╔════╝  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║  ██╔══██╗██║
██║  ██║██╔██╗ ██║███████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║  ███████║██║
██║  ██║██║╚██╗██║╚════██║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║  ██╔══██║██║
██████╔╝██║ ╚████║███████║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║  ██║  ██║██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝
                                                                                                    """)

    print(f"DNS Guardian listening on port {port}...")
    server.start()
