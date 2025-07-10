# server.py

from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver
from settings import config
from app import Dashboard
from threading import Thread
from blacklist_updater import BlacklistUpdater

if __name__ == "__main__":
# ----------------- LOAD ALL CONFIG VALUES ----------------- 
    filtering_enabled = config["filtering_enabled"]
    list_only_filtering_enabled = not(config["advanced_analysis_enabled"])
    model = config["model"]
    api_url = config["api_url"]
    port = config["dns_port"]
    upstream_dns = config ["upstream_dns"]
    threshold = config["broken_link_threshold"]
    blacklist_urls = config["blacklist_urls"]

# ----------------- UPDATE LISTS ---------------------------
    for blacklist_url in blacklist_urls:
        updater = BlacklistUpdater(blacklist_url)
        updater.update()
        

# ----------------- LAUNCH DASHBOARD ----------------------
    Thread(target=lambda: Dashboard().start(), daemon=True).start()

# ----------------- START THE SERVER ----------------------
    resolver = FilteringResolver(filtering_enabled=filtering_enabled, list_only_filtering_enabled=list_only_filtering_enabled, model=model, api_url=api_url, threshold=threshold, port=port, upstream_dns=upstream_dns)
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
