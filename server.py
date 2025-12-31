from dnslib.server import DNSServer
from filtering_resolver import FilteringResolver
from settings import config
from app import Dashboard
from threading import Thread
from blacklist_updater import BlacklistUpdater

if __name__ == "__main__":
    for url in config["blacklist_urls"]:
        BlacklistUpdater(url).update()

    Thread(target=lambda: Dashboard().start(), daemon=True).start()

    resolver = FilteringResolver(
        filtering_enabled=config["filtering_enabled"],
        list_only_filtering_enabled=not config["advanced_analysis_enabled"],
        model=config["llm"]["profiles"][config["llm"]["active_profile"]]["model"],
        api_url=config["llm"]["profiles"][config["llm"]["active_profile"]]["api_url"],
        block_score=config["block_score"],
        upstream_dns=config["upstream_dns"]
    )

    DNSServer(resolver, port=config["dns_port"]).start()
