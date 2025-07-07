from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
from llmcheck import llmcheck_with_ns
import socket, time
import requests
from bs4 import BeautifulSoup

WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "queries.log"
UPSTREAM_DNS_PORT = 52
UPSTREAM_DNS = ("1.1.1.1", UPSTREAM_DNS_PORT)

# ----------------- Utility Functions -----------------

def load_whitelist():
    with open(WHITELIST_FILE) as f:
        return set(line.strip().lower() for line in f if line.strip())

def load_blacklist():
    with open(BLACKLIST_FILE) as f:
        return set(line.strip().lower() for line in f if line.strip())

def log_query(qname):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {qname}\n")

def fetch_title(domain: str) -> str:
    try:
        url = f"http://{domain}"
        r = requests.get(url, timeout=2)
        soup = BeautifulSoup(r.text, 'html.parser')
        return soup.title.string.strip() if soup.title else ""
    except Exception:
        return ""

# ----------------- DNS Filtering Resolver -----------------

class FilteringResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        log_query(qname)

        # Παράκαμψη reverse DNS (PTR) queries
        if qname.endswith(".in-addr.arpa"):
            return self.forward(request)

        base_qname = qname.lstrip("www.")

        whitelist = load_whitelist()
        blacklist = load_blacklist()

        if base_qname in whitelist:
            print(f"[WHITELIST] {base_qname} is whitelisted.")
            return self.forward(request)

        if base_qname in blacklist:
            print(f"[BLACKLIST] {base_qname} is blacklisted — blocking immediately.")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN (Blocked)
            return reply

        # Προσπάθεια για fetch title (προαιρετικό enrichment)
        title = fetch_title(base_qname)

        result = llmcheck_with_ns(base_qname, title=title)
        verdict = result.get("verdict", "Not Sure")

        print(f"[LLM Verdict] {base_qname}: {verdict} - Reason: {result.get('reason')}")

        # Απόφαση
        if verdict == "Safe":
            self.add_to_whitelist(base_qname)
            return self.forward(request)
        elif verdict in ("Malicious", "Likely Phishing"):
            self.add_to_blacklist(base_qname)
            reply = request.reply()
            reply.header.rcode = 3
            print(f"[BLOCKED] {base_qname} as {verdict}")
            return reply
        else:
            reply = request.reply()
            reply.header.rcode = 3
            print(f"[BLOCKED DEFAULT] {base_qname} - Verdict: {verdict}")
            return reply

    def forward(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(request.pack(), UPSTREAM_DNS)
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        except Exception as e:
            print("Upstream error:", e)
            reply = request.reply()
            reply.header.rcode = 2  # SERVFAIL
            return reply

    def add_to_whitelist(self, domain):
        domain = domain.strip().lower()
        if domain.endswith(".in-addr.arpa") or not domain:
            return
        with open(WHITELIST_FILE, "r") as f:
            whitelist = set(line.strip().lower() for line in f if line.strip())
        if domain not in whitelist:
            with open(WHITELIST_FILE, "a") as f:
                f.write(f"{domain}\n")
            print(f"[WHITELIST ADDED] {domain}")

    def add_to_blacklist(self, domain):
        domain = domain.strip().lower()
        if not domain or domain.endswith(".in-addr.arpa"):
            return
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = set(line.strip().lower() for line in f if line.strip())
        if domain not in blacklist:
            with open(BLACKLIST_FILE, "a") as f:
                f.write(f"{domain}\n")
            print(f"[BLACKLIST ADDED] {domain}")

# ----------------- Server Startup -----------------

if __name__ == "__main__":
    resolver = FilteringResolver()
    server = DNSServer(resolver, port=UPSTREAM_DNS_PORT, address="0.0.0.0")
    print(f"DNS Firewall running on port {UPSTREAM_DNS_PORT}...")
    server.start()
