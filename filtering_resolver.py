# filtering_resolver.py

from dnslib import DNSRecord
from dnslib.server import BaseResolver
import socket
import time
import threading
from domain_analyser import DomainAnalyser

WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "queries.log"
UPSTREAM_DNS_PORT = 52
UPSTREAM_DNS = ("1.1.1.1", UPSTREAM_DNS_PORT)


class FilteringResolver(BaseResolver):
    def __init__(self, model: str, api_url: str):
        self.analyser = DomainAnalyser(model=model, api_url=api_url)
        self.in_progress = set()
        self.lock = threading.Lock()

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        self.log_query(qname)

        if qname.endswith(".in-addr.arpa"):
            return self.forward(request)

        base_qname = qname.lstrip("www.")

        whitelist = self.load_whitelist()
        blacklist = self.load_blacklist()

        if base_qname in whitelist:
            print(f"[WHITELIST] {base_qname} is whitelisted.")
            return self.forward(request)

        if base_qname in blacklist:
            print(f"[BLACKLIST] {base_qname} is blacklisted — blocking immediately.")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            return reply

        # Prevent duplicate concurrent analysis
        with self.lock:
            if base_qname in self.in_progress:
                print(f"[SKIP] Analysis already in progress for {base_qname}")
                reply = request.reply()
                reply.header.rcode = 2  # SERVFAIL
                return reply
            else:
                self.in_progress.add(base_qname)

        try:
            analysis = self.analyser.analyse(base_qname)
        finally:
            with self.lock:
                self.in_progress.discard(base_qname)

        if analysis["verdict"] == "block":
            reply = request.reply()
            reply.header.rcode = 3
            print(f"[BLOCKED] {base_qname} - {analysis['reason']}")
            return reply

        elif analysis["verdict"] == "allow":
            print(f"[ALLOWED] {base_qname} - {analysis['reason']}")
            return self.forward(request)

        else:
            reply = request.reply()
            reply.header.rcode = 3
            print(f"[BLOCKED DEFAULT] {base_qname} - Unexpected verdict")
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

    def log_query(self, qname):
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {qname}\n")
        except Exception as e:
            print(f"[LOGGING ERROR] Failed to log {qname}: {e}")

    def load_whitelist(self):
        try:
            with open(WHITELIST_FILE) as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def load_blacklist(self):
        try:
            with open(BLACKLIST_FILE) as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            return set()
