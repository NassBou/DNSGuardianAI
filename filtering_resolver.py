# filtering_resolver.py

from dnslib import DNSRecord
from dnslib.server import BaseResolver
import socket
import time
import threading
from domain_analyser import DomainAnalyser
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.txt")
BLACKLIST_FILE = os.path.join(CONFIG_DIR, "blacklist.txt")
LOG_FILE = os.path.join(CONFIG_DIR, "queries.log")

class FilteringResolver(BaseResolver):
    def __init__(self, filtering_enabled:bool, list_only_filtering_enabled:bool, model: str, api_url: str, threshold: int, upstream_dns: str):
        self.filtering_enabled = filtering_enabled
        self.list_only_filtering_enabled = list_only_filtering_enabled
        self.analyser = DomainAnalyser(
            model=model,
            api_url=api_url,
            threshold=threshold
        )
        self.port = 53
        self.upstream_dns = upstream_dns 
        self.in_progress = set()
        self.lock = threading.Lock()
        self.DNS = (self.upstream_dns,self.port)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()

# ----------------- CHECK IF FORWARD ONLY MODE IS ON -----------------
        if not self.filtering_enabled:
            print(f"[FORWARD ONLY MODE] {qname}")
            return self.forward(request)
# ----------------- IF FORWARD ONLY MODE IS ON STOP HERE -----------------
        
        if qname.endswith(".in-addr.arpa"):
            self.log_query(qname, "allow")
            return self.forward(request)

        base_qname = qname.lstrip("www.")

        whitelist = self.load_whitelist()
        blacklist = self.load_blacklist()

        if base_qname in whitelist:
            print(f"[WHITELIST] {base_qname} is whitelisted.")
            self.log_query(qname, "allow")
            return self.forward(request)


        if base_qname in blacklist:
            print(f"[BLACKLIST] {base_qname} is blacklisted — blocking immediately.")
            reply = request.reply()
            reply.header.rcode = 3
            self.log_query(qname, "block")
            return reply
     
        if self.list_only_filtering_enabled:
            print(f"[LIST-ONLY MODE] {qname} not found in lists — forwarding")
            self.log_query(qname, "allow")
            return self.forward(request)
# -------- IF FORWARD LIST-ONLY MODE MODE IS ON STOP HERE ---------
        

#------------------------FURTHER ANALYSIS-------------------------

        #Prevent duplicate concurrent analysis
        with self.lock:
            if base_qname in self.in_progress:
                print(f"[SKIP] Analysis already in progress for {base_qname}")
                reply = request.reply()
                reply.header.rcode = 2
                return reply
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
            self.log_query(qname, "block")
            return reply

        elif analysis["verdict"] == "allow":
            print(f"[ALLOWED] {base_qname} - {analysis['reason']}")
            self.log_query(qname, "allow")
            return self.forward(request)

        else:
            reply = request.reply()
            reply.header.rcode = 3
            print(f"[BLOCKED DEFAULT] {base_qname} - Unexpected verdict")
            self.log_query(qname, "block")
            return reply

#------------------------- DNS FORWARDING -------------------------
    def forward(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(request.pack(), self.DNS)
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        except Exception as e:
            print("Upstream error:", e)
            reply = request.reply()
            reply.header.rcode = 2
            return reply

#------------------------- LOGGING -------------------------
    def log_query(self, qname, verdict):
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {qname} - {verdict}\n")
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
