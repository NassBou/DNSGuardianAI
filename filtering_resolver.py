from dnslib.server import BaseResolver
from dnslib import DNSRecord
from domain_analyser import DomainAnalyser
import socket, threading, time, os

from lists import (
    WHITELIST_USER, BLACKLIST_USER,
    WHITELIST_AUTO, BLACKLIST_AUTO
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
LOG_FILE = os.path.join(CONFIG_DIR, "queries.log")


class FilteringResolver(BaseResolver):
    def __init__(self, filtering_enabled, list_only_filtering_enabled,
                 model, api_url, block_score, upstream_dns):
        self.filtering_enabled = filtering_enabled
        self.list_only = list_only_filtering_enabled
        self.analyser = DomainAnalyser(model, api_url, block_score)
        self.upstream = (upstream_dns, 53)
        self.lock = threading.Lock()
        self.in_progress = set()

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        base = qname.lstrip("www.")

        # ---------- Forward-only mode ----------
        if not self.filtering_enabled:
            return self.forward(request)

        # ---------- Load lists ----------
        user_whitelist = self._load(WHITELIST_USER)
        user_blacklist = self._load(BLACKLIST_USER)
        auto_whitelist = self._load(WHITELIST_AUTO)
        auto_blacklist = self._load(BLACKLIST_AUTO)

        # ---------- Resolution priority ----------
        if base in user_whitelist:
            self._log(qname, "allow (user whitelist)")
            return self.forward(request)

        if base in user_blacklist:
            self._log(qname, "block (user blacklist)")
            return self._block(request)

        if base in auto_whitelist:
            self._log(qname, "allow (auto whitelist)")
            return self.forward(request)

        if base in auto_blacklist:
            self._log(qname, "block (auto blacklist)")
            return self._block(request)

        # ---------- List-only mode ----------
        if self.list_only:
            self._log(qname, "allow (list-only)")
            return self.forward(request)

        # ---------- Prevent duplicate analysis ----------
        with self.lock:
            if base in self.in_progress:
                reply = request.reply()
                reply.header.rcode = 2
                return reply
            self.in_progress.add(base)

        try:
            result = self.analyser.analyse(base)
        finally:
            self.in_progress.remove(base)

        if result.get("verdict") == "block":
            self._log(qname, "block (analysis)")
            return self._block(request)

        self._log(qname, "allow (analysis)")
        return self.forward(request)

    # ---------- Helpers ----------

    def forward(self, request):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(request.pack(), self.upstream)
        data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(data)

    def _block(self, request):
        reply = request.reply()
        reply.header.rcode = 3  # NXDOMAIN
        return reply

    def _load(self, path):
        try:
            with open(path) as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def _log(self, qname, verdict):
        with open(LOG_FILE, "a") as f:
            f.write(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {qname} - {verdict}\n"
            )
