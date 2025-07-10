# simple_verifier.py

import requests
import ssl
import socket
import whois
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ----------------- SSL CERTIFICATE (SAN) -----------------

def get_san(hostname, port=443):
    """
    Extract Subject Alternative Names (SANs) from an SSL certificate.
    Returns a list of domain names or None if no certificate.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = ext.value.get_values_for_type(x509.DNSName)
                return sans
    except Exception as e:
        print(f"[SAN ERROR] {hostname}: {e}")
        return None

# ----------------- WHOIS CREATION DATE -----------------

def get_domain_creation_date(hostname):
    """
    Returns a datetime object for the domain's creation date.
    Returns None if not found or WHOIS lookup fails.
    """
    try:
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = min(created)
        return created
    except Exception as e:
        print(f"[WHOIS ERROR] {hostname}: {e}")
        return None

# ----------------- AGE CHECK -----------------

def is_recent_domain(created_date, months=6):
    """
    Returns True if the domain was registered within the last `months`.
    Treats None (unknown date) as suspicious (returns True).
    """
    if not created_date:
        return True  # Unknown date → treat as recent/suspicious
    now = datetime.now(timezone.utc)
    if created_date.tzinfo is None:
        created_date = created_date.replace(tzinfo=timezone.utc)
    age = now - created_date
    return age.days < (months * 30)

#--------------------- SITE ELEMENTS -----------------
def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https')
    except:
        return False

def check_url_status(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.status_code
    except requests.RequestException:
        return None

def find_broken_links(site_url):
    broken_links = []
    try:
        page = requests.get(site_url, timeout=10)
        soup = BeautifulSoup(page.text, 'html.parser')

        tags = {
            'a': 'href',
            'img': 'src',
            'script': 'src',
            'link': 'href'
        }

        for tag, attr in tags.items():
            for element in soup.find_all(tag):
                url = element.get(attr)
                if not url:
                    continue
                full_url = urljoin(site_url, url)
                if is_valid_url(full_url):
                    status = check_url_status(full_url)
                    if status is None or status >= 400:
                        broken_links.append((full_url, status))
    except requests.RequestException as e:
        print(f"Failed to load site: {e}")
    
    return broken_links
