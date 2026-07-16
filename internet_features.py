import requests
import ssl
import socket
import whois
import dns.resolver

from multiprocessing import Process, Queue

from typing import Any
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Reuse one HTTP session for all requests.
# This improves performance by reusing TCP
# connections instead of opening a new
# connection for every URL.
SESSION = requests.Session()

SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 "
        "(Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/125.0 Safari/537.36"
    )
})
# Reuse one SSL context.
# Creating an SSL context is relatively
# expensive, so reuse the same one.
SSL_CONTEXT = ssl.create_default_context()

# Reuse one DNS resolver.
# Timeout prevents slow DNS lookups from
# blocking feature extraction.
RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 10
RESOLVER.lifetime = 10

# Cache lookup results.
# Many URLs belong to the same domain, so
# avoid repeating expensive SSL, WHOIS and
# DNS requests.
SSL_CACHE = {}      # domain -> (has_ssl, ssl_issuer_known)
WHOIS_CACHE = {}
DNS_CACHE = {}

# Worker process used for WHOIS lookups.
# WHOIS can block indefinitely, so it is run
# inside a separate process.
def _whois_worker(domain, queue):
    try:
        info = whois.whois(domain)
        queue.put(info)
    except Exception:
        queue.put(None)

# Safe WHOIS lookup.
# Terminates the worker process if it exceeds
# the specified timeout.
def whois_lookup(domain, timeout=10):

    queue = Queue()

    process = Process(
        target=_whois_worker,
        args=(domain, queue),
        daemon=True
    )

    process.start()
    try:
        process.join(timeout)
        if process.is_alive():

            process.terminate()
            process.join()
            return None

        if queue.empty():
            return None
        return queue.get()
    finally:

        if process.is_alive():
            process.terminate()
            process.join()

# Extract internet-based features.
# These require network communication such as
# SSL, WHOIS, DNS and website requests.
def extract_internet_features(url):

    # Default values.
    # If any lookup fails or times out,
    # keep "None" instead of raising an error.
    features: dict[str, Any] = {

        "has_ssl": "None",
        "ssl_issuer_known": "None",

        "domain_age_days": "None",
        "new_domain": "None",

        "dns_exists": "None",
        "dns_ip_count": "None",

        "http_status": "None",
        "title_suspicious": "None",
        "form_count": "None",
        "has_password_field": "None",
        "external_link_ratio": "None"
    }

    # Extract hostname from URL.
    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        return features

    # SSL FEATURES
    # Reuse cached SSL information if available.
    if domain in SSL_CACHE:

        has_ssl, issuer_known = SSL_CACHE[domain]

        features["has_ssl"] = has_ssl
        features["ssl_issuer_known"] = issuer_known

    else:
        try:
            # Attempt SSL connection on port 443.
            with socket.create_connection(
                (domain, 443),
                timeout=10
            ) as sock:

                with SSL_CONTEXT.wrap_socket(
                    sock,
                    server_hostname=domain
                ) as ssock:

                    certificate = ssock.getpeercert()

                    issuer = (
                        certificate.get("issuer")
                        if certificate
                        else None
                    )

                    issuer_text = str(issuer).lower()

                    # LetsEncrypt is treated as a
                    # recognised certificate issuer.
                    issuer_known = (
                        1 if "letsencrypt" in issuer_text else 0
                    )

                    features["ssl_issuer_known"] = issuer_known
        except Exception:
            # SSL lookup failed.
            pass

    # DOMAIN AGE (WHOIS)
    try:
        # Use cached WHOIS data whenever possible.
        if domain in WHOIS_CACHE:

            info = WHOIS_CACHE[domain]
        else:

            info = whois_lookup(
                domain,
                timeout=10
            )
            if info is not None:
                WHOIS_CACHE[domain] = info

        if info is not None:
            creation = info.get("creation_date")

            # Some WHOIS servers return multiple
            # creation dates.
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                # Remove timezone to avoid datetime
                # subtraction errors.
                if creation.tzinfo is not None:
                    creation = creation.replace(
                        tzinfo=None
                    )

                age_days = (
                    datetime.now() - creation
                ).days

                features["domain_age_days"] = age_days
                # Domains younger than
                # 180 days are considered
                # potentially suspicious.
                features["new_domain"] = (1 if age_days < 180 else 0)
    except Exception:
        pass

    # DNS FEATURES
    # Reuse cached DNS lookup if available.
    if domain in DNS_CACHE:

        dns_exists, ip_count = DNS_CACHE[domain]

        features["dns_exists"] = dns_exists
        features["dns_ip_count"] = ip_count
    else:
        try:
            # Resolve IPv4 addresses.
            records = RESOLVER.resolve(
                domain,
                "A"
            )
            ips = [
                record.address
                for record in records
            ]
            features["dns_exists"] = 1
            features["dns_ip_count"] = len(ips)

        except Exception:
            pass
        # Cache successful lookups.
        if features["dns_exists"] != "None":

            DNS_CACHE[domain] = (
                features["dns_exists"],
                features["dns_ip_count"]
            )
    
    # WEBSITE FEATURES
    response = None
    try:
        # Download the webpage.
        response = SESSION.get(
            url,
            timeout=(10, 10)
        )
    except requests.RequestException:

        # Retry HTTPS if HTTP fails.
        if url.startswith("http://"):
            try:
                https_url = url.replace(
                    "http://",
                    "https://",
                    1
                )
                response = SESSION.get(
                    https_url,
                    timeout=(10, 10)
                )
            except requests.RequestException:
                pass

    if response is not None:

        # Determine whether HTTPS was ultimately used.
        if response.url.startswith("https://"):
            features["has_ssl"] = 1
        else:
            features["has_ssl"] = 0

        # Cache SSL information after the request.
        if (
            domain not in SSL_CACHE
            or (
                SSL_CACHE[domain][1] == "None"
                and features["ssl_issuer_known"] != "None"
            )
        ):
            SSL_CACHE[domain] = (
                features["has_ssl"],
                features["ssl_issuer_known"]
            )

        # Store HTTP status code.
        features["http_status"] = response.status_code

        # Only analyse successful responses.
        if response.ok:
            try:
                soup = BeautifulSoup(
                    response.text,
                    "html.parser"
                )

                # Extract page title.
                title = (
                    soup.title.string.lower()
                    if soup.title and soup.title.string
                    else ""
                )
                # Words frequently found on
                # phishing pages.
                suspicious_words = [
                    "login","verify","password",
                    "account","secure"
                ]
        
                features["title_suspicious"] = (
                    1 if any(
                        word in title
                        for word in suspicious_words
                    ) else 0
                )

                # Count HTML forms.
                forms = soup.find_all("form")
                features["form_count"] = len(forms)

                # Count password fields.
                inputs = soup.find_all("input")

                password_fields = [
                    i
                    for i in inputs
                    if i.get("type") == "password"
                ]

                features["has_password_field"] = (
                    1 if len(password_fields) > 0 else 0
                )

                # Count external hyperlinks.
                links = soup.find_all("a")

                external = 0

                for link in links:

                    href = link.get("href")

                    # Ignore invalid values.
                    if not isinstance(href, str):
                        continue

                    # Ignore anchors.
                    if href.startswith("#"):
                        continue

                    # Ignore relative links.
                    if href.startswith("/"):
                        continue

                    # Ignore JavaScript links.
                    if href.startswith("javascript:"):
                        continue

                    # Ignore email links.
                    if href.startswith("mailto:"):
                        continue

                    parsed_href = urlparse(href)

                    # External link belongs to
                    # another domain.
                    if (
                        parsed_href.netloc
                        and parsed_href.hostname != domain
                    ):
                        external += 1

                if len(links) > 0:

                    features["external_link_ratio"] = (
                        external / len(links)
                    )
                else:
                    features["external_link_ratio"] = 0

            except Exception:
                pass
            
    return features