import tldextract
import re
import math
from urllib.parse import urlparse

def extract_advanced_features(url):

    # urlparse splits URL into:
    # scheme, domain (netloc), path, query, etc.
    parsed = urlparse(url)

    # tldextract gives accurate domain parsing using public suffix list
    # Example: login.google.com
    # subdomain = login
    # domain = google
    # suffix = com
    ext = tldextract.extract(url)

    subdomain = ext.subdomain
    domain = ext.domain
    tld = ext.suffix

    # Rebuild full registered domain (domain + TLD)
    registered_domain = f"{domain}.{tld}" if domain and tld else domain

    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    
    # Flag: too many subdomains often indicate phishing
    many_subdomains = 1 if subdomain_count > 2 else 0

    # SUSPICIOUS WORDS
    words = [
        "login", "verify", "secure",
        "update", "bank", "account",
        "password", "confirm"
    ]
    # Phishing URLs often contain urgent/security-related words
    suspicious_words = sum(
        1 for w in words if w in url.lower()
    )
    is_suspicious_tld = 1 if tld in [
        "xyz", "top", "click", "gq", "cf", "ml", "tk"
    ] else 0

    is_trusted_tld = 1 if tld in [
        "com", "org", "net", "edu", "gov"
    ] else 0

    tld_unknown = 1 if (
        is_suspicious_tld == 0 and is_trusted_tld == 0
    ) else 0
    
    has_suspicious_word = 1 if suspicious_words > 0 else 0

    brands = ["paypal", "google", "apple", "amazon", "microsoft", "facebook"]

    brand_in_subdomain = any(b in subdomain.lower() for b in brands)
    brand_in_domain = any(b in domain.lower() for b in brands)

    spoofed_brand = 1 if brand_in_subdomain or brand_in_domain else 0

    #login.secure.bank.paypal.verify.xyz
    deep_subdomain = 1 if subdomain_count >= 3 else 0
    very_deep_subdomain = 1 if subdomain_count >= 4 else 0

    # PATH FEATURES

    # Detect PHP-based pages (common in phishing kits)
    php_page = 1 if ".php" in url.lower() else 0

    # Long path often indicates deep fake login pages
    long_path = 1 if len(parsed.path) > 50 else 0

    # Number of directories in URL path
    path_depth = parsed.path.count("/")

    # URL encoding (%xx) used to hide malicious content
    url_encoded = 1 if "%" in url else 0

    at_index = url.find("@")
    redirect_masking = 1 if at_index > 0 else 0

    # Randomness of URL
    probability = [
        url.count(c)/len(url)
        for c in set(url)
    ]

    entropy = -sum(
        p * math.log2(p)
        for p in probability
    )
    at_index = url.find("@")
    has_valid_auth = parsed.username != ""

    # @ exists in URL, but NOT used for proper authentication
    has_at_misuse = 1 if (at_index > 0 and not has_valid_auth) else 0

    return {

    "subdomain": subdomain,
    "domain": domain,
    "tld": tld,
    "registered_domain": registered_domain,

    "subdomain_count": subdomain_count,
    "many_subdomains": many_subdomains,

    "suspicious_words": suspicious_words,
    "has_suspicious_word": has_suspicious_word,

    "spoofed_brand": spoofed_brand,
    "deep_subdomain": deep_subdomain,
    "very_deep_subdomain": very_deep_subdomain,

    "php_page": php_page,
    "long_path": long_path,
    "path_depth": path_depth,

    "url_encoded": url_encoded,
    "entropy": entropy,
    "redirect_masking": redirect_masking,
    "has_at_misuse": has_at_misuse

}