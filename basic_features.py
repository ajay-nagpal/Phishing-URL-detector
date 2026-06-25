# basic_features.py

import re
import math
from urllib.parse import urlparse

def extract_basic_features(url):

    # Split URL into parts
    parsed = urlparse(url)

    url_length = len(url)

    domain_length = len(parsed.netloc)

    path_length = len(parsed.path)

    query_length = len(parsed.query)
    # Count number of parameters in query string
    # Example: id=10&session=abc → 2 parameters
    param_count = len(parsed.query.split("&")) if parsed.query else 0

    # Presence of "=" indicates key-value injection
    has_equal = 1 if "=" in url else 0

    # Presence of "&" indicates multiple parameters
    has_ampersand = 1 if "&" in url else 0

    # Query density (how heavy query is compared to full URL)
    query_ratio = query_length / (len(url) + 1)


    # Number of dots
    dots = url.count(".")

    # Number of "-"
    hyphens = url.count("-")

    # Number of "_"
    underscores = url.count("_")

    # Number of letters
    letters = sum(l.isalpha() for l in url)

    # Special characters
    special_chars = len(
        re.findall(r'[^a-zA-Z0-9]', url)
    )

    letter_ratio = letters / (len(url) + 1)
    special_ratio = special_chars / (len(url) + 1)

    digits = sum(c.isdigit() for c in url)
    digit_ratio = digits / (len(url)+1)

    # HTTPS present?
    https = 1 if parsed.scheme == "https" else 0

    # @ symbol
    has_at = 1 if "@" in url else 0


    # IP address instead of domain
    has_ip = 1 if re.search(
        r"\d+\.\d+\.\d+\.\d+",
        url
    ) else 0

    #Phishing URLs often repeat symbols:
    # Detect repeated special characters
    has_double_slash = 1 if "//" in url[8:] else 0

    # Count repeated hyphens pattern
    repeated_hyphen = 1 if "--" in url else 0

    # Count repeated special symbols (simple heuristic)
    repeated_special = len(re.findall(r'(\W)\1+', url))

    has_html = 1 if ".html" in url.lower() else 0
    hostname_length = len(parsed.netloc)
    # /login/account/verify/security/update/

    path_segments = len([p for p in parsed.path.split("/") if p])
    complex_path = 1 if path_segments > 4 else 0

    return {

        "url_length": url_length,

        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,

        "param_count": param_count,
        "has_equal": has_equal,
        "has_ampersand": has_ampersand,
        "query_ratio": query_ratio,

        "dots": dots,
        "hyphens": hyphens,
        "underscores": underscores,
        "letters_ratio": letter_ratio,
        "special_ratio": special_ratio,
        "digit_ratio": digit_ratio,

        "https": https,
        "has_at": has_at,
        "has_ip": has_ip,
        "has_double_slash": has_double_slash,
        "repeated_hyphen": repeated_hyphen,
        "repeated_special": repeated_special,
        "has_html": has_html,
        "hostname_length": hostname_length,
        "path_segments": path_segments,
        "complex_path": complex_path
    }