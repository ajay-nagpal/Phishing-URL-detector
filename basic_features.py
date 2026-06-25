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


    # Number of dots
    dots = url.count(".")

    # Number of "-"
    hyphens = url.count("-")

    # Number of "_"
    underscores = url.count("_")

    # Number of digits
    digits = sum(d.isdigit() for d in url)

    # Number of letters
    letters = sum(l.isalpha() for l in url)

    # Special characters
    special_chars = len(
        re.findall(r'[^a-zA-Z0-9]', url)
    )

    # HTTPS present?
    https = 1 if parsed.scheme == "https" else 0

    # @ symbol
    has_at = 1 if "@" in url else 0


    # IP address instead of domain
    has_ip = 1 if re.search(
        r"\d+\.\d+\.\d+\.\d+",
        url
    ) else 0


    # Randomness of URL
    probability = [
        url.count(c)/len(url)
        for c in set(url)
    ]

    entropy = -sum(
        p * math.log2(p)
        for p in probability
    )

    return {

        "url_length": url_length,

        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,

        "dots": dots,
        "hyphens": hyphens,
        "underscores": underscores,

        "digits": digits,
        "letters": letters,
        "special_chars": special_chars,

        "https": https,
        "has_at": has_at,
        "has_ip": has_ip,

        "entropy": entropy
    }