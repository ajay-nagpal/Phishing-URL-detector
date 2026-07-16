import re
from urllib.parse import urlparse

def extract_basic_features(url):

    # Parse the URL into components
    # (scheme, domain, path, query, etc.).
    parsed = urlparse(url)

    # Lowercase copy for case-insensitive checks.
    url_lower = url.lower()

    # Total URL length.
    url_length = len(url)

    # Length of domain (hostname).
    domain_length = len(parsed.netloc)

    # Same as domain length.
    hostname_length = domain_length

    # Length of URL path.
    path_length = len(parsed.path)

    # Length of query string.
    query_length = len(parsed.query)

    # QUERY FEATURES

    # Number of query parameters.
    # Example:
    # id=10&name=test -> 2
    param_count = (
        len(parsed.query.split("&"))
        if parsed.query
        else 0
    )

    # "=" commonly appears in
    # URL parameters.
    has_equal = (1 if "=" in url else 0)

    # "&" separates multiple
    # query parameters.
    has_ampersand = (1 if "&" in url else 0)

    # Portion of URL occupied
    # by the query string.
    query_ratio = (query_length / (url_length + 1))

    # CHARACTER FEATURES

    # Number of dots.
    dots = url.count(".")

    # Number of hyphens.
    hyphens = url.count("-")

    # Number of underscores.
    underscores = url.count("_")

    # Count alphabetic characters.
    letters = sum(c.isalpha() for c in url)

    # Count numeric characters.
    digits = sum(c.isdigit()for c in url)

    # Count special characters.
    special_chars = len(
        re.findall(r"[^a-zA-Z0-9]",url)
    )

    # Ratio of letters.
    letter_ratio = (letters / (url_length + 1))

    # Ratio of digits.
    digit_ratio = (digits / (url_length + 1))

    # Ratio of special characters.
    special_ratio = (special_chars / (url_length + 1))

    # URL STRUCTURE

    # HTTPS indicates encrypted
    # communication.
    https = (1 if parsed.scheme == "https" else 0)

    # Presence of '@' character.
    has_at = (1 if "@" in url else 0)

    # Detect IPv4 address used
    # instead of a domain.
    has_ip = (
        1 if re.search(
            r"\d+\.\d+\.\d+\.\d+",
            parsed.netloc
        )
        else 0
    )

    # Detect extra "//" after
    # the protocol.
    has_double_slash = (1 if "//" in url[8:] else 0)

    # Detect repeated hyphens.
    repeated_hyphen = (1 if "--" in url else 0)

    # Detect repeated special
    # characters.
    repeated_special = len(
        re.findall(r"(\W)\1+",url)
    )

    # Detect HTML pages.
    has_html = (1 if ".html" in url_lower else 0)

    # PATH FEATURES

    # Number of directories
    # in the URL path.
    path_segments = len(
        [segment for segment in parsed.path.split("/")if segment]
    )

    # Long paths are often
    # seen in phishing URLs.
    complex_path = (1 if path_segments > 4 else 0)

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
        "digit_ratio": digit_ratio,
        "special_ratio": special_ratio,

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