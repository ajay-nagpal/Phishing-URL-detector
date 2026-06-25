import requests
import ssl #check certificate
import socket #create connection
import whois 
import dns.resolver

from bs4 import BeautifulSoup
from urllib.parse import urlparse

def extract_internet_features(url):

    features = {}

    parsed = urlparse(url)

    domain = parsed.netloc

    # SSL CERTIFICATE FEATURES
    #Does the real server actually provide a valid certificate?
    try:
        # Create SSL connection with website
        context = ssl.create_default_context()
        
        #open a socket connection to the domain on port 443 (HTTPS)# http port 80
        # prevent resource leak  
        with socket.create_connection(
            (domain,443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

                certificate = ssock.getpeercert()
                # Certificate exists
                features["has_ssl"] = 1

                # Certificate issuer
                if certificate:
                    issuer = certificate["issuer"]
                else:
                    issuer = None

                issuer_text = str(issuer).lower()

                # Detect free/common issuers
                features["ssl_issuer_known"] = (
                    1 if "letsencrypt" in issuer_text
                    else 0
                )
    except Exception:
        # No certificate or failed connection
        features["has_ssl"] = 0
        features["ssl_issuer_known"] = 0


    # DOMAIN AGE FEATURES
    try:
        # Query WHOIS database
        info = whois.whois(domain)

        creation = info.get("creation_date")

        if isinstance(creation,list):
            creation = creation[0]

        if creation:
            from datetime import datetime
            # Calculate how old the domain is
            age_days = (datetime.now()-creation).days

            features["domain_age_days"] = age_days

            # Very new domains are suspicious
            # New domains are more commonly used in phishing
            # Example:
            # age < 180 days → suspicious
            features["new_domain"] = (
                1 if age_days < 180
                else 0
            )
        else:
            # No creation date available
            features["domain_age_days"] = -1
            features["new_domain"] = 1

    except Exception:
        # WHOIS lookup failed
        features["domain_age_days"] = -1
        features["new_domain"] = 1

    
    # DNS FEATURES
    try:
        # Check if domain has DNS records
        dns_records = dns.resolver.resolve(domain,"A")#A record, IPv4 address
        ips = [r.address for r in dns_records]#can have many IPs, IP address stored inside this DNS record
        
        features["dns_exists"] = 1
        # Number of IP addresses
        features["dns_ip_count"] = len(ips)
    except Exception:
        features["dns_exists"] = 0
        features["dns_ip_count"] = 0


    # WEBSITE CONTENT FEATURES
    #what it actually does
    try:
        #fetch website
        #send a req to browser
        response = requests.get(
            url,
            timeout=5
        )

        #Store the raw webpage code as tex
        html = response.text

        #bad sites → unstable status codes
        features["http_status"] = response.status_code

        #page title
        #HTML → readable object
        soup = BeautifulSoup(html,"html.parser")
        # Page title
        title = soup.title.string.lower() if (soup.title and soup.title.string) else ""

        suspicious_words = ["login","verify","password", "account","secure"]
    
        # Detect suspicious title
        features["title_suspicious"] = (
            1 if any(w in title for w in suspicious_words)
            else 0
        )

        # FORM DETECTION

        # Phishing pages usually contain
        # login/password forms
        forms = soup.find_all("form")
        features["form_count"] = len(forms)

        inputs = soup.find_all("input")
        password_fields = [
            i for i in inputs
            if i.get("type")=="password"
        ]

        features["has_password_field"] = (
            1 if len(password_fields)>0 else 0
        )

        # EXTERNAL LINK RATIO
        links = soup.find_all("a")
        external = 0

        for link in links:
            href = link.get("href")
            if href and domain not in href:
                #checking if external site 
                external += 1

        if len(links)>0:
            features["external_link_ratio"] = (
                external / len(links)
            )
        else:
            features["external_link_ratio"] = 0

    except Exception:

        features["http_status"] = 0
        features["title_suspicious"] = 0
        features["form_count"] = 0
        features["has_password_field"] = 0
        features["external_link_ratio"] = 0


    return features