import re
import requests
from pysafebrowsing import SafeBrowsing
from urllib.parse import urlparse
from collections import Counter

def check_url(url):
    if "http://" in url or "https://" in url:
        return is_phishing_url(url)
    else:
        return is_phishing_url(f"http://{url}")

def is_phishing_url(url):
    safeBrowse = SafeBrowsing("api_key") # Google Safe Browsing API Key
    result = safeBrowse.lookup_urls([url])
    if result and result[url]["malicious"]:
        return True

    parsed_url = urlparse(url)

    suspicious_domains = ["phishing", "hack", "malicious", "reward", "deal", "@", "-"]
    for domain in suspicious_domains:
        if domain in parsed_url.netloc:
            return True
    
    count = Counter(url)
    if count["."] > 3:
        return True

    suspicious_keywords = ["login", "password", "account", "verify", "reward", "deal", "@", "-", "."]
    for keyword in suspicious_keywords:
        if keyword in parsed_url.path:
            return True

    ip_pattern = re.compile(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    )
    if ip_pattern.match(parsed_url.netloc):
        return True

    if len(url) > 100:
        return True

    return False

