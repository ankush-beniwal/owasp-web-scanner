"""
Module: crawler.py
Purpose: Crawl target website to discover all URLs and HTML forms.
         Forms are used by SQLi, XSS, CSRF, and injection modules.
"""

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "WebVulnScanner/1.0 (Educational Pentest Tool)"
}


def get_all_links(url, base_domain, soup):
    """Extract all internal links from a page."""
    links = set()
    for tag in soup.find_all("a", href=True):
        href = urljoin(url, tag["href"])
        parsed = urlparse(href)
        # Only follow links on same domain, ignore fragments
        if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
            links.add(href.split("#")[0])
    return links


def extract_forms(url, soup):
    """
    Extract all HTML forms from a page.
    Returns list of dicts with: url, action, method, inputs
    """
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(url, action) if action else url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_type  = inp.get("type", "text")
            inp_name  = inp.get("name", "")
            inp_value = inp.get("value", "")
            if inp_name:
                inputs.append({
                    "type":  inp_type,
                    "name":  inp_name,
                    "value": inp_value
                })

        if inputs:
            forms.append({
                "url":    url,
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
    return forms


def crawl_site(base_url, depth=2, timeout=5):
    """
    BFS crawl starting from base_url.
    Returns (set of discovered URLs, list of forms found).
    """
    base_domain = urlparse(base_url).netloc
    visited  = set()
    to_visit = {base_url}
    all_forms = []

    for level in range(depth):
        next_level = set()
        for url in to_visit:
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")

                # Collect links for next level
                links = get_all_links(url, base_domain, soup)
                next_level.update(links - visited)

                # Collect forms
                forms = extract_forms(url, soup)
                all_forms.extend(forms)

            except Exception:
                pass

        to_visit = next_level

    return visited, all_forms
