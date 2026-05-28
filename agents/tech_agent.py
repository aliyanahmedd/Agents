"""Tech Stack Detection Agent — reads HTTP headers and HTML meta tags."""
import re
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

# Header → technology mapping
HEADER_SIGNATURES = {
    "x-powered-by": lambda v: v,
    "server": lambda v: v,
    "x-generator": lambda v: v,
    "x-drupal-cache": lambda _: "Drupal",
    "x-wp-total": lambda _: "WordPress",
    "x-shopify-stage": lambda _: "Shopify",
}

# HTML pattern → technology
HTML_SIGNATURES = {
    r'wp-content|wp-includes': "WordPress",
    r'Drupal\.settings': "Drupal",
    r'Joomla': "Joomla",
    r'__NEXT_DATA__': "Next.js",
    r'ng-version': "Angular",
    r'data-reactroot|__reactFiber': "React",
    r'id="__nuxt"': "Vue/Nuxt",
    r'laravel_session': "Laravel",
    r'csrfmiddlewaretoken': "Django",
    r'railsenv': "Ruby on Rails",
}


class TechAgent:
    def run(self, domain: str) -> dict:
        log_info(f"[TechAgent] Detecting tech stack for {domain}")
        tech = {"technologies": [], "headers": {}, "cms": None}

        for scheme in ("https", "http"):
            try:
                r = requests.get(
                    f"{scheme}://{domain}",
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                tech["headers"] = dict(r.headers)
                tech["status_code"] = r.status_code
                self._parse_headers(r.headers, tech)
                self._parse_html(r.text, tech)
                log_success(f"[TechAgent] Detected: {tech['technologies']}")
                break
            except requests.RequestException as e:
                log_warn(f"[TechAgent] {scheme}://{domain} failed: {e}")

        return tech

    def _parse_headers(self, headers, tech: dict):
        for header, extractor in HEADER_SIGNATURES.items():
            value = headers.get(header)
            if value:
                detected = extractor(value)
                if detected and detected not in tech["technologies"]:
                    tech["technologies"].append(detected)

    def _parse_html(self, html: str, tech: dict):
        for pattern, name in HTML_SIGNATURES.items():
            if re.search(pattern, html, re.IGNORECASE):
                if name not in tech["technologies"]:
                    tech["technologies"].append(name)
                if tech["cms"] is None:
                    tech["cms"] = name
