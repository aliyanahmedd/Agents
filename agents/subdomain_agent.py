"""Subdomain Enumeration Agent — crt.sh (cert transparency) + HackerTarget."""
import requests
import dns.resolver
from utils.api_client import crt_sh_subdomains
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_subdomains
from config.settings import REQUEST_TIMEOUT

# Subdomains that are commonly risky if publicly exposed
RISKY_KEYWORDS = {"admin", "dev", "staging", "test", "api", "internal", "vpn", "secret", "beta"}


class SubdomainAgent:
    def run(self, target_id: int, domain: str) -> list[dict]:
        log_info(f"[SubdomainAgent] Enumerating subdomains for {domain}")
        found_subs = set()

        # Source 1: Certificate Transparency logs (crt.sh)
        ct_subs = crt_sh_subdomains(domain)
        found_subs.update(ct_subs)
        log_success(f"[SubdomainAgent] crt.sh found {len(ct_subs)} subdomains")

        # Source 2: HackerTarget (free, no key required)
        ht_subs = self._hackertarget(domain)
        found_subs.update(ht_subs)
        log_success(f"[SubdomainAgent] HackerTarget found {len(ht_subs)} subdomains")

        subdomains = []
        for sub in sorted(found_subs):
            ip = self._resolve_ip(sub)
            risk = any(kw in sub.split(".")[0] for kw in RISKY_KEYWORDS)
            subdomains.append({
                "subdomain": sub,
                "ip": ip or "",
                "open_ports": [],
                "technology": [],
                "risk_flag": int(risk),
            })

        if subdomains:
            insert_subdomains(target_id, subdomains)
            risky = [s for s in subdomains if s["risk_flag"]]
            log_success(f"[SubdomainAgent] {len(subdomains)} subdomains saved | {len(risky)} flagged as risky")

        return subdomains

    @staticmethod
    def _hackertarget(domain: str) -> list[str]:
        try:
            r = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200 or "error" in r.text.lower():
                return []
            subs = []
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts and parts[0].endswith(f".{domain}"):
                    subs.append(parts[0].strip().lower())
            return subs
        except Exception as e:
            log_warn(f"[SubdomainAgent] HackerTarget failed: {e}")
            return []

    @staticmethod
    def _resolve_ip(hostname: str) -> str | None:
        try:
            answers = dns.resolver.resolve(hostname, "A", lifetime=3)
            return str(answers[0])
        except Exception:
            return None
