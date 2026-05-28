"""Subdomain Enumeration Agent — crt.sh (cert transparency) + Shodan."""
import dns.resolver
from utils.api_client import crt_sh_subdomains, shodan_search
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_subdomains

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

        # Source 2: Shodan
        shodan_data = shodan_search(f"hostname:.{domain}")
        if shodan_data and "matches" in shodan_data:
            for match in shodan_data["matches"]:
                for hostname in match.get("hostnames", []):
                    if hostname.endswith(f".{domain}"):
                        found_subs.add(hostname.lower())
            log_success(f"[SubdomainAgent] Shodan added extra subdomains")

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
    def _resolve_ip(hostname: str) -> str | None:
        try:
            answers = dns.resolver.resolve(hostname, "A", lifetime=3)
            return str(answers[0])
        except Exception:
            return None
