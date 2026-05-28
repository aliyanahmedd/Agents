"""Threat Intelligence Agent — VirusTotal checks for domain & discovered IPs."""
from utils.api_client import virustotal_check_domain, virustotal_check_ip
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_threat_intel


class ThreatAgent:
    def run(self, target_id: int, domain: str, subdomains: list[dict]) -> list[dict]:
        log_info(f"[ThreatAgent] Running VirusTotal checks")
        findings = []

        # Check root domain
        findings += self._check_domain(domain)

        # Collect unique IPs from subdomains
        seen_ips = set()
        for sub in subdomains:
            ip = sub.get("ip")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                findings += self._check_ip(ip)

        if findings:
            insert_threat_intel(target_id, findings)
            malicious = [f for f in findings if f["malicious"]]
            log_success(
                f"[ThreatAgent] {len(findings)} indicators checked | "
                f"{len(malicious)} flagged as malicious"
            )

        return findings

    def _check_domain(self, domain: str) -> list[dict]:
        data = virustotal_check_domain(domain)
        return [self._parse_vt(domain, "domain", data)] if data else []

    def _check_ip(self, ip: str) -> list[dict]:
        data = virustotal_check_ip(ip)
        return [self._parse_vt(ip, "ip", data)] if data else []

    @staticmethod
    def _parse_vt(indicator: str, itype: str, data: dict) -> dict:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return {
            "indicator": indicator,
            "indicator_type": itype,
            "malicious": int(malicious_count > 0),
            "engine_hits": malicious_count,
            "vt_link": f"https://www.virustotal.com/gui/{itype}/{indicator}",
        }
