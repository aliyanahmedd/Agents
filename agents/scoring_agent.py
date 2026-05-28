"""Risk Scoring Agent — aggregates findings into a 0–10 attack surface score."""
from database.db import upsert_risk_score
from utils.helpers import log_info, log_success


class ScoringAgent:
    def run(self, target_id: int, findings: dict) -> dict:
        log_info("[ScoringAgent] Computing risk scores")

        email_score = self._email_score(findings.get("emails", []))
        subdomain_score = self._subdomain_score(findings.get("subdomains", []))
        breach_score = self._breach_score(findings.get("breaches", []))
        threat_score = self._threat_score(findings.get("threat_intel", []))

        total = round(
            (email_score * 0.2 + subdomain_score * 0.3 + breach_score * 0.35 + threat_score * 0.15),
            2,
        )

        scores = {
            "total": total,
            "email": email_score,
            "subdomain": subdomain_score,
            "breach": breach_score,
            "threat": threat_score,
        }

        upsert_risk_score(target_id, scores)
        log_success(f"[ScoringAgent] Total attack surface risk: {total}/10")
        return scores

    @staticmethod
    def _email_score(emails: list) -> float:
        # More exposed emails = larger social engineering surface
        count = len(emails)
        if count == 0:
            return 0.0
        if count < 5:
            return 2.0
        if count < 20:
            return 5.0
        return min(10.0, 5.0 + (count - 20) * 0.1)

    @staticmethod
    def _subdomain_score(subdomains: list) -> float:
        risky = sum(1 for s in subdomains if s.get("risk_flag"))
        total = len(subdomains)
        base = min(5.0, total * 0.2)
        bonus = min(5.0, risky * 1.5)
        return round(min(10.0, base + bonus), 2)

    @staticmethod
    def _breach_score(breaches: list) -> float:
        count = len(breaches)
        if count == 0:
            return 0.0
        if count < 3:
            return 4.0
        if count < 10:
            return 7.0
        return 10.0

    @staticmethod
    def _threat_score(intel: list) -> float:
        malicious = sum(1 for i in intel if i.get("malicious"))
        if malicious == 0:
            return 0.0
        return min(10.0, malicious * 3.5)
