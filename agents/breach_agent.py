"""Breach Intelligence Agent — checks Have I Been Pwned for each discovered email."""
from utils.api_client import hibp_check_email
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_breaches


class BreachAgent:
    def run(self, target_id: int, emails: list[dict]) -> list[dict]:
        log_info(f"[BreachAgent] Checking {len(emails)} emails against HIBP")
        all_breaches = []

        for entry in emails:
            email = entry.get("email", "")
            if not email:
                continue

            breaches = hibp_check_email(email)
            if breaches is None:
                log_warn(f"[BreachAgent] HIBP check failed for {email}")
                continue
            if not breaches:
                continue

            for b in breaches:
                all_breaches.append({
                    "email": email,
                    "breach_name": b.get("Name", ""),
                    "breach_date": b.get("BreachDate", ""),
                    "data_types": b.get("DataClasses", []),
                })
                log_warn(f"[BreachAgent] {email} found in breach: {b.get('Name')}")

        if all_breaches:
            insert_breaches(target_id, all_breaches)
            log_success(f"[BreachAgent] {len(all_breaches)} breach records saved")
        else:
            log_success("[BreachAgent] No breaches found for discovered emails")

        return all_breaches
