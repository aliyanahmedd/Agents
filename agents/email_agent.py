"""Email Discovery Agent — finds company emails via Hunter.io."""
from utils.api_client import hunter_domain_search, hunter_email_verify
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_emails


class EmailAgent:
    def run(self, target_id: int, domain: str) -> list[dict]:
        log_info(f"[EmailAgent] Searching emails for {domain}")
        emails = []

        data = hunter_domain_search(domain)
        if not data or "data" not in data:
            log_warn("[EmailAgent] No email data returned from Hunter.io")
            return emails

        raw_emails = data["data"].get("emails", [])
        pattern = data["data"].get("pattern", "unknown")
        log_success(f"[EmailAgent] Email format: {pattern} | Found {len(raw_emails)} emails")

        for e in raw_emails:
            emails.append({
                "email": e.get("value", ""),
                "first_name": e.get("first_name", ""),
                "last_name": e.get("last_name", ""),
                "position": e.get("position", ""),
                "confidence": e.get("confidence", 0),
                "source": "hunter.io",
            })

        if emails:
            insert_emails(target_id, emails)
            log_success(f"[EmailAgent] Saved {len(emails)} emails to database")

        return emails
