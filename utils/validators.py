"""Input validation helpers."""
import re


def is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def is_valid_email(value: str) -> bool:
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, value.strip()))


def detect_input_type(value: str) -> str:
    """Return 'domain' | 'email' | 'unknown'."""
    value = value.strip()
    if is_valid_email(value):
        return "email"
    if is_valid_domain(value):
        return "domain"
    return "unknown"


def extract_domain_from_email(email: str) -> str:
    return email.split("@")[-1].lower().strip()


def normalize_domain(domain: str) -> str:
    return domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
