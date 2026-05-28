"""
Orchestrator Agent — coordinates all sub-agents using Claude as the reasoning core.

Flow:
  1. Validate & classify input
  2. Spin up sub-agents sequentially (data dependencies require ordering)
  3. Pass aggregated findings to Claude for analysis
  4. Return structured report + risk scores
"""
import anthropic
from config.settings import ANTHROPIC_API_KEY
from utils.validators import detect_input_type, normalize_domain, extract_domain_from_email
from utils.helpers import log_info, log_success, log_warn, print_section
from database.models import init_db
from database.db import create_target

from agents.email_agent import EmailAgent
from agents.subdomain_agent import SubdomainAgent
from agents.breach_agent import BreachAgent
from agents.dns_agent import DNSAgent
from agents.tech_agent import TechAgent
from agents.threat_agent import ThreatAgent
from agents.social_agent import SocialAgent
from agents.scoring_agent import ScoringAgent


class OSINTOrchestrator:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        init_db()

    def run(self, raw_input: str) -> dict:
        input_type = detect_input_type(raw_input)
        if input_type == "email":
            domain = extract_domain_from_email(raw_input)
        elif input_type == "domain":
            domain = normalize_domain(raw_input)
        else:
            log_warn(f"Unrecognized input type: {raw_input!r}. Treating as domain.")
            domain = normalize_domain(raw_input)
            input_type = "domain"

        log_info(f"Target: {domain} (type={input_type})")
        target_id = create_target(raw_input, input_type)
        findings: dict = {}

        # ── Phase 1: DNS & WHOIS ───────────────────────────────────────────────
        print_section("Phase 1 — DNS & WHOIS")
        dns_data = DNSAgent().run(target_id, domain)
        findings["dns"] = dns_data

        # ── Phase 2: Email discovery ───────────────────────────────────────────
        print_section("Phase 2 — Email Discovery")
        emails = EmailAgent().run(target_id, domain)
        findings["emails"] = emails

        # ── Phase 3: Subdomain enumeration ────────────────────────────────────
        print_section("Phase 3 — Subdomain Enumeration")
        subdomains = SubdomainAgent().run(target_id, domain)
        findings["subdomains"] = subdomains

        # ── Phase 4: Breach intelligence ──────────────────────────────────────
        print_section("Phase 4 — Breach Intelligence")
        breaches = BreachAgent().run(target_id, emails)
        findings["breaches"] = breaches

        # ── Phase 5: Tech stack ────────────────────────────────────────────────
        print_section("Phase 5 — Tech Stack Detection")
        tech = TechAgent().run(domain)
        findings["tech"] = tech

        # ── Phase 6: Threat intelligence ──────────────────────────────────────
        print_section("Phase 6 — Threat Intelligence")
        threat_intel = ThreatAgent().run(target_id, domain, subdomains)
        findings["threat_intel"] = threat_intel

        # ── Phase 7: Social media ──────────────────────────────────────────────
        print_section("Phase 7 — Social Media Intelligence")
        social = SocialAgent().run(domain)
        findings["social"] = social

        # ── Phase 8: Risk scoring ──────────────────────────────────────────────
        print_section("Phase 8 — Risk Scoring")
        scores = ScoringAgent().run(target_id, findings)
        findings["scores"] = scores

        # ── Phase 9: Claude analysis ───────────────────────────────────────────
        print_section("Phase 9 — AI Analysis")
        analysis = self._claude_analysis(domain, findings)
        findings["analysis"] = analysis

        findings["target_id"] = target_id
        findings["domain"] = domain
        return findings

    def _claude_analysis(self, domain: str, findings: dict) -> str:
        email_count = len(findings.get("emails", []))
        sub_count = len(findings.get("subdomains", []))
        risky_subs = [s["subdomain"] for s in findings.get("subdomains", []) if s.get("risk_flag")]
        breach_count = len(findings.get("breaches", []))
        malicious = [t["indicator"] for t in findings.get("threat_intel", []) if t.get("malicious")]
        tech = findings.get("tech", {}).get("technologies", [])
        scores = findings.get("scores", {})

        prompt = f"""You are a senior cybersecurity analyst reviewing OSINT findings for: {domain}

COLLECTED DATA:
- Emails discovered: {email_count}
- Subdomains: {sub_count} (risky: {risky_subs or 'none'})
- Breach records: {breach_count}
- Malicious indicators: {malicious or 'none'}
- Tech stack: {tech or 'unknown'}
- Risk scores: {scores}

Write a concise intelligence report with these sections:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. KEY FINDINGS (bullet points, most critical first)
3. ATTACK SURFACE ANALYSIS (what an attacker would target)
4. RECOMMENDATIONS (actionable, prioritized by risk)

Be specific. Reference actual findings above, not generic advice."""

        message = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        analysis = message.content[0].text
        log_success("[Orchestrator] Claude analysis complete")
        return analysis
