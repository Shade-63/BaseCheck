import re
from typing import Any, Dict
import dns.asyncresolver
import dns.resolver

from backend.app.utils.grading import score_to_grade
from backend.app.utils.validation import validate_target


async def check_dns(domain: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Asynchronously inspects SPF and DMARC DNS records for email spoofing protection.
    Includes SSRF validation.
    """
    try:
        _, clean_domain = validate_target(domain)
    except ValueError as val_err:
        return {
            "check_type": "dns",
            "score": 0.0,
            "grade": "F",
            "passed": False,
            "details": {
                "domain_tested": domain,
                "spf": {"present": False, "status": "error"},
                "dmarc": {"present": False, "status": "error"},
                "recommendations": [],
                "warnings": [str(val_err)],
            },
        }

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    score = 0.0
    recommendations = []
    warnings = []

    # -------------------------------------------------------------
    # 1. SPF Check (40 pts)
    # -------------------------------------------------------------
    spf_record = None
    spf_status = "missing"
    spf_details = {}

    try:
        txt_answers = await resolver.resolve(clean_domain, "TXT")
        for rdata in txt_answers:
            txt_str = "".join([part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_record = txt_str
                break

        if spf_record:
            if "-all" in spf_record:
                score += 40.0
                spf_status = "strict"
            elif "~all" in spf_record:
                score += 35.0
                spf_status = "softfail"
            elif "?all" in spf_record or "+all" in spf_record:
                score += 15.0
                spf_status = "permissive"
                warnings.append("SPF record uses permissive '?all' or '+all' qualifier.")
            else:
                score += 25.0
                spf_status = "valid"

            spf_details = {"present": True, "record": spf_record, "status": spf_status}
        else:
            recommendations.append("Publish an SPF DNS TXT record (e.g. 'v=spf1 -all' or authorized mail servers) to prevent email spoofing.")
            spf_details = {"present": False, "record": None, "status": "missing"}

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        recommendations.append("Publish an SPF DNS TXT record to authorize valid mail senders.")
        spf_details = {"present": False, "record": None, "status": "missing"}
    except Exception as e:
        spf_details = {"present": False, "error": str(e), "status": "error"}

    # -------------------------------------------------------------
    # 2. DMARC Check (60 pts)
    # -------------------------------------------------------------
    dmarc_record = None
    dmarc_status = "missing"
    dmarc_details = {}
    dmarc_domain = f"_dmarc.{clean_domain}"

    try:
        dmarc_answers = await resolver.resolve(dmarc_domain, "TXT")
        for rdata in dmarc_answers:
            txt_str = "".join([part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_str.startswith("v=DMARC1"):
                dmarc_record = txt_str
                break

        if dmarc_record:
            policy_match = re.search(r"p=(reject|quarantine|none)", dmarc_record, re.IGNORECASE)
            policy = policy_match.group(1).lower() if policy_match else "none"

            if policy == "reject":
                score += 60.0
                dmarc_status = "enforcing_reject"
            elif policy == "quarantine":
                score += 50.0
                dmarc_status = "enforcing_quarantine"
            else:
                score += 30.0
                dmarc_status = "monitoring_only"
                warnings.append("DMARC policy is set to 'p=none' (monitoring only). Upgrade to 'quarantine' or 'reject'.")

            dmarc_details = {"present": True, "record": dmarc_record, "policy": policy, "status": dmarc_status}
        else:
            recommendations.append(f"Publish a DMARC TXT record at '{dmarc_domain}' to protect your brand from email phishing.")
            dmarc_details = {"present": False, "record": None, "status": "missing"}

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        recommendations.append(f"Publish a DMARC TXT record at '{dmarc_domain}'.")
        dmarc_details = {"present": False, "record": None, "status": "missing"}
    except Exception as e:
        dmarc_details = {"present": False, "error": str(e), "status": "error"}

    final_score = max(0.0, min(100.0, score))
    grade = score_to_grade(final_score)

    return {
        "check_type": "dns",
        "score": final_score,
        "grade": grade,
        "passed": final_score >= 70.0,
        "details": {
            "domain_tested": clean_domain,
            "spf": spf_details,
            "dmarc": dmarc_details,
            "recommendations": recommendations,
            "warnings": warnings,
        },
    }
