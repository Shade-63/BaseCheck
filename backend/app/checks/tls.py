import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any

from backend.app.utils.grading import score_to_grade

async def check_tls(domain: str, port: int=443, timeout: float = 10.0) -> Dict[str, Any]:
    """Asynchronously inspects the TLS/SSL configs and certi of the domain"""
    
    #clean domain(remove the protocols or paths if passed)
    clean_domain = domain.replace("https://", "").replace("http://","").split("/")[0].split(":")[0]

    ssl_context = ssl.create_default_context()

    try:
        #run socket connection in aync loop with timeout
        loop = asyncio.get_running_loop()

        def _get_cert_and_protocol():
            with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    return cert, protocol, cipher

        cert, protocol, cipher = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert_and_protocol),
            timeout=timeout,
        )

        #parse expiry and validity
        #date format in cert: 'May 15 12:00:00 2026 GMT'
        not_after_str = cert.get("notAfter")
        not_before_str = cert.get("notBefore")

        expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        valid_from = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        days_remaining = (expires_at - now).days
        is_expired = now > expires_at

        #Scoring logic
        score = 100.0
        warnings = []

        if is_expired:
            score = 0.0
            warnings.append(f"Certificate expired {abs(days_remaining)} days ago.")
        elif days_remaining < 14:
            score -= 30.0
            warnings.append(f"Certificate expires in {abs(days_remaining)} days. Renew Soon!")
        elif days_remaining < 30:
            score -= 10.0
            warnings.append(f"Certificate expires in {abs(days_remaining)} days.")

        #Protocol Scores
        if protocol == "TLSv1.3":
            #Best
            pass
        elif protocol == "TLSv1.2":
            score -= 5.0
        else:
            score -= 40.0
            warnings.append(f"Deprecated protocol {protocol} in use")

        score = max(0.0, min(100.0, score))
        grade = score_to_grade(score)

        #Extracting the subject/Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
        subject_dict = dict(x[0] for x in cert.get("subject", ()))

        return{
            "check_type": "tls",
            "score": score,
            "grade": grade,
            "passed": score>= 70.0,
            "details": {
                "valid": not is_expired,
                "protocol": protocol,
                "cipher_suite": cipher[0] if cipher else None,
                "days_until_expiration": days_remaining,
                "expires_at": expires_at.isoformat(),
                "valid_from": valid_from.isoformat(),
                "issuer": issuer_dict.get("organiztionName") or issuer_dict.get("commonName"),
                "subject": subject_dict.get("commonName"),
                "warnings": warnings,
            },
        }

    except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
        return{
            "check_type": "tls",
            "score": 0.0,
            "grade": "F",
            "passed": False,
            "details":{
                "valid": False,
                "error": f"SSl verification error: {str(e)}",
                "warnings": ["invalid or untrusted SSL certificate"],
            },
        }

    except (socket.timeout, asyncio.TimeoutError):
        return{
            "check_type": "tls",
            "score": 0.0,
            "grade": "F",
            "passed": False,
            "details": {
                "valid": False,
                "error": f"Connection timed out after {timeout}s while connecting to {clean_domain}: {port}",
                "warnings": ["TLS port 443 unreachable or timed out"],
            },
        }

    except Exception as e:
        return{
            "ccheck_type": "tls",
            "score": 0.0,
            "grade": "F",
            "passed": False,
            "details": {
                "valid": False,
                "error": f"Failed to inspect TLS: {str(e)}",
                "warnings": [f"Could not complete TLS handshake: {str(e)}"],
            },
        }