from typing import Any, Dict
import httpx

from backend.app.utils.grading import score_to_grade

def clean_headers_value(val: str, max_len: int = 120) -> str:
    """Trims overly long header values (like huge CSPs) for clean report display and readability"""
    val = val.strip()
    return f"{val[:max_len]}..." if len(val) > max_len else val

async def check_headers(url: str, timeout: float = 10.0) -> Dict[str,Any]:
    """Asynchronously inspects the HTTP response security headers for a given URL"""
    #ensures the scheme is present
    target_url = url if url.startswith(("http://", "https://")) else f"https://{url}"

    header_findings = {}
    recommendations = []
    warnings = []
    score = 0.0

    try:
        async with httpx.AsyncClient(
            follow_redirects= True,
            timeout=timeout,
            verify=False, #TLS check is handled separately
            headers={"User-Agent": "Basecheck-Security-Scanner/1.0"},
        ) as client:
            response = await client.get(target_url)
            resp_headers = {k.lower(): v for k, v in response.headers.items()}

        #1. Content-Security-Policy (25 pts)
        csp = resp_headers.get("content-security-policy")
        if csp:
            score += 25.0
            header_findings["content-security-policy"] = {
                "present": True,
                "value": clean_headers_value(csp),
                "status": "good",
            }
        else:
            recommendations.append("Add a Content-Security-Policy (CSP) header to mitigate XSS and clickjacking")
            header_findings["content-security-policy"] = {"present": False, "status": "missing"}

        #2. Strict-Transport-Security(25 pts)
        hsts = resp_headers.get("strict-transport-security")
        if hsts:
            score += 25.0
            header_findings["strict-transport-security"] = {
                "present": True,
                "value": clean_headers_value(hsts),
                "status": "good",
            }
        else:
            recommendations.append("Add strict-transport-security (HSTS) with a max-age of at least 1 year (31536000)")
            header_findings["strict-transport-security"] = {"present": False, "status": "missing"}

        #3. X-Frame-Options (15 pts)
        xfo = resp_headers.get("x-frame-options")
        if xfo:
            score += 15.0
            header_findings["x-frame-options"] = {
                "present": True,
                "value": clean_headers_value(xfo),
                "status": "good",
            }
        else:
            recommendations.append("add X-Frame-Options: DENY or SAMEORIGIAN to prevent clickjacking attacks")
            header_findings["x-frame-options"] = {"present": False, "status": "missing"}

        #4. X-Content-Type-Options (15 pts)
        xcto = resp_headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            score += 15.0
            header_findings["x-content-type-options"] = {
                "present": True,
                "value": clean_headers_value(xcto),
                "status": "good",
            }
        else:
            recommendations.append("Add X-Content-Type-Options: nosniff to prevent MIME type sniffing.")
            header_findings["x-content-type-options"] = {"present": False, "status": "missing"}

        # 5. Referrer-Policy (10 pts)
        ref_pol = resp_headers.get("referrer-policy")
        if ref_pol:
            score += 10.0
            header_findings["referrer-policy"] = {
                "present" : True,
                "value": clean_headers_value(ref_pol),
                "status": "good",
            }
        else:
            recommendations.append("Add Referrer-Policy (e.g. strict-origin-when-cross-origin) to protect user privacy")
            header_findings["referrer-policy"] = {"present": False, "status": "missing"}

        #6. Permission-Policy (10 pts)
        perm_pol = resp_headers.get("permissions-policy") or resp_headers.get("feature-policy")
        if perm_pol:
            score += 10.0
            header_findings["permissions-policy"] = {
                "present": True,
                "value": clean_headers_value(perm_pol),
                "status" : "good",
            }
        else:
            header_findings["permissions-policy"] = {"present": False, "status": "missing"}

        #7. Check for Info leakage
        x_powered_by = resp_headers.get("x-powered-by")
        if x_powered_by:
            score -= 5.00
            warnings.append(f"Server leaks technology stack via X-Powered-By: {x_powered_by}")

        server_hdr = resp_headers.get("server")
        if server_hdr and any(char.isdigit() for char in server_hdr):
            score -= 5.0
            warnings.append(f"Server header exposes exact version: {server_hdr}")

        final_score = max(0.0, min(100.0, score))
        grade = score_to_grade(final_score)

        return{
            "check_type": "headers",
            "score": score,
            "grade": grade,
            "passed": score>= 70.0,
            "details": {
                "url_tested": target_url,
                "http_status": response.status_code,
                "headers": header_findings,
                "recommendations": recommendations,
                "warnings": warnings,
            },
        }

    except Exception as e:
        return{
            "check_type": "headers",
            "score": 0.0,
            "grade": "F",
            "passed": False,
            "details": {
                "url_tested": target_url,
                "error": f"Failed to fetch headers: {str(e)}",
                "headers": {},
                "recommendations": ["Ensures the website is online and accessible over HTTP/HTTPS"],
                "warnings": [str(e)],
            },
        }