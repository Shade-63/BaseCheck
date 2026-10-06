import asyncio
from typing import Any, Dict, List
import httpx
from urllib.parse import urlparse

from backend.app.utils.grading import score_to_grade

SENSITIVE_PATHS = [
    {"path": "/.env", "name": "Environment Variables (.env)", "weight": 40.0},
    {"path": "/.git/config", "name": "Git configs (.git/config)", "weight": 30.0},
    {"path": "/.git/HEAD", "name": "Git Repository HEAD (.git/HEAD)", "weight": 30.0},
    {"path": "/docker-compose.yml", "name": "Docker Compose Config", "weight": 20.0},
    {"path": "/.DS_Store", "name": "macOS Directory Metadata (.DS_Store)", "weight": 10.0},
    {"path": "/backup.sq;", "name": "Database Backup File (backup.sql)", "weight": 40.0},
]

def is_false_positive(content_type: str, body_snippet: str) -> bool:
    """Detects if a 200 OK is actually a SPA / Custom 404 HTML fallback rather than a real file."""
    ct = content_type.lower()
    snippet = body_snippet.strip().lower()

    if "text/html" in ct or "application/xhtml+xml" in ct:
        if snippet.startswith("<!doctype") or "<html" in snippet or "<body" in snippet:
            return True
        return False

async def probe_path(client: httpx.AsyncClient, base_url: str, path_info: Dict[str, Any]) -> Dict[str, Any]:
    target_url = f"{base_url.rstrip('/')}{path_info['path']}"
    try:
        response = await client.get(target_url)
        content_type = response.headers.get("content-type", "")
        body_snippet = response.text[:300]

        if response.status_code==200:
            if not is_false_positive(content_type, body_snippet):
                return{
                    "path": path_info["path"],
                    "name": path_info["name"],
                    "exposed": True,
                    "weight": path_info["weight"],
                    "status_code": response.status_code,
                }

        return {
            "path": path_info["path"],
            "name": path_info["name"],
            "exposed": False,
            "weight": path_info["weight"],
            "status_code": response.status_code,
        }

    except Exception:
        return{
            "path": path_info["path"],
            "name": path_info["name"],
            "exposed": False,
            "weight": path_info["weight"],
            "status_code": None,
        }

async def check_exposed_files(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Probes common sensitive file paths concurrently to detect unauthorized public exposure"""
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    exposed_findings: List[Dict[str, Any]] = []
    penalties = 0.0

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        verify=False,
        headers={"User-Agents": "Basecheck-Security-Scaner/1.0"},
    ) as client:
        #Run probes concurrently
        tasks = [probe_path(client, base_url, item) for item in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)

        for res in results:
            if res["exposed"]:
                exposed_findings.append({
                    "path": res["path"],
                    "name": res["name"],
                    "status_code": res["status_code"],
                })
                penalties += res["weight"]

        final_score = max(0.0, 100.0 - penalties)
        grade = score_to_grade(final_score)
        passed = len(exposed_findings) == 0

        warnings = [f"Critical file exposed publicly: {f['path']} ({f['name']})" for f in exposed_findings]
        recommendations = ["Block public access to hidden files and dotfiles(.env, .git) in your web server/reverse proxy (Nginx, Caddy, Apache)"] if exposed_findings else []

        return {
            "check_type": "exposed_files",                                                                                                                   
            "score": final_score,
            "grade": grade,
            "passed": passed,
            "details": {
                "probed_paths_count": len(SENSITIVE_PATHS),
                "exposed_count": len(exposed_findings),
                "exposed_files": exposed_findings,
                "recommendations": recommendations,
                "warnings": warnings,
            },
        }