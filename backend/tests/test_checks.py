import asyncio
import sys
from urllib.parse import urlparse

from backend.app.checks.tls import check_tls
from backend.app.checks.headers import check_headers
from backend.app.checks.exposed_files import check_exposed_files
from backend.app.checks.dns import check_dns
from backend.app.utils.grading import score_to_grade

async def run_all_checks(target_url: str):
    parsed = urlparse(target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}")
    domain = parsed.netloc or parsed.path
    clean_domain = domain.split(":")[0]
    full_url = f"https://{clean_domain}"

    print(f"\n=================================================")
    print(f"RUNNING ALL 4 SECURITY CHECKS FOR: {clean_domain}")
    print(f"\n=================================================")

    #run all 4 checks in parellel using asyncio.gather
    tls_task = check_tls(clean_domain)
    headers_task = check_headers(full_url)
    files_task = check_exposed_files(full_url)
    dns_task = check_dns(clean_domain)

    tls_res, headers_res, files_res, dns_res = await asyncio.gather(
        tls_task, headers_task, files_task, dns_task
    )

    results = [tls_res, headers_res, files_res, dns_res]

    #Calculate overall score and grade
    total_score = sum(r["score"] for r in results)/len(results)
    overall_grade = score_to_grade(total_score)

    print("\n--- INDIVIDUAL CHECK RESULTS ---")
    for r in results:
        status_symbol = "True" if r["passed"] else "False"
        print(f"{status_symbol} [{r['grade']}] {r['check_type'].upper():<15} Score: {r['score']:>5.1f}/100")

    print("\n================================================================")
    print(f"OVERALL GRADE: {overall_grade} | OVERALL SCORE: {total_score:.1f}/100")
    print("===============================================================\n")

    return results

if __name__ == "__main__":
    test_domain = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    asyncio.run(run_all_checks(test_domain))