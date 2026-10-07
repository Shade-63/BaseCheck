import asyncio
import sys

from backend.app.checks.tls import check_tls
from backend.app.checks.headers import check_headers
from backend.app.checks.exposed_files import check_exposed_files
from backend.app.checks.dns import check_dns
from backend.app.utils.grading import score_to_grade


async def run_all_checks(target_input: str):
    print(f"\n=======================================================")
    print(f">> RUNNING SECURITY CHECKS FOR: {target_input}")
    print(f"=======================================================")

    # 1. Run all 4 checks concurrently
    tls_task = check_tls(target_input)
    headers_task = check_headers(target_input)
    files_task = check_exposed_files(target_input)
    dns_task = check_dns(target_input)

    tls_res, headers_res, files_res, dns_res = await asyncio.gather(
        tls_task, headers_task, files_task, dns_task
    )

    results = [tls_res, headers_res, files_res, dns_res]

    # Calculate Overall Score & Grade
    total_score = sum(r["score"] for r in results) / len(results)
    overall_grade = score_to_grade(total_score)

    print("\n--- INDIVIDUAL CHECK RESULTS ---")
    for r in results:
        status_symbol = "[PASS]" if r["passed"] else "[FAIL]"
        print(f"{status_symbol} [{r['grade']}] {r['check_type'].upper():<15} Score: {r['score']:>5.1f}/100")
        if r["details"].get("warnings"):
            for w in r["details"]["warnings"][:2]:
                print(f"    [WARN] {w}")

    print("\n-------------------------------------------------------")
    print(f"OVERALL GRADE: {overall_grade}  |  OVERALL SCORE: {total_score:.1f}/100")
    print("=======================================================\n")

    return results


async def run_comprehensive_test_suite():
    print("\n" + "=" * 60)
    print("RUNNING COMPREHENSIVE PHASE 3 TEST SUITE")
    print("=" * 60)

    # 1. Valid public domain
    print("\n>>> TEST 1: Valid Public Domain (github.com)")
    res_github = await run_all_checks("github.com")
    assert all("check_type" in r for r in res_github), "Missing check_type key in results"
    assert res_github[0]["check_type"] == "tls"
    assert res_github[1]["check_type"] == "headers"
    assert res_github[2]["check_type"] == "exposed_files"
    assert res_github[3]["check_type"] == "dns"
    print("[OK] Test 1 Passed (Valid Domain Scanned Cleanly)")

    # 2. SSRF Tests - Localhost & Private IPs
    ssrf_targets = [
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://169.254.169.254",
        "http://192.168.1.1",
    ]
    for target in ssrf_targets:
        print(f"\n>>> TEST SSRF BLOCKING: {target}")
        res_ssrf = await run_all_checks(target)
        for r in res_ssrf:
            assert r["passed"] is False, f"SSRF Target {target} was not rejected!"
            assert r["score"] == 0.0
            assert r["grade"] == "F"
            assert any("SSRF" in str(w) or "blocked" in str(w) or "error" in str(w).lower() for w in r["details"].get("warnings", []))
        print(f"[OK] SSRF Protection Successfully Blocked: {target}")

    # 3. Malformed Input Tests
    malformed_targets = [
        "ftp://example.com",
        "file:///etc/passwd",
    ]
    for target in malformed_targets:
        print(f"\n>>> TEST MALFORMED INPUT BLOCKING: {target}")
        res_malformed = await run_all_checks(target)
        for r in res_malformed:
            assert r["passed"] is False
            assert r["score"] == 0.0
        print(f"[OK] Malformed Input Successfully Handled: {target}")

    print("\n" + "=" * 60)
    print("ALL PHASE 3 SECURITY & VALIDATION TESTS PASSED 100%!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(run_all_checks(sys.argv[1]))
    else:
        asyncio.run(run_comprehensive_test_suite())
