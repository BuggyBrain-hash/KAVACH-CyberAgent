import sys
from pathlib import Path

from scanner import scan_file
from patcher import create_patched_file
from regression_tester import run_regression_tests
from report import save_report


# ============================================================
# RISK CALCULATION
# ============================================================

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def calculate_risk(findings):
    """
    Calculate a simple risk score and risk level
    from scanner findings.
    """

    if not findings:
        return 0, "SAFE"

    highest_score = 0

    for finding in findings:

        severity = str(
            finding.get("severity", "LOW")
        ).upper()

        score = SEVERITY_SCORES.get(
            severity,
            1
        )

        highest_score = max(
            highest_score,
            score
        )

    # Multiple vulnerabilities increase risk.
    if len(findings) >= 3:
        risk_score = 10
        risk_level = "CRITICAL"

    elif len(findings) == 2:
        risk_score = max(
            highest_score,
            7
        )
        risk_level = "HIGH"

    else:
        risk_score = highest_score

        if risk_score >= 7:
            risk_level = "HIGH"

        elif risk_score >= 4:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

    return risk_score, risk_level


# ============================================================
# PRINT FINDINGS
# ============================================================

def print_findings(title, findings):

    print()
    print("=" * 50)
    print(title)
    print("=" * 50)

    if not findings:

        print("No security vulnerabilities found.")
        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        vulnerability_type = finding.get(
            "type",
            "Unknown"
        )

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        line = finding.get(
            "line",
            "?"
        )

        code = finding.get(
            "code",
            ""
        )

        description = finding.get(
            "description",
            finding.get(
                "explanation",
                ""
            )
        )

        print(
            f"\n[{index}] {vulnerability_type}"
        )

        print(
            f"    Severity: {severity}"
        )

        print(
            f"    Line: {line}"
        )

        if code:
            print(
                f"    Code: {code}"
            )

        if description:
            print(
                f"    Explanation: {description}"
            )


# ============================================================
# PATCH VERIFICATION
# ============================================================

def verify_patch(
    original_findings,
    patched_findings
):
    """
    Verify that vulnerabilities found originally
    are no longer present in the patched file.
    """

    original_types = []

    for finding in original_findings:

        vulnerability_type = str(
            finding.get(
                "type",
                ""
            )
        ).strip()

        if vulnerability_type:
            original_types.append(
                vulnerability_type
            )

    patched_types = []

    for finding in patched_findings:

        vulnerability_type = str(
            finding.get(
                "type",
                ""
            )
        ).strip()

        if vulnerability_type:
            patched_types.append(
                vulnerability_type
            )

    # Determine which original vulnerability
    # categories are still present.
    remaining = []

    for original_type in original_types:

        still_present = False

        for patched_type in patched_types:

            if (
                original_type.lower()
                == patched_type.lower()
            ):
                still_present = True
                break

        if still_present:
            remaining.append(
                original_type
            )

    # Remove duplicates while preserving order.
    remaining_unique = []

    for item in remaining:

        if item not in remaining_unique:
            remaining_unique.append(item)

    resolved = []

    for original_type in original_types:

        if (
            original_type
            not in remaining_unique
            and original_type
            not in resolved
        ):
            resolved.append(
                original_type
            )

    success = len(
        remaining_unique
    ) == 0

    return {
        "success": success,
        "original_count": len(
            original_findings
        ),
        "remaining_count": len(
            patched_findings
        ),
        "resolved": resolved,
        "remaining": remaining_unique
    }


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Check command-line argument
    # --------------------------------------------------------

    if len(sys.argv) < 2:

        print(
            "\nUsage:"
        )

        print(
            "  python main.py <python_file>"
        )

        print(
            "\nExample:"
        )

        print(
            "  python main.py "
            "test_samples/vulnerable.py"
        )

        return 1

    filename = sys.argv[1]

    source_path = Path(filename)

    if not source_path.exists():

        print(
            f"\nERROR: File not found: {filename}"
        )

        return 1

    print()
    print("=" * 55)
    print("             KAVACH CYBERAGENT")
    print("=" * 55)

    print(
        f"\nTarget: {filename}"
    )

    # --------------------------------------------------------
    # Initialize all variables.
    #
    # This is important because regression and verification
    # must always have a defined value.
    # --------------------------------------------------------

    original_findings = []

    patched_findings = []

    patched_file = None

    verification = {
        "success": False,
        "original_count": 0,
        "remaining_count": 0,
        "resolved": [],
        "remaining": []
    }

    regression = {
        "success": False,
        "tests_run": 0,
        "tests_passed": 0,
        "tests_failed": 0,
        "results": [],
        "message": "Regression testing not executed."
    }

    # ========================================================
    # STEP 1 — SECURITY SCAN
    # ========================================================

    print()
    print("=" * 50)
    print("========== SECURITY SCAN ==========")
    print("=" * 50)

    try:

        original_findings = scan_file(
            filename
        )

    except Exception as error:

        print(
            "\nSecurity scanner failed."
        )

        print(
            f"{type(error).__name__}: {error}"
        )

        return 1

    print_findings(
        "Detected Vulnerabilities",
        original_findings
    )

    # ========================================================
    # SAFE PROGRAM
    # ========================================================

    if not original_findings:

        risk_score = 0
        risk_level = "SAFE"

        print()
        print("=" * 50)
        print("========== RISK ASSESSMENT ==========")
        print("=" * 50)

        print(
            f"Risk Score: {risk_score}/10"
        )

        print(
            f"Risk Level: {risk_level}"
        )

        print()
        print(
            "✓ No vulnerabilities detected."
        )

        # ----------------------------------------------------
        # Save safe-program report
        # ----------------------------------------------------

        try:

            report_path = save_report(
                filename,
                original_findings,
                [],
                risk_score,
                risk_level,
                {
                    "success": True,
                    "original_count": 0,
                    "remaining_count": 0,
                    "resolved": [],
                    "remaining": []
                },
                {
                    "success": True,
                    "tests_run": 0,
                    "tests_passed": 0,
                    "tests_failed": 0,
                    "results": [],
                    "message": "No patch required."
                }
            )

            print()
            print(
                f"Report saved: {report_path}"
            )

        except Exception as error:

            print(
                "\nWarning: Could not save report."
            )

            print(
                f"{type(error).__name__}: {error}"
            )

        print()
        print("=" * 50)
        print("========== KAVACH RESULT ==========")
        print("=" * 50)

        print(
            "✓ SECURITY STATUS: SAFE"
        )

        return 0

    # ========================================================
    # STEP 2 — RISK ASSESSMENT
    # ========================================================

    risk_score, risk_level = calculate_risk(
        original_findings
    )

    print()
    print("=" * 50)
    print("========== RISK ASSESSMENT ==========")
    print("=" * 50)

    print(
        f"Risk Score: {risk_score}/10"
    )

    print(
        f"Risk Level: {risk_level}"
    )

    # ========================================================
    # STEP 3 — PATCH GENERATION
    # ========================================================

    print()
    print("=" * 50)
    print("========== PATCH GENERATION ==========")
    print("=" * 50)

    try:

        patched_file = create_patched_file(
            filename,
            original_findings
        )

        print(
            f"Patched File: {patched_file}"
        )

    except Exception as error:

        print(
            "\nPatch generation failed."
        )

        print(
            f"{type(error).__name__}: {error}"
        )

        return 1

    # ========================================================
    # STEP 4 — SCAN PATCHED PROGRAM
    # ========================================================

    print()
    print("=" * 50)
    print("========== PATCHED SECURITY SCAN ==========")
    print("=" * 50)

    try:

        patched_findings = scan_file(
            patched_file
        )

    except Exception as error:

        print(
            "\nPatched scan failed."
        )

        print(
            f"{type(error).__name__}: {error}"
        )

        patched_findings = []

        verification = {
            "success": False,
            "original_count": len(
                original_findings
            ),
            "remaining_count": 0,
            "resolved": [],
            "remaining": [
                "Patched scan failed"
            ]
        }

    else:

        print_findings(
            "Remaining Vulnerabilities",
            patched_findings
        )

        # ====================================================
        # STEP 5 — PATCH VERIFICATION
        # ====================================================

        print()
        print(
            "========== PATCH VERIFICATION =========="
        )

        verification = verify_patch(
            original_findings,
            patched_findings
        )

        print()
        print(
            f"Original vulnerabilities: "
            f"{len(original_findings)}"
        )

        print(
            f"Remaining vulnerabilities: "
            f"{len(patched_findings)}"
        )

        print()

        if verification["resolved"]:

            print("Resolved:")

            for vulnerability in verification[
                "resolved"
            ]:

                print(
                    f"  ✓ {vulnerability}"
                )

        if verification["remaining"]:

            print()
            print("Still present:")

            for vulnerability in verification[
                "remaining"
            ]:

                print(
                    f"  ! {vulnerability}"
                )

        print()

        if verification["success"]:

            print(
                "✓ PATCH VERIFICATION PASSED"
            )

        else:

            print(
                "! PATCH VERIFICATION FAILED"
            )

    # ========================================================
    # STEP 6 — REGRESSION TEST
    # ========================================================

    print()
    print("=" * 50)
    print("========== REGRESSION TEST ==========")
    print("=" * 50)

    if not verification["success"]:

        regression = {
            "success": False,
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "results": [],
            "message": (
                "Regression testing skipped "
                "because patch verification failed."
            )
        }

        print(
            "\n⚠ Regression testing skipped."
        )

        print(
            "Patch verification must pass first."
        )

    else:

        try:

            regression = run_regression_tests(
                patched_file,
                filename
            )

            # Protect against a regression function
            # returning None.
            if regression is None:

                regression = {
                    "success": False,
                    "tests_run": 0,
                    "tests_passed": 0,
                    "tests_failed": 0,
                    "results": [],
                    "message": (
                        "Regression tester returned no result."
                    )
                }

        except Exception as error:

            regression = {
                "success": False,
                "tests_run": 0,
                "tests_passed": 0,
                "tests_failed": 1,
                "results": [],
                "message": str(error)
            }

        print()
        print(
            f"Tests run: "
            f"{regression.get('tests_run', 0)}"
        )

        print(
            f"Tests passed: "
            f"{regression.get('tests_passed', 0)}"
        )

        print(
            f"Tests failed: "
            f"{regression.get('tests_failed', 0)}"
        )

        results = regression.get(
            "results",
            []
        )

        if results:

            print()
            print("Test Results:")

            for result in results:

                test_name = result.get(
                    "name",
                    "Unnamed test"
                )

                passed = result.get(
                    "passed",
                    False
                )

                if passed:

                    print(
                        f"  ✓ {test_name}"
                    )

                else:

                    print(
                        f"  ✗ {test_name}"
                    )

                    error_text = result.get(
                        "error",
                        ""
                    )

                    if error_text:

                        print(
                            f"      Error: {error_text}"
                        )

        print()

        if regression.get(
            "success",
            False
        ):

            print(
                "✓ Regression testing PASSED"
            )

        else:

            print(
                "⚠ Regression testing requires review"
            )

    # ========================================================
    # STEP 7 — FINAL SECURITY STATUS
    # ========================================================

    print()
    print("=" * 50)
    print("========== FINAL SECURITY STATUS ==========")
    print("=" * 50)

    if verification["success"]:

        print(
            "✓ All detected vulnerabilities were resolved."
        )

    else:

        print(
            "⚠ One or more vulnerabilities remain."
        )

    # ========================================================
    # STEP 8 — FINAL FUNCTIONAL STATUS
    # ========================================================

    print()
    print("=" * 50)
    print("========== FINAL FUNCTIONAL STATUS ==========")
    print("=" * 50)

    if regression.get(
        "success",
        False
    ):

        print(
            "✓ Patched program passed regression testing."
        )

    else:

        print(
            "⚠ Patched program requires functional review."
        )

    # ========================================================
    # STEP 9 — KAVACH FINAL RESULT
    # ========================================================

    print()
    print("=" * 50)
    print("========== KAVACH FINAL RESULT ==========")
    print("=" * 50)

    if (
        verification["success"]
        and regression.get(
            "success",
            False
        )
    ):

        print(
            "✓ SECURITY PATCH PASSED"
        )

        print(
            "✓ FUNCTIONAL TESTS PASSED"
        )

        print(
            "✓ PATCH VERIFIED AND FUNCTIONAL"
        )

    elif verification["success"]:

        print(
            "⚠ SECURITY PATCH PASSED — "
            "MANUAL REVIEW REQUIRED"
        )

    else:

        print(
            "✗ SECURITY PATCH FAILED"
        )

    # ========================================================
    # STEP 10 — FINAL REPORT GENERATION
    # ========================================================

    print()
    print("=" * 50)
    print("========== FINAL REPORT ==========")
    print("=" * 50)

    final_report = None

    try:

        final_report = save_report(
            filename,
            original_findings,
            patched_findings,
            risk_score,
            risk_level,
            verification,
            regression
        )

        print(
            f"✓ Final report saved: "
            f"{final_report}"
        )

    except Exception as error:

        print(
            "⚠ Final report could not be saved."
        )

        print(
            f"{type(error).__name__}: {error}"
        )

    # ========================================================
    # STEP 11 — SUMMARY
    # ========================================================

    print()
    print("=" * 50)
    print("========== SUMMARY ==========")
    print("=" * 50)

    print(
        f"Target: {filename}"
    )

    print(
        f"Risk Level: {risk_level}"
    )

    print(
        f"Risk Score: {risk_score}/10"
    )

    print(
        f"Original Findings: "
        f"{len(original_findings)}"
    )

    print(
        f"Remaining Findings: "
        f"{len(patched_findings)}"
    )

    print(
        f"Patched File: "
        f"{patched_file}"
    )

    print(
        f"Regression Tests: "
        f"{regression.get('tests_run', 0)}"
    )

    print(
        f"Regression Passed: "
        f"{regression.get('tests_passed', 0)}"
    )

    print(
        f"Regression Failed: "
        f"{regression.get('tests_failed', 0)}"
    )

    if final_report:

        print(
            f"Final Report: "
            f"{final_report}"
        )

    print()
    print("=" * 50)
    print("       KAVACH scan completed.")
    print("=" * 50)

    return 0


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )