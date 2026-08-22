import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from advanced_scanner import scan_advanced


PROJECT_ROOT = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_ROOT / "reports"


SEVERITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10,
}


def calculate_risk(findings):
    if not findings:
        return {
            "score": 0,
            "level": "SAFE",
        }

    score = min(
        10,
        max(
            SEVERITY_SCORE.get(
                finding.get("severity", "LOW"),
                1,
            )
            for finding in findings
        ),
    )

    if score >= 10:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
    }


def run_dependency_audit():

    requirements = PROJECT_ROOT / "requirements.txt"

    result = {
        "available": False,
        "success": False,
        "tool": "pip-audit",
        "output": "",
    }

    if not requirements.exists():
        result["output"] = "requirements.txt not found."
        return result

    try:

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(requirements),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        result["available"] = True
        result["success"] = completed.returncode == 0
        result["output"] = (
            completed.stdout
            + completed.stderr
        ).strip()

    except FileNotFoundError:

        result["output"] = (
            "pip-audit is not installed."
        )

    except subprocess.TimeoutExpired:

        result["output"] = (
            "Dependency audit timed out."
        )

    except Exception as error:

        result["output"] = str(error)

    return result


def generate_report(
    target,
    findings,
    dependency_audit,
):

    risk = calculate_risk(findings)

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    target_path = Path(target)

    report_name = (
        target_path.stem
        + "_advanced_report.json"
    )

    report_path = REPORT_DIR / report_name

    report = {
        "project": "KAVACH CyberAgent",
        "scan_type": "Advanced Security Audit",
        "timestamp": datetime.now().isoformat(),
        "target": str(
            target_path.resolve()
        ),
        "risk": risk,
        "findings_count": len(findings),
        "findings": findings,
        "dependency_audit": dependency_audit,
        "status": (
            "ISSUES FOUND"
            if findings
            else "NO STATIC ISSUES FOUND"
        ),
    }

    report_path.write_text(
        json.dumps(
            report,
            indent=4,
        ),
        encoding="utf-8",
    )

    return report_path, report


def print_report(
    report_path,
    report,
):

    print()
    print("=" * 60)
    print("           KAVACH ADVANCED SECURITY AUDIT")
    print("=" * 60)

    print()
    print(
        f"Target: {report['target']}"
    )

    print()
    print("========== ADVANCED STATIC ANALYSIS ==========")

    findings = report["findings"]

    if not findings:

        print()
        print(
            "✓ No advanced static security issues found."
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            print()
            print(
                f"[{index}] "
                f"{finding['type']}"
            )

            print(
                f"    Severity: "
                f"{finding['severity']}"
            )

            print(
                f"    Line: "
                f"{finding['line']}"
            )

            print(
                f"    Code: "
                f"{finding['code']}"
            )

            print(
                f"    Explanation: "
                f"{finding['description']}"
            )

    print()
    print("========== RISK ASSESSMENT ==========")

    print(
        f"Risk Level: "
        f"{report['risk']['level']}"
    )

    print(
        f"Risk Score: "
        f"{report['risk']['score']}/10"
    )

    print()
    print("========== DEPENDENCY AUDIT ==========")

    dependency = report[
        "dependency_audit"
    ]

    if dependency["available"]:

        if dependency["success"]:

            print(
                "✓ No vulnerable dependencies "
                "reported by pip-audit."
            )

        else:

            print(
                "⚠ Dependency audit found "
                "potential issues."
            )

        if dependency["output"]:

            print()
            print(
                dependency["output"]
            )

    else:

        print(
            "⚠ pip-audit is not installed."
        )

        print()
        print(
            "Install it with:"
        )

        print(
            "pip install pip-audit"
        )

    print()
    print("========== ADVANCED REPORT ==========")

    print(
        f"Report: "
        f"{report_path.resolve()}"
    )

    print()
    print("=" * 60)
    print("       KAVACH advanced audit completed.")
    print("=" * 60)


def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python advanced_audit.py "
            "<python_file>"
        )

        sys.exit(1)

    target = sys.argv[1]

    try:

        findings = scan_advanced(
            target
        )

    except Exception as error:

        print(
            f"Advanced scan failed: {error}"
        )

        sys.exit(1)

    dependency_audit = (
        run_dependency_audit()
    )

    report_path, report = (
        generate_report(
            target,
            findings,
            dependency_audit,
        )
    )

    print_report(
        report_path,
        report,
    )


if __name__ == "__main__":
    main()
