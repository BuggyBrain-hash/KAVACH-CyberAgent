import json
from pathlib import Path
from datetime import datetime


def save_report(
    filename,
    findings,
    patched_findings=None,
    risk_score=None,
    risk_level=None,
    verification=None,
    regression=None
):
    """
    Save a complete KAVACH security report.
    """

    report = {
        "project": "KAVACH CyberAgent",

        "timestamp": datetime.now().isoformat(),

        "target": filename,

        "risk": {
            "score": risk_score,
            "level": risk_level
        },

        "original_vulnerabilities": findings,

        "patched_vulnerabilities": (
            patched_findings
            if patched_findings is not None
            else []
        ),

        "patch_verification": (
            verification
            if verification is not None
            else {}
        ),

        "regression_testing": (
            regression
            if regression is not None
            else {}
        )
    }

    reports_directory = Path("reports")

    reports_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    target_name = Path(filename).stem

    report_path = (
        reports_directory
        / f"{target_name}_report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return str(report_path)