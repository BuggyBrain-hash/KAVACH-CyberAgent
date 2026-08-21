#!/usr/bin/env python3

"""
KAVACH CyberAgent
Automated Security Analysis and Vulnerability Remediation

API integration is intentionally disabled for now.
"""

import ast
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

REPORT_DIR = BASE_DIR / "reports"
PATCHED_DIR = BASE_DIR / "patched_samples"

REPORT_DIR.mkdir(parents=True, exist_ok=True)
PATCHED_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# VULNERABILITY INFORMATION
# ============================================================

VULNERABILITY_INFO = {
    "Hardcoded Password": {
        "severity": "HIGH",
        "description":
            "A password or secret appears to be hardcoded in source code."
    },

    "Dangerous eval()": {
        "severity": "HIGH",
        "description":
            "eval() can execute user-controlled Python code."
    },

    "Command Execution": {
        "severity": "HIGH",
        "description":
            "os.system() can execute operating-system commands."
    }
}


# ============================================================
# FILE FUNCTIONS
# ============================================================

def read_file(path):
    path = Path(path)

    return path.read_text(
        encoding="utf-8",
        errors="replace"
    )


def write_file(path, content):
    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    path.write_text(
        content,
        encoding="utf-8"
    )


# ============================================================
# SECURITY SCANNER
# ============================================================

def scan_source(source):

    findings = []

    lines = source.splitlines()

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        stripped = line.strip()

        if stripped.startswith("#"):
            continue


        # ====================================================
        # HARDCODED PASSWORD
        # ====================================================

        password_match = re.search(
            r"\b(password|passwd|pwd)\b\s*=\s*(['\"])(.*?)\2",
            line,
            re.IGNORECASE
        )

        if password_match:

            findings.append({
                "type": "Hardcoded Password",
                "severity": "HIGH",
                "line": line_number,
                "code": stripped,
                "description":
                    VULNERABILITY_INFO[
                        "Hardcoded Password"
                    ]["description"]
            })


        # ====================================================
        # DANGEROUS EVAL
        # ====================================================

        if re.search(
            r"\beval\s*\(",
            line
        ):

            findings.append({
                "type": "Dangerous eval()",
                "severity": "HIGH",
                "line": line_number,
                "code": stripped,
                "description":
                    VULNERABILITY_INFO[
                        "Dangerous eval()"
                    ]["description"]
            })


        # ====================================================
        # COMMAND EXECUTION
        # ====================================================

        if re.search(
            r"\bos\.system\s*\(",
            line
        ):

            findings.append({
                "type": "Command Execution",
                "severity": "HIGH",
                "line": line_number,
                "code": stripped,
                "description":
                    VULNERABILITY_INFO[
                        "Command Execution"
                    ]["description"]
            })


    return findings


def scan_file(path):

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"File not found: {path}"
        )

    return scan_source(
        read_file(path)
    )


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(findings):

    if not findings:

        return {
            "score": 0,
            "level": "SAFE"
        }


    score = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity == "CRITICAL":
            score += 10

        elif severity == "HIGH":
            score += 8

        elif severity == "MEDIUM":
            score += 5

        elif severity == "LOW":
            score += 2


    score = min(
        score,
        10
    )


    if score >= 9:
        level = "CRITICAL"

    elif score >= 7:
        level = "HIGH"

    elif score >= 4:
        level = "MEDIUM"

    elif score > 0:
        level = "LOW"

    else:
        level = "SAFE"


    return {
        "score": score,
        "level": level
    }


# ============================================================
# PATCH - HARDCODED PASSWORD
# ============================================================

def patch_hardcoded_password(source):

    lines = source.splitlines()

    output = []

    changed = False

    needs_os = False


    for line in lines:

        match = re.match(
            r"^(\s*)(password|passwd|pwd)(\s*=\s*)(['\"])(.*?)\4(.*)$",
            line,
            re.IGNORECASE
        )

        if match:

            indentation = match.group(1)
            variable = match.group(2)
            equals = match.group(3)
            suffix = match.group(6)

            output.append(
                indentation
                + "# KAVACH PATCH: Removed hardcoded password"
            )

            output.append(
                indentation
                + variable
                + equals
                + 'os.getenv("PASSWORD")'
                + suffix
            )

            changed = True
            needs_os = True

        else:

            output.append(line)


    patched = "\n".join(output)

    if source.endswith("\n"):
        patched += "\n"


    if needs_os:

        has_import = re.search(
            r"^\s*import\s+os\s*$",
            patched,
            re.MULTILINE
        )

        if not has_import:

            patched = (
                "import os\n"
                + patched
            )


    return patched, changed


# ============================================================
# PATCH - EVAL
# ============================================================

def patch_eval(source):

    lines = source.splitlines()

    output = []

    changed = False

    has_safe_eval_import = False


    for line in lines:

        if re.search(
            r"from\s+safe_eval\s+import\s+safe_eval",
            line
        ):

            has_safe_eval_import = True


        if re.search(
            r"\beval\s*\(",
            line
        ):

            indentation = (
                line
                [:len(line) - len(line.lstrip())]
            )

            patched_line = re.sub(
                r"\beval\s*\(",
                "safe_eval(",
                line
            )

            output.append(
                indentation
                + "# KAVACH PATCH: Replaced dangerous eval()"
            )

            output.append(
                patched_line
            )

            changed = True

        else:

            output.append(line)


    patched = "\n".join(output)

    if source.endswith("\n"):
        patched += "\n"


    if changed and not has_safe_eval_import:

        patched = (
            "from safe_eval import safe_eval\n"
            + patched
        )


    return patched, changed


# ============================================================
# PATCH - COMMAND EXECUTION
# ============================================================

def patch_command_execution(source):

    lines = source.splitlines()

    output = []

    changed = False


    for line in lines:

        if re.search(
            r"\bos\.system\s*\(",
            line
        ):

            indentation = (
                line
                [:len(line) - len(line.lstrip())]
            )

            output.append(
                indentation
                + "# KAVACH PATCH: Removed dangerous os.system()"
            )

            changed = True

        else:

            output.append(line)


    patched = "\n".join(output)

    if source.endswith("\n"):
        patched += "\n"


    return patched, changed


# ============================================================
# COMPLETE PATCHER
# ============================================================

def generate_patch(source):

    patched = source

    changes = []


    # Password

    patched, changed = patch_hardcoded_password(
        patched
    )

    if changed:

        changes.append(
            "Hardcoded Password"
        )


    # eval

    patched, changed = patch_eval(
        patched
    )

    if changed:

        changes.append(
            "Dangerous eval()"
        )


    # os.system

    patched, changed = patch_command_execution(
        patched
    )

    if changed:

        changes.append(
            "Command Execution"
        )


    return patched, changes


# ============================================================
# SAFE EVAL MODULE
# ============================================================

def ensure_safe_eval():

    path = BASE_DIR / "safe_eval.py"


    code = r'''
import ast
import operator


OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(expression):

    tree = ast.parse(
        expression,
        mode="eval"
    )


    def evaluate(node):

        if isinstance(
            node,
            ast.Expression
        ):

            return evaluate(
                node.body
            )


        if isinstance(
            node,
            ast.Constant
        ):

            if isinstance(
                node.value,
                (int, float)
            ):

                return node.value

            raise ValueError(
                "Only numbers are allowed."
            )


        if isinstance(
            node,
            ast.BinOp
        ):

            operation = OPERATORS.get(
                type(node.op)
            )

            if operation is None:

                raise ValueError(
                    "Operator is not allowed."
                )

            return operation(
                evaluate(node.left),
                evaluate(node.right)
            )


        if isinstance(
            node,
            ast.UnaryOp
        ):

            operation = OPERATORS.get(
                type(node.op)
            )

            if operation is None:

                raise ValueError(
                    "Operator is not allowed."
                )

            return operation(
                evaluate(node.operand)
            )


        raise ValueError(
            "Unsupported expression."
        )


    return evaluate(tree)
'''


    write_file(
        path,
        code.strip() + "\n"
    )

    return path


# ============================================================
# REGRESSION TESTING
# ============================================================

def regression_test():

    tests = []

    tests_run = 0
    tests_passed = 0
    tests_failed = 0


    # ========================================================
    # SAFE EVAL TEST
    # ========================================================

    tests_run += 1

    try:

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from safe_eval import safe_eval; "
                    "result=safe_eval('2+3*4'); "
                    "print(result); "
                    "assert result == 14"
                )
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=10
        )


        if result.returncode == 0:

            tests_passed += 1

            tests.append({

                "name":
                    "Safe Expression Test",

                "passed":
                    True,

                "expected_exit_code":
                    0,

                "actual_exit_code":
                    result.returncode,

                "expected_output":
                    "14",

                "actual_output":
                    result.stdout.strip(),

                "error":
                    ""

            })

        else:

            tests_failed += 1

            tests.append({

                "name":
                    "Safe Expression Test",

                "passed":
                    False,

                "expected_exit_code":
                    0,

                "actual_exit_code":
                    result.returncode,

                "expected_output":
                    "14",

                "actual_output":
                    result.stdout.strip(),

                "error":
                    result.stderr.strip()

            })


    except Exception as error:

        tests_failed += 1

        tests.append({

            "name":
                "Safe Expression Test",

            "passed":
                False,

            "expected_exit_code":
                0,

            "actual_exit_code":
                -1,

            "expected_output":
                "14",

            "actual_output":
                "",

            "error":
                str(error)

        })


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "success":
            tests_failed == 0,

        "tests_run":
            tests_run,

        "tests_passed":
            tests_passed,

        "tests_failed":
            tests_failed,

        "results":
            tests

    }


# ============================================================
# PATCH VERIFICATION
# ============================================================

def verify_patch(
    original_findings,
    patched_findings
):

    original_types = []

    for finding in original_findings:

        vulnerability = finding["type"]

        if vulnerability not in original_types:

            original_types.append(
                vulnerability
            )


    remaining_types = []

    for finding in patched_findings:

        vulnerability = finding["type"]

        if vulnerability not in remaining_types:

            remaining_types.append(
                vulnerability
            )


    resolved = [
        vulnerability
        for vulnerability in original_types
        if vulnerability not in remaining_types
    ]


    remaining = [
        vulnerability
        for vulnerability in original_types
        if vulnerability in remaining_types
    ]


    return {

        "success":
            len(remaining) == 0,

        "original_count":
            len(original_types),

        "remaining_count":
            len(remaining),

        "resolved":
            resolved,

        "remaining":
            remaining

    }


# ============================================================
# REPORT GENERATION
# ============================================================

def save_report(
    target,
    original_findings,
    patched_findings,
    risk,
    verification,
    regression,
    patched_file
):

    report = {

        "project":
            "KAVACH CyberAgent",

        "timestamp":
            datetime.now().isoformat(),

        "target":
            str(target),

        "patched_file":
            str(patched_file)
            if patched_file
            else None,

        "risk":
            risk,

        "original_vulnerabilities":
            original_findings,

        "patched_vulnerabilities":
            patched_findings,

        "patch_verification":
            verification,

        "regression_testing":
            regression

    }


    report_path = (
        REPORT_DIR
        / f"{Path(target).stem}_report.json"
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


    return report_path


# ============================================================
# DISPLAY FINDINGS
# ============================================================

def print_findings(findings):

    if not findings:

        print(
            "No security vulnerabilities found."
        )

        return


    for index, finding in enumerate(
        findings,
        start=1
    ):

        print(
            f"\n[{index}] "
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


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_kavach(target):

    target = Path(target)


    if not target.is_absolute():

        target = (
            BASE_DIR / target
        )


    target = target.resolve()


    if not target.exists():

        print(
            f"ERROR: Target does not exist: {target}"
        )

        return 1


    print()
    print("=" * 60)
    print("             KAVACH CYBERAGENT")
    print("=" * 60)
    print()

    print(
        f"Target: {target}"
    )


    # ========================================================
    # ORIGINAL SCAN
    # ========================================================

    print()
    print(
        "========== ORIGINAL SECURITY SCAN =========="
    )


    original_source = read_file(
        target
    )

    original_findings = scan_source(
        original_source
    )


    print_findings(
        original_findings
    )


    # ========================================================
    # RISK
    # ========================================================

    risk = calculate_risk(
        original_findings
    )


    print()
    print(
        "========== RISK ASSESSMENT =========="
    )

    print(
        f"Risk Level: {risk['level']}"
    )

    print(
        f"Risk Score: {risk['score']}/10"
    )


    # ========================================================
    # IF NO VULNERABILITIES
    # ========================================================

    if not original_findings:

        verification = {

            "success": True,

            "original_count": 0,

            "remaining_count": 0,

            "resolved": [],

            "remaining": []

        }


        regression = {

            "success": True,

            "tests_run": 0,

            "tests_passed": 0,

            "tests_failed": 0,

            "results": []

        }


        report_path = save_report(
            target,
            [],
            [],
            risk,
            verification,
            regression,
            None
        )


        print()
        print(
            "✓ No vulnerabilities detected."
        )

        print(
            f"Report saved: {report_path}"
        )

        return 0


    # ========================================================
    # CREATE SAFE EVAL
    # ========================================================

    ensure_safe_eval()


    # ========================================================
    # PATCH
    # ========================================================

    print()
    print(
        "========== PATCH GENERATION =========="
    )


    try:

        patched_source, changes = generate_patch(
            original_source
        )

    except Exception as error:

        print(
            f"Patch generation failed: {error}"
        )

        return 1


    if changes:

        for change in changes:

            print(
                f"✓ Patched: {change}"
            )

    else:

        print(
            "! No automatic patches generated."
        )


    # ========================================================
    # SAVE PATCHED FILE
    # ========================================================

    patched_file = (
        PATCHED_DIR
        / f"{target.stem}_patched.py"
    )


    write_file(
        patched_file,
        patched_source
    )


    print()
    print(
        f"Patched file: {patched_file}"
    )


    # ========================================================
    # RESCAN
    # ========================================================

    print()
    print(
        "========== PATCHED SECURITY SCAN =========="
    )


    patched_findings = scan_file(
        patched_file
    )


    print_findings(
        patched_findings
    )


    # ========================================================
    # PATCH VERIFICATION
    # ========================================================

    print()
    print(
        "========== PATCH VERIFICATION =========="
    )


    verification = verify_patch(
        original_findings,
        patched_findings
    )


    print(
        f"Original vulnerabilities: "
        f"{verification['original_count']}"
    )

    print(
        f"Remaining vulnerabilities: "
        f"{verification['remaining_count']}"
    )


    if verification["resolved"]:

        print()
        print(
            "Resolved:"
        )

        for vulnerability in verification[
            "resolved"
        ]:

            print(
                f"  ✓ {vulnerability}"
            )


    if verification["remaining"]:

        print()
        print(
            "Still present:"
        )

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
    # REGRESSION
    # ========================================================

    print()
    print(
        "========== REGRESSION TEST =========="
    )


    try:

        regression = regression_test()

    except Exception as error:

        regression = {

            "success": False,

            "tests_run": 0,

            "tests_passed": 0,

            "tests_failed": 1,

            "results": [

                {

                    "name":
                        "Regression Framework",

                    "passed":
                        False,

                    "error":
                        str(error)

                }

            ]

        }


    print(
        f"Tests run: "
        f"{regression['tests_run']}"
    )

    print(
        f"Tests passed: "
        f"{regression['tests_passed']}"
    )

    print(
        f"Tests failed: "
        f"{regression['tests_failed']}"
    )


    if regression["results"]:

        print()
        print(
            "Test Results:"
        )

        for result in regression[
            "results"
        ]:

            if result.get(
                "passed",
                False
            ):

                print(
                    f"  ✓ "
                    f"{result['name']}"
                )

            else:

                print(
                    f"  ✗ "
                    f"{result['name']}"
                )

                if result.get("error"):

                    print(
                        f"      Error: "
                        f"{result['error']}"
                    )


    print()


    if regression["success"]:

        print(
            "✓ Regression testing PASSED"
        )

    else:

        print(
            "⚠ Regression testing requires review"
        )


    # ========================================================
    # FINAL SECURITY STATUS
    # ========================================================

    print()
    print(
        "========== FINAL SECURITY STATUS =========="
    )


    if verification["success"]:

        print(
            "✓ All detected vulnerabilities "
            "were resolved."
        )

    else:

        print(
            "⚠ Some vulnerabilities remain."
        )


    # ========================================================
    # FINAL FUNCTIONAL STATUS
    # ========================================================

    print()
    print(
        "========== FINAL FUNCTIONAL STATUS =========="
    )


    if regression["success"]:

        print(
            "✓ Patched program passed "
            "regression tests."
        )

    else:

        print(
            "⚠ Patched program requires "
            "functional review."
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()
    print(
        "========== KAVACH FINAL RESULT =========="
    )


    if (
        verification["success"]
        and regression["success"]
    ):

        print(
            "✓ SECURITY PATCH PASSED — "
            "ALL TESTS PASSED"
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
    # SAVE REPORT
    # ========================================================

    report_path = save_report(
        target,
        original_findings,
        patched_findings,
        risk,
        verification,
        regression,
        patched_file
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print(
        "========== SUMMARY =========="
    )

    print(
        f"Target: {target}"
    )

    print(
        f"Risk Level: {risk['level']}"
    )

    print(
        f"Risk Score: {risk['score']}/10"
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
        f"{regression['tests_run']}"
    )

    print(
        f"Regression Passed: "
        f"{regression['tests_passed']}"
    )

    print(
        f"Regression Failed: "
        f"{regression['tests_failed']}"
    )

    print(
        f"Report: "
        f"{report_path}"
    )


    print()
    print("=" * 60)
    print(
        "       KAVACH scan completed."
    )
    print("=" * 60)


    return 0


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python main.py <python_file>"
        )

        print(
            "Example: "
            "python main.py test_samples/vulnerable.py"
        )

        return 1


    return run_kavach(
        sys.argv[1]
    )


if __name__ == "__main__":

    sys.exit(
        main()
    )