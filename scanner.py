import re


def scan_file(filename):
    findings = []

    with open(filename, "r", encoding="utf-8") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):

        # Ignore comments
        stripped_line = line.strip()

        if stripped_line.startswith("#"):
            continue

        # Remove inline comments
        code_line = line.split("#", 1)[0]

        # Dangerous eval()
        if re.search(r"\beval\s*\(", code_line):
            findings.append({
                "type": "Dangerous eval()",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "description": "eval() can execute user-controlled Python code."
            })

        # Hardcoded password
        if re.search(
            r"(password|passwd|pwd)\s*=\s*[\"']",
            code_line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Hardcoded Password",
                "severity": "MEDIUM",
                "line": line_number,
                "code": line.strip(),
                "description": (
                    "A password appears to be directly stored "
                    "in source code."
                )
            })

        # Command execution
        if re.search(r"os\.system\s*\(", code_line):
            findings.append({
                "type": "Command Execution",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "description": (
                    "os.system() can execute operating-system commands."
                )
            })

    return findings