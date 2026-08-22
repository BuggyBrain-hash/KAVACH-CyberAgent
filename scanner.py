import ast
import re
from pathlib import Path


# ============================================================
# KAVACH SECURITY SCANNER
# ============================================================

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def make_finding(
    vulnerability_type,
    severity,
    line,
    code,
    description,
):
    return {
        "type": vulnerability_type,
        "severity": severity,
        "line": line,
        "code": code.strip(),
        "description": description,
    }


# ============================================================
# HARD-CODED PASSWORD / SECRET DETECTION
# ============================================================

SECRET_PATTERN = re.compile(
    r"""
    \b(
        password|
        passwd|
        pwd|
        secret|
        api[_-]?key|
        access[_-]?key|
        auth[_-]?token|
        private[_-]?key
    )
    \s*
    =
    \s*
    (
        ["'][^"']+["']
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def detect_hardcoded_secrets(source):

    findings = []

    lines = source.splitlines()

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        match = SECRET_PATTERN.search(line)

        if not match:
            continue

        value = match.group(2)

        # Ignore empty strings.
        if value in ('""', "''"):
            continue

        findings.append(
            make_finding(
                "Hardcoded Password",
                "HIGH",
                line_number,
                line,
                "A password or secret appears to be "
                "hardcoded in source code.",
            )
        )

    return findings


# ============================================================
# AST SECURITY VISITOR
# ============================================================

class SecurityVisitor(ast.NodeVisitor):

    def __init__(self, source_lines):

        self.source_lines = source_lines
        self.findings = []

    def get_line_code(self, line_number):

        if (
            0 < line_number
            <= len(self.source_lines)
        ):

            return self.source_lines[
                line_number - 1
            ]

        return ""

    # ========================================================
    # FUNCTION CALL DETECTION
    # ========================================================

    def visit_Call(self, node):

        line_number = getattr(
            node,
            "lineno",
            1
        )

        code = self.get_line_code(
            line_number
        )

        # ----------------------------------------------------
        # Dangerous eval()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ):

            self.findings.append(
                make_finding(
                    "Dangerous eval()",
                    "HIGH",
                    line_number,
                    code,
                    "eval() can execute user-controlled "
                    "Python code.",
                )
            )

        # ----------------------------------------------------
        # os.system()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
            and isinstance(
                node.func.value,
                ast.Name
            )
            and node.func.value.id == "os"
        ):

            self.findings.append(
                make_finding(
                    "Command Execution",
                    "HIGH",
                    line_number,
                    code,
                    "os.system() can execute "
                    "operating-system commands.",
                )
            )

        # ----------------------------------------------------
        # subprocess(..., shell=True)
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "run",
                "call",
                "check_call",
                "check_output",
                "Popen",
            }
            and isinstance(
                node.func.value,
                ast.Name
            )
            and node.func.value.id == "subprocess"
        ):

            for keyword in node.keywords:

                if keyword.arg != "shell":
                    continue

                if (
                    isinstance(
                        keyword.value,
                        ast.Constant
                    )
                    and keyword.value.value is True
                ):

                    self.findings.append(
                        make_finding(
                            "Command Injection",
                            "HIGH",
                            line_number,
                            code,
                            "subprocess is configured with "
                            "shell=True, which can allow command "
                            "injection when attacker-controlled "
                            "input is used.",
                        )
                    )

        # ----------------------------------------------------
        # pickle.loads() / pickle.load()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "loads",
                "load",
            }
            and isinstance(
                node.func.value,
                ast.Name
            )
            and node.func.value.id == "pickle"
        ):

            self.findings.append(
                make_finding(
                    "Unsafe Deserialization",
                    "HIGH",
                    line_number,
                    code,
                    "pickle deserialization of untrusted "
                    "data can lead to arbitrary code execution.",
                )
            )

        # ----------------------------------------------------
        # hashlib.md5()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "md5"
            and isinstance(
                node.func.value,
                ast.Name
            )
            and node.func.value.id == "hashlib"
        ):

            self.findings.append(
                make_finding(
                    "Weak Cryptography",
                    "MEDIUM",
                    line_number,
                    code,
                    "MD5 is cryptographically broken and "
                    "should not be used for security-sensitive "
                    "operations.",
                )
            )

        # ----------------------------------------------------
        # hashlib.sha1()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "sha1"
            and isinstance(
                node.func.value,
                ast.Name
            )
            and node.func.value.id == "hashlib"
        ):

            self.findings.append(
                make_finding(
                    "Weak Cryptography",
                    "MEDIUM",
                    line_number,
                    code,
                    "SHA-1 is weak for modern "
                    "security-sensitive applications.",
                )
            )

        self.generic_visit(node)


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def scan_file(file_path):

    path = Path(file_path)

    if not path.exists():

        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not path.is_file():

        raise ValueError(
            f"Not a file: {file_path}"
        )

    source = path.read_text(
        encoding="utf-8",
        errors="replace"
    )

    findings = []

    # ========================================================
    # SECRET DETECTION
    # ========================================================

    findings.extend(
        detect_hardcoded_secrets(
            source
        )
    )

    # ========================================================
    # AST ANALYSIS
    # ========================================================

    try:

        tree = ast.parse(
            source,
            filename=str(path)
        )

        visitor = SecurityVisitor(
            source.splitlines()
        )

        visitor.visit(tree)

        findings.extend(
            visitor.findings
        )

    except SyntaxError as error:

        findings.append(
            make_finding(
                "Syntax Error",
                "MEDIUM",
                error.lineno or 1,
                "",
                f"Python syntax could not be parsed: "
                f"{error.msg}",
            )
        )

    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    unique_findings = []

    seen = set()

    for finding in findings:

        key = (
            finding["type"],
            finding["line"],
            finding["code"],
        )

        if key in seen:
            continue

        seen.add(key)

        unique_findings.append(
            finding
        )

    # ========================================================
    # SORT FINDINGS
    # ========================================================

    unique_findings.sort(
        key=lambda item: (
            item["line"],
            -SEVERITY_ORDER.get(
                item["severity"],
                0
            ),
            item["type"],
        )
    )

    return unique_findings


# ============================================================
# COMMAND-LINE MODE
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python scanner.py <python_file>"
        )

        sys.exit(1)

    target = sys.argv[1]

    results = scan_file(
        target
    )

    if not results:

        print(
            "No security vulnerabilities found."
        )

        sys.exit(0)

    print(
        f"Found {len(results)} security issue(s):"
    )

    for index, finding in enumerate(
        results,
        start=1
    ):

        print()

        print(
            f"[{index}] {finding['type']}"
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