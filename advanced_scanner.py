import ast
import re
from pathlib import Path


class AdvancedSecurityScanner(ast.NodeVisitor):

    def __init__(self, source):

        self.source = source
        self.lines = source.splitlines()
        self.findings = []

    def line(self, number):

        if 1 <= number <= len(self.lines):
            return self.lines[number - 1].strip()

        return ""

    def add(
        self,
        vulnerability,
        severity,
        node,
        description,
    ):

        line_number = getattr(
            node,
            "lineno",
            1,
        )

        self.findings.append({
            "type": vulnerability,
            "severity": severity,
            "line": line_number,
            "code": self.line(line_number),
            "description": description,
        })

    # --------------------------------------------------------
    # Dangerous functions
    # --------------------------------------------------------

    def visit_Call(self, node):

        # eval()
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ):

            self.add(
                "Dangerous eval()",
                "HIGH",
                node,
                "eval() can execute dynamically supplied "
                "Python expressions.",
            )

        # exec()
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ):

            self.add(
                "Dangerous exec()",
                "CRITICAL",
                node,
                "exec() can execute arbitrary Python code.",
            )

        # os.system()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):

            self.add(
                "Command Execution",
                "HIGH",
                node,
                "os.system() can execute operating-system "
                "commands.",
            )

        # ----------------------------------------------------
        # subprocess shell=True
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "run",
                "call",
                "Popen",
                "check_call",
                "check_output",
            }
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):

            for keyword in node.keywords:

                if keyword.arg == "shell":

                    if (
                        isinstance(
                            keyword.value,
                            ast.Constant,
                        )
                        and keyword.value.value is True
                    ):

                        self.add(
                            "Command Injection",
                            "HIGH",
                            node,
                            "subprocess is using shell=True.",
                        )

        # ----------------------------------------------------
        # pickle
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "loads",
                "load",
            }
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ):

            self.add(
                "Unsafe Deserialization",
                "HIGH",
                node,
                "pickle can execute arbitrary code when "
                "untrusted serialized data is loaded.",
            )

        # ----------------------------------------------------
        # hashlib
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
        ):

            if node.func.attr == "md5":

                self.add(
                    "Weak Cryptography",
                    "MEDIUM",
                    node,
                    "MD5 should not be used for "
                    "security-sensitive hashing.",
                )

            if node.func.attr == "sha1":

                self.add(
                    "Weak Cryptography",
                    "MEDIUM",
                    node,
                    "SHA-1 is weak for modern "
                    "security-sensitive applications.",
                )

        # ----------------------------------------------------
        # requests verify=False
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {
                "get",
                "post",
                "put",
                "delete",
                "request",
            }
        ):

            for keyword in node.keywords:

                if keyword.arg == "verify":

                    if (
                        isinstance(
                            keyword.value,
                            ast.Constant,
                        )
                        and keyword.value.value is False
                    ):

                        self.add(
                            "TLS Certificate Verification Disabled",
                            "HIGH",
                            node,
                            "TLS certificate verification is "
                            "disabled with verify=False.",
                        )

        # ----------------------------------------------------
        # yaml.load()
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
        ):

            has_safe_loader = False

            for keyword in node.keywords:

                if keyword.arg == "Loader":

                    has_safe_loader = True

            if not has_safe_loader:

                self.add(
                    "Unsafe YAML Loading",
                    "HIGH",
                    node,
                    "yaml.load() should use a safe loader "
                    "when processing untrusted data.",
                )

        # ----------------------------------------------------
        # random module
        # ----------------------------------------------------

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "random"
            and node.func.attr in {
                "random",
                "randint",
                "choice",
                "randrange",
            }
        ):

            self.add(
                "Weak Randomness",
                "MEDIUM",
                node,
                "The random module is not designed for "
                "security-sensitive random values.",
            )

        self.generic_visit(node)

    # --------------------------------------------------------
    # SQL injection heuristic
    # --------------------------------------------------------

    def visit_BinOp(self, node):

        if isinstance(
            node.op,
            ast.Add,
        ):

            left = node.left

            if isinstance(
                left,
                ast.Constant,
            ) and isinstance(
                left.value,
                str,
            ):

                sql_words = (
                    "select ",
                    "insert ",
                    "update ",
                    "delete ",
                    "where ",
                )

                if left.value.lower().startswith(
                    sql_words
                ):

                    self.add(
                        "Potential SQL Injection",
                        "HIGH",
                        node,
                        "SQL query appears to be constructed "
                        "using string concatenation.",
                    )

        self.generic_visit(node)


# ============================================================
# SECRET DETECTION
# ============================================================

SECRET_PATTERN = re.compile(
    r"""
    \b(
        password|
        passwd|
        api[_-]?key|
        secret|
        access[_-]?token|
        auth[_-]?token|
        private[_-]?key
    )
    \s*=\s*
    ["'][^"']{4,}["']
    """,
    re.IGNORECASE | re.VERBOSE,
)


def scan_advanced(file_path):

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(file_path)

    source = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    findings = []

    # --------------------------------------------------------
    # Regex secret detection
    # --------------------------------------------------------

    for number, line in enumerate(
        source.splitlines(),
        start=1,
    ):

        if SECRET_PATTERN.search(line):

            findings.append({
                "type": "Hardcoded Secret",
                "severity": "HIGH",
                "line": number,
                "code": line.strip(),
                "description":
                    "A possible hardcoded credential or "
                    "secret was detected.",
            })

    # --------------------------------------------------------
    # AST analysis
    # --------------------------------------------------------

    try:

        tree = ast.parse(
            source,
            filename=str(path),
        )

        scanner = AdvancedSecurityScanner(
            source
        )

        scanner.visit(tree)

        findings.extend(
            scanner.findings
        )

    except SyntaxError as error:

        findings.append({
            "type": "Syntax Error",
            "severity": "MEDIUM",
            "line": error.lineno or 1,
            "code": "",
            "description":
                f"Unable to parse Python source: "
                f"{error.msg}",
        })

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique = []
    seen = set()

    for finding in findings:

        key = (
            finding["type"],
            finding["line"],
            finding["code"],
        )

        if key not in seen:

            seen.add(key)
            unique.append(finding)

    unique.sort(
        key=lambda x: (
            x["line"],
            x["type"],
        )
    )

    return unique


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python advanced_scanner.py <file>"
        )

        raise SystemExit(1)

    results = scan_advanced(
        sys.argv[1]
    )

    if not results:

        print(
            "No advanced security issues found."
        )

    else:

        print(
            f"Found {len(results)} advanced "
            f"security issue(s):"
        )

        for index, finding in enumerate(
            results,
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
