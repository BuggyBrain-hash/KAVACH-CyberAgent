def generate_patch_suggestions(findings):
    suggestions = []

    for finding in findings:

        if finding["type"] == "Dangerous eval()":
            suggestions.append({
                "line": finding["line"],
                "vulnerability": finding["type"],
                "severity": finding["severity"],
                "suggestion": (
                    "Avoid eval() with untrusted input. "
                    "Use explicit input validation or a safe parser."
                )
            })

        elif finding["type"] == "Hardcoded Password":
            suggestions.append({
                "line": finding["line"],
                "vulnerability": finding["type"],
                "severity": finding["severity"],
                "suggestion": (
                    "Remove the password from source code. "
                    "Use an environment variable or secrets manager."
                )
            })

        elif finding["type"] == "Command Execution":
            suggestions.append({
                "line": finding["line"],
                "vulnerability": finding["type"],
                "severity": finding["severity"],
                "suggestion": (
                    "Avoid os.system() with untrusted input. "
                    "Validate commands and use safer subprocess APIs "
                    "with controlled arguments."
                )
            })

    return suggestions