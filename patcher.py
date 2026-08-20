from pathlib import Path
import re


def create_patched_file(filename, findings):
    """
    Create a patched copy of the source file.

    Local patch rules:
    - Replace eval() with safe_eval()
    - Remove os.system() command execution
    - Replace shell=True with shell=False
    - Remove simple hardcoded passwords
    """

    source_path = Path(filename)

    if not source_path.exists():
        raise FileNotFoundError(
            f"Source file not found: {filename}"
        )

    source_code = source_path.read_text(
        encoding="utf-8"
    )

    patched_code = source_code

    vulnerability_types = {
        str(finding.get("type", "")).lower()
        for finding in findings
    }

    # ========================================================
    # 1. PATCH DANGEROUS eval()
    # ========================================================

    if any(
        "eval" in vulnerability
        for vulnerability in vulnerability_types
    ):

        if "from safe_eval import safe_eval" not in patched_code:

            patched_code = (
                "from safe_eval import safe_eval\n"
                + patched_code
            )

        patched_code = re.sub(
            r"\beval\s*\(",
            "safe_eval(",
            patched_code
        )

    # ========================================================
    # 2. PATCH os.system()
    # ========================================================

    if any(
        (
            "command execution" in vulnerability
            or "os.system" in vulnerability
        )
        for vulnerability in vulnerability_types
    ):

        # Remove simple os.system(...) statements.
        patched_code = re.sub(
            r"(?m)^[ \t]*os\.system\s*\([^)]*\)\s*$",
            "# KAVACH PATCH: Removed dangerous os.system()",
            patched_code
        )

    # ========================================================
    # 3. PATCH subprocess shell=True
    # ========================================================

    if any(
        (
            "command execution" in vulnerability
            or "shell" in vulnerability
        )
        for vulnerability in vulnerability_types
    ):

        patched_code = patched_code.replace(
            "shell=True",
            "shell=False"
        )

    # ========================================================
    # 4. PATCH HARD-CODED PASSWORD
    # ========================================================

    if any(
        "password" in vulnerability
        for vulnerability in vulnerability_types
    ):

        patched_code = re.sub(
            r'(?m)^(\s*)(password|passwd|pwd)'
            r'\s*=\s*["\'][^"\']*["\']\s*$',
            r'\1password = None',
            patched_code
        )

    # ========================================================
    # 5. CREATE PATCHED DIRECTORY
    # ========================================================

    patched_directory = (
        source_path.parent.parent
        / "patched_samples"
    )

    patched_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    patched_filename = (
        source_path.stem
        + "_patched.py"
    )

    patched_path = (
        patched_directory
        / patched_filename
    )

    # ========================================================
    # 6. WRITE PATCHED FILE
    # ========================================================

    patched_path.write_text(
        patched_code,
        encoding="utf-8"
    )

    return str(patched_path)