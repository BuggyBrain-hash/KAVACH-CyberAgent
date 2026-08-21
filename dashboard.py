import json
import subprocess
import sys
from pathlib import Path

import streamlit as st


# ============================================================
# KAVACH CYBERAGENT DASHBOARD
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

REPORT_DIR = BASE_DIR / "reports"
PATCHED_DIR = BASE_DIR / "patched_samples"
UPLOAD_DIR = BASE_DIR / "uploaded_samples"

REPORT_DIR.mkdir(exist_ok=True)
PATCHED_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="KAVACH CyberAgent",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ KAVACH CyberAgent")

st.subheader(
    "AI-Assisted Cybersecurity Vulnerability Detection "
    "and Automated Patch Verification"
)

st.markdown(
    """
    **KAVACH** scans Python source code for security
    vulnerabilities, generates patches, verifies the patches,
    and performs regression testing.
    """
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ KAVACH")

st.sidebar.markdown(
    """
    ### Pipeline

    1. 📁 Upload Python File
    2. 🔍 Security Scan
    3. 📊 Risk Assessment
    4. 🛠️ Patch Generation
    5. ✅ Patch Verification
    6. 🧪 Regression Testing
    7. 📄 Final Report
    """
)

st.sidebar.divider()

st.sidebar.info(
    "API/LLM integration is currently disabled. "
    "The deterministic security pipeline works locally."
)


# ============================================================
# FILE UPLOAD
# ============================================================

st.header("📁 Upload Python Source File")

uploaded_file = st.file_uploader(
    "Choose a Python file",
    type=["py"]
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def find_latest_report():

    reports = list(
        REPORT_DIR.glob("*_report.json")
    )

    if not reports:
        return None

    return max(
        reports,
        key=lambda path: path.stat().st_mtime
    )


def load_report(path):

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        st.error(
            f"Could not read report: {error}"
        )

        return None


def run_kavach(file_path):

    try:

        result = subprocess.run(
            [
                sys.executable,
                str(BASE_DIR / "main.py"),
                str(file_path)
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=120
        )

        return result

    except subprocess.TimeoutExpired:

        st.error(
            "KAVACH scan timed out."
        )

        return None

    except Exception as error:

        st.error(
            f"Could not start KAVACH: {error}"
        )

        return None


def severity_color(severity):

    if severity == "CRITICAL":
        return "🔴"

    if severity == "HIGH":
        return "🟠"

    if severity == "MEDIUM":
        return "🟡"

    return "🟢"


# ============================================================
# PROCESS UPLOADED FILE
# ============================================================

if uploaded_file is not None:

    upload_path = (
        UPLOAD_DIR
        / uploaded_file.name
    )

    with open(
        upload_path,
        "wb"
    ) as file:

        file.write(
            uploaded_file.getbuffer()
        )


    st.success(
        f"Uploaded: `{uploaded_file.name}`"
    )


    # ========================================================
    # SOURCE PREVIEW
    # ========================================================

    with st.expander(
        "👁️ View Uploaded Source Code"
    ):

        try:

            source_code = upload_path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            st.code(
                source_code,
                language="python"
            )

        except Exception as error:

            st.error(
                f"Could not display source: {error}"
            )


    # ========================================================
    # SCAN BUTTON
    # ========================================================

    if st.button(
        "🚀 Run KAVACH Security Scan",
        type="primary",
        use_container_width=True
    ):

        with st.spinner(
            "KAVACH is scanning, patching and testing..."
        ):

            result = run_kavach(
                upload_path
            )


        if result is None:

            st.stop()


        if result.returncode != 0:

            st.error(
                "KAVACH encountered an error."
            )

            with st.expander(
                "View Error Details"
            ):

                st.code(
                    result.stderr
                )

            st.stop()


        st.success(
            "KAVACH scan completed successfully."
        )


        # ====================================================
        # OUTPUT
        # ====================================================

        with st.expander(
            "🖥️ View KAVACH Terminal Output"
        ):

            st.code(
                result.stdout
            )


        st.session_state[
            "last_report"
        ] = str(
            find_latest_report()
        )


# ============================================================
# LOAD REPORT
# ============================================================

report_path = None


if "last_report" in st.session_state:

    candidate = Path(
        st.session_state["last_report"]
    )

    if candidate.exists():

        report_path = candidate


if report_path is None:

    report_path = find_latest_report()


if report_path is not None:

    report = load_report(
        report_path
    )

else:

    report = None


# ============================================================
# DISPLAY DASHBOARD
# ============================================================

if report:

    st.divider()

    st.header("📊 Security Analysis Dashboard")


    # ========================================================
    # TOP METRICS
    # ========================================================

    risk = report.get(
        "risk",
        {}
    )

    verification = report.get(
        "patch_verification",
        {}
    )

    regression = report.get(
        "regression_testing",
        {}
    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "Risk Level",
            risk.get(
                "level",
                "UNKNOWN"
            )
        )


    with col2:

        st.metric(
            "Risk Score",
            f"{risk.get('score', 0)}/10"
        )


    with col3:

        st.metric(
            "Original Findings",
            len(
                report.get(
                    "original_vulnerabilities",
                    []
                )
            )
        )


    with col4:

        st.metric(
            "Remaining Findings",
            len(
                report.get(
                    "patched_vulnerabilities",
                    []
                )
            )
        )


    # ========================================================
    # SECURITY STATUS
    # ========================================================

    st.subheader(
        "🛡️ Security Status"
    )


    if verification.get(
        "success",
        False
    ):

        st.success(
            "PATCH VERIFICATION PASSED — "
            "All detected vulnerabilities were resolved."
        )

    else:

        st.error(
            "PATCH VERIFICATION FAILED — "
            "Some vulnerabilities remain."
        )


    # ========================================================
    # REGRESSION STATUS
    # ========================================================

    if regression.get(
        "success",
        False
    ):

        st.success(
            "REGRESSION TESTING PASSED"
        )

    else:

        st.warning(
            "REGRESSION TESTING REQUIRES REVIEW"
        )


    # ========================================================
    # ORIGINAL VULNERABILITIES
    # ========================================================

    st.subheader(
        "🔍 Original Vulnerabilities"
    )


    original = report.get(
        "original_vulnerabilities",
        []
    )


    if original:

        for index, finding in enumerate(
            original,
            start=1
        ):

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            icon = severity_color(
                severity
            )


            with st.expander(
                f"{icon} {index}. "
                f"{finding.get('type', 'Unknown')}"
            ):

                st.write(
                    f"**Severity:** {severity}"
                )

                st.write(
                    f"**Line:** "
                    f"{finding.get('line', '-')}"
                )

                st.write(
                    f"**Description:** "
                    f"{finding.get('description', '-')}"
                )

                st.code(
                    finding.get(
                        "code",
                        ""
                    ),
                    language="python"
                )

    else:

        st.info(
            "No vulnerabilities were detected."
        )


    # ========================================================
    # RESOLVED VULNERABILITIES
    # ========================================================

    st.subheader(
        "✅ Resolved Vulnerabilities"
    )


    resolved = verification.get(
        "resolved",
        []
    )


    if resolved:

        for vulnerability in resolved:

            st.success(
                f"✓ {vulnerability}"
            )

    else:

        st.info(
            "No vulnerabilities were resolved."
        )


    # ========================================================
    # REMAINING VULNERABILITIES
    # ========================================================

    remaining = verification.get(
        "remaining",
        []
    )


    st.subheader(
        "⚠️ Remaining Vulnerabilities"
    )


    if remaining:

        for vulnerability in remaining:

            st.error(
                f"! {vulnerability}"
            )

    else:

        st.success(
            "No detected vulnerabilities remain."
        )


    # ========================================================
    # REGRESSION TEST RESULTS
    # ========================================================

    st.subheader(
        "🧪 Regression Testing"
    )


    test_col1, test_col2, test_col3 = st.columns(3)


    with test_col1:

        st.metric(
            "Tests Run",
            regression.get(
                "tests_run",
                0
            )
        )


    with test_col2:

        st.metric(
            "Tests Passed",
            regression.get(
                "tests_passed",
                0
            )
        )


    with test_col3:

        st.metric(
            "Tests Failed",
            regression.get(
                "tests_failed",
                0
            )
        )


    results = regression.get(
        "results",
        []
    )


    if results:

        for test in results:

            if test.get(
                "passed",
                False
            ):

                st.success(
                    f"✓ {test.get('name', 'Test')}"
                )

            else:

                st.error(
                    f"✗ {test.get('name', 'Test')}"
                )

                if test.get("error"):

                    st.code(
                        test["error"]
                    )


    # ========================================================
    # PATCHED FILE
    # ========================================================

    st.subheader(
        "🛠️ Patched Source Code"
    )


    patched_file = report.get(
        "patched_file"
    )


    if patched_file:

        patched_path = Path(
            patched_file
        )


        if patched_path.exists():

            patched_code = patched_path.read_text(
                encoding="utf-8",
                errors="replace"
            )


            st.success(
                f"Patched file: `{patched_path.name}`"
            )


            st.code(
                patched_code,
                language="python"
            )


            st.download_button(
                label="📥 Download Patched File",
                data=patched_code,
                file_name=patched_path.name,
                mime="text/plain",
                use_container_width=True
            )

        else:

            st.warning(
                "Patched file was recorded in the report "
                "but could not be found."
            )


    # ========================================================
    # JSON REPORT
    # ========================================================

    st.subheader(
        "📄 Final Security Report"
    )


    with open(
        report_path,
        "r",
        encoding="utf-8"
    ) as file:

        report_text = file.read()


    st.download_button(
        label="📥 Download JSON Security Report",
        data=report_text,
        file_name=report_path.name,
        mime="application/json",
        use_container_width=True
    )


    with st.expander(
        "View Complete JSON Report"
    ):

        st.json(
            report
        )


    # ========================================================
    # PROJECT INFORMATION
    # ========================================================

    st.divider()

    st.subheader(
        "ℹ️ Project Information"
    )


    info_col1, info_col2 = st.columns(2)


    with info_col1:

        st.write(
            "**Project:** KAVACH CyberAgent"
        )

        st.write(
            "**Target:** "
            + str(
                report.get(
                    "target",
                    "-"
                )
            )
        )


    with info_col2:

        st.write(
            "**Report Generated:** "
            + str(
                report.get(
                    "timestamp",
                    "-"
                )
            )
        )

        st.write(
            "**Patched File:** "
            + str(
                report.get(
                    "patched_file",
                    "-"
                )
            )
        )


else:

    # ========================================================
    # NO REPORT
    # ========================================================

    st.info(
        "👆 Upload a Python file and click "
        "**Run KAVACH Security Scan** to begin."
    )


    st.markdown(
        """
        ### What KAVACH does

        | Stage | Function |
        |---|---|
        | 🔍 Scanner | Detects security vulnerabilities |
        | 📊 Risk Engine | Calculates security risk |
        | 🛠️ Patcher | Generates security patches |
        | ✅ Verifier | Confirms vulnerabilities are removed |
        | 🧪 Regression Tester | Checks functionality |
        | 📄 Reporter | Generates the final JSON report |
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "KAVACH CyberAgent • Cybersecurity Automation Project"
)