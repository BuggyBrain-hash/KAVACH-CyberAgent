# 🛡️ KAVACH CyberAgent

### Automated Cybersecurity Vulnerability Detection, Patch Generation & Verification

KAVACH CyberAgent is a Python-based cybersecurity automation tool that detects common security vulnerabilities in Python source code, generates automated security patches, verifies that the vulnerabilities have been removed, and performs regression testing to check that the patched program remains functional.

> **Current status:** Core static-analysis, patching, verification, regression testing, reporting, and Streamlit dashboard are working locally. AI/API integration is planned as a future module.

---

## 🚀 Features

- 🔍 Python source-code security scanning
- 🔐 Hardcoded password detection
- ⚠️ Dangerous `eval()` detection
- 💻 Command-execution detection through `os.system()`
- 📊 Automated risk assessment
- 🛠️ Automated patch generation
- ✅ Patch verification
- 🧪 Regression testing
- 📄 JSON security report generation
- 🖥️ Streamlit dashboard
- 📥 Patched-file download
- 📥 Security-report download
- 🔌 AI/API integration planned for a future version

---

## 🧠 KAVACH Workflow

```text
Python Source Code
        │
        ▼
┌──────────────────────┐
│   Security Scanner   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    Risk Assessment   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Patch Generation   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Patch Verification  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Regression Testing   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   JSON Report        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Streamlit Dashboard  │
└──────────────────────┘