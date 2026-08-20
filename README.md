# KAVACH CyberAgent

KAVACH CyberAgent is a local automated security analysis and vulnerability
remediation system designed to detect security vulnerabilities, generate
patches, verify the patches, and perform regression testing.

## Features

- Static security scanning
- Vulnerability detection
- Risk assessment
- Automated patch generation
- Patched-code rescanning
- Patch verification
- Docker-based sandbox execution
- Regression testing
- JSON security reports
- Safe replacement for dangerous `eval()`

## Current Vulnerability Detection

KAVACH currently demonstrates detection and remediation of:

1. Command Execution
2. Hardcoded Password
3. Dangerous `eval()`

## Architecture

```text
Source Code
     |
     v
Security Scanner
     |
     v
Risk Assessment
     |
     v
Patch Generator
     |
     v
Patch Engine
     |
     v
Patched Source
     |
     v
Patched Security Scan
     |
     v
Patch Verification
     |
     v
Docker Sandbox
     |
     v
Regression Testing
     |
     v
Final JSON Report
