SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0
}


def calculate_risk(findings):

    if not findings:
        return 0

    total = sum(
        SEVERITY_SCORES.get(
            finding["severity"].upper(),
            0
        )
        for finding in findings
    )

    return min(total, 10)


def get_risk_level(score):

    if score >= 9:
        return "CRITICAL"

    if score >= 7:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "SAFE"