from scanner import scan_file


def test_safe_file():

    findings = scan_file(
        "test_samples/calculator.py"
    )

    assert len(findings) == 0