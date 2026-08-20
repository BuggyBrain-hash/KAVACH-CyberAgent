from sandbox import run_in_sandbox
from test_runner import get_tests_for_file


def run_regression_tests(patched_file, original_file):
    """
    Run the test cases belonging to the original file
    against the patched file.
    """

    tests = get_tests_for_file(original_file)

    if not tests:
        return {
            "success": False,
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "results": [],
            "message": "No test cases found."
        }

    results = []

    passed = 0
    failed = 0

    for test in tests:

        test_name = test.get(
            "name",
            "Unnamed test"
        )

        input_data = test.get(
            "input",
            ""
        )

        expected_exit_code = test.get(
            "expected_exit_code",
            0
        )

        expected_output = test.get(
            "expected_output"
        )

        # Execute the PATCHED program
        execution = run_in_sandbox(
            patched_file,
            input_data
        )

        actual_exit_code = execution.get(
            "return_code"
        )

        actual_output = execution.get(
            "stdout",
            ""
        )

        error = execution.get(
            "stderr",
            ""
        )

        # Check exit code
        exit_code_ok = (
            actual_exit_code ==
            expected_exit_code
        )

        # Check expected output
        output_ok = True

        if expected_output is not None:

            output_ok = (
                expected_output
                in actual_output
            )

        test_passed = (
            exit_code_ok and
            output_ok
        )

        if test_passed:
            passed += 1
        else:
            failed += 1

        results.append({
            "name": test_name,
            "passed": test_passed,
            "expected_exit_code": expected_exit_code,
            "actual_exit_code": actual_exit_code,
            "expected_output": expected_output,
            "actual_output": actual_output,
            "error": error
        })

    return {
        "success": failed == 0,
        "tests_run": len(tests),
        "tests_passed": passed,
        "tests_failed": failed,
        "results": results
    }