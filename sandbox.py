import subprocess
from pathlib import Path


def run_in_sandbox(filename, input_data=""):
    """
    Execute a Python file inside an isolated Docker container.

    The target Python file is mounted as /sandbox/test_file.py.
    safe_eval.py is also mounted so patched programs can import it.
    """

    filename = Path(filename).resolve()

    if not filename.exists():
        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": f"File not found: {filename}"
        }

    # Find the KAVACH project directory.
    project_root = Path(__file__).resolve().parent

    safe_eval_file = project_root / "safe_eval.py"

    command = [
        "docker",
        "run",
        "-i",
        "--rm",

        # Disable network access.
        "--network",
        "none",

        # Resource limits.
        "--memory",
        "128m",

        "--cpus",
        "0.5",

        # Mount the patched/original program.
        "-v",
        f"{filename}:/sandbox/test_file.py:ro",

        # Mount safe_eval.py if it exists.
        "-v",
        f"{safe_eval_file}:/sandbox/safe_eval.py:ro",

        # Python image.
        "python:3.13-slim",

        # Execute the program.
        "python",
        "/sandbox/test_file.py"
    ]

    try:

        result = subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": "Sandbox execution timed out."
        }

    except Exception as error:

        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": str(error)
        }