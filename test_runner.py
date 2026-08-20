import json
from pathlib import Path


def load_test_cases(filename="test_cases.json"):

    path = Path(filename)

    if not path.exists():
        return {}

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_tests_for_file(source_file):

    test_cases = load_test_cases()

    return test_cases.get(source_file, [])