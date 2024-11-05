import pytest
import json
from kauma import *


def test_01_evaluate_testcases():

    with open("testcases/task01.json") as file:
        testcases_json = json.load(file)
    with open("testcases/task01_output.json") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_02_gfmul():
    with open("testcases/gfmul_args.json") as file:
        testcases_json = json.load(file)
    with open("testcases/gfmul_results.json") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


if __name__ == "__main__":
    pytest.main()
