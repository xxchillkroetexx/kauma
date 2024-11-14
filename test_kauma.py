import pytest
import json
from kauma import *


def test_01_evaluate_testcases():

    with open("testcases/task01.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task01_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_02_evaluate_testcases():

    with open("testcases/task02.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task02_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_03_evaluate_testcases():

    with open("testcases/task03.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task03_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_gfmul():
    with open("testcases/gfmul_args.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfmul_results.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_gcm_block_poly():
    with open("testcases/gcm_block_poly.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm_block_poly_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_gcm_encrypt():
    with open("testcases/gcm_encrypt_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm_encrypt_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


def test_gcm_decrypt():
    with open("testcases/gcm_decrypt_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm_decrypt_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json

    pass


if __name__ == "__main__":
    pytest.main()
