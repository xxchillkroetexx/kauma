import pytest
import json
from kauma import *


def test_01_evaluate_testcases():

    with open("testcases/task01.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task01_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_02_evaluate_testcases():

    with open("testcases/task02.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task02_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_03_evaluate_testcases():

    with open("testcases/task03.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/task03_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfmul():
    with open("testcases/gfmul_args.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfmul_results.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gcm_block_poly():
    with open("testcases/gcm/gcm_block_poly.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm/gcm_block_poly_output.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gcm_encrypt():
    with open("testcases/gcm/gcm_encrypt_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm/gcm_encrypt_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gcm_decrypt():
    with open("testcases/gcm/gcm_decrypt_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gcm/gcm_decrypt_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfdiv():
    with open("testcases/gfdiv_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfdiv_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfpoly_add():
    with open("testcases/gfpoly/gfpoly_add_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfpoly/gfpoly_add_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfpoly_mul():
    with open("testcases/gfpoly/gfpoly_mul_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfpoly/gfpoly_mul_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfpoly_pow():
    with open("testcases/gfpoly/gfpoly_pow_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfpoly/gfpoly_pow_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfpoly_divmod():
    with open("testcases/gfpoly/gfpoly_divmod_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfpoly/gfpoly_divmod_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


def test_gfpoly_powmod():
    with open("testcases/gfpoly/gfpoly_powmod_in.json", "r") as file:
        testcases_json = json.load(file)
    with open("testcases/gfpoly/gfpoly_powmod_out.json", "r") as file:
        output_json = json.load(file)

    assert evaluate_testcases(testcase_json=testcases_json) == output_json


if __name__ == "__main__":
    pytest.main()
