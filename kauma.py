import json
import argparse
import sys

from helper import bytes_to_base64
from task01 import (
    add_numbers,
    subtract_numbers,
    poly2block,
    block2poly,
    gfmul,
    sea128,
    full_disc_encryption,
)
from task02 import gcm_encrypt, gcm_decrypt, padding_oracle
from task03 import gfdiv, gfpoly_add, gfpoly_divmod, gfpoly_mul, gfpoly_pow, gfpoly_powmod
from task04 import gfpoly_make_monic, gfpoly_sort, gfpoly_sqrt


def evaluate_testcases(testcase_json: dict) -> dict:
    """
    Evaluate all testcases and return the results
    """
    responses = {}

    for testcase in testcase_json["testcases"]:
        try:
            responses[testcase] = evaluate_testcase(testcase_json["testcases"][testcase])
        except ValueError as e:
            raise ValueError(f"Error in testcase {testcase}: {e}")

    responses = {"responses": responses}

    return responses


def evaluate_testcase(testcase: dict) -> dict:
    """
    Evaluate a single testcase and return the result
    """

    match testcase["action"]:
        case "add_numbers":
            return {"sum": add_numbers(testcase["arguments"])}
        case "subtract_numbers":
            return {"difference": subtract_numbers(testcase["arguments"])}
        case "poly2block":
            try:
                return {"block": bytes_to_base64(poly2block(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in poly2block: {e}")
        case "block2poly":
            try:
                return {"coefficients": block2poly(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in block2poly: {e}")
        case "gfmul":
            try:
                return {"product": bytes_to_base64(gfmul(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in gfmul: {e}")
        case "sea128":
            try:
                return {"output": bytes_to_base64(sea128(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in sea128: {e}")
        case "xex":
            try:
                return {"output": bytes_to_base64(full_disc_encryption(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in block2poly: {e}")
        case "padding_oracle":
            try:
                return {"plaintext": bytes_to_base64(padding_oracle(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in padding_oracle: {e}")
        case "gcm_encrypt":
            try:
                return gcm_encrypt(testcase["arguments"])
            except ValueError as e:
                raise ValueError(f"Error in gcm_encrypt: {e}")
        case "gcm_decrypt":
            try:
                return gcm_decrypt(testcase["arguments"])
            except ValueError as e:
                raise ValueError(f"Error in gcm_decrypt: {e}")
        case "gfpoly_add":
            try:
                return {"S": gfpoly_add(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_add: {e}")
        case "gfpoly_mul":
            try:
                return {"P": gfpoly_mul(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_mul: {e}")
        case "gfpoly_pow":
            try:
                return {"Z": gfpoly_pow(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_pow: {e}")
        case "gfdiv":
            try:
                return {"q": bytes_to_base64(gfdiv(testcase["arguments"]))}
            except ValueError as e:
                raise ValueError(f"Error in gfdiv: {e}")
        case "gfpoly_divmod":
            try:
                return gfpoly_divmod(testcase["arguments"])
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_divmod: {e}")
        case "gfpoly_powmod":
            try:
                return {"Z": gfpoly_powmod(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_powmod: {e}")
        case "gfpoly_sort":
            try:
                return {"sorted_polys": gfpoly_sort(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_sort: {e}")
        case "gfpoly_make_monic":
            try:
                return {"A*": gfpoly_make_monic(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_make_monic: {e}")
        case "gfpoly_sqrt":
            try:
                return {"S": gfpoly_sqrt(testcase["arguments"])}
            except ValueError as e:
                raise ValueError(f"Error in gfpoly_sqrt: {e}")

        case _:
            raise ValueError("Invalid action")
    pass


def main():
    """
    Main function

    Parse the arguments and evaluate the testcases
    """
    parser = argparse.ArgumentParser(description="evaluate testcases from json file")
    parser.add_argument("json_file", type=str, help="json file containing testcases")
    args = parser.parse_args()

    with open(args.json_file, "r") as f:
        testcase_json = json.load(f)

    print(json.dumps(evaluate_testcases(testcase_json)))


if __name__ == "__main__":
    main()
