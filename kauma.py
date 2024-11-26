import json
import argparse

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
from task04 import gfpoly_make_monic, gfpoly_sort


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
            except:
                return {"error": "poly2block"}
        case "block2poly":
            try:
                return {"coefficients": block2poly(testcase["arguments"])}
            except:
                return {"error": "block2poly"}
        case "gfmul":
            try:
                return {"product": bytes_to_base64(gfmul(testcase["arguments"]))}
            except:
                return {"error": "gfmul"}
        case "sea128":
            try:
                return {"output": bytes_to_base64(sea128(testcase["arguments"]))}
            except:
                return {"error": "sea128"}
        case "xex":
            try:
                return {"output": bytes_to_base64(full_disc_encryption(testcase["arguments"]))}
            except:
                return {"error": "xex"}
        case "padding_oracle":
            try:
                return {"plaintext": bytes_to_base64(padding_oracle(testcase["arguments"]))}
            except:
                return {"error": "padding_oracle"}
        case "gcm_encrypt":
            try:
                return gcm_encrypt(testcase["arguments"])
            except:
                return {"error": "gcm_encrypt"}
        case "gcm_decrypt":
            try:
                return gcm_decrypt(testcase["arguments"])
            except:
                return {"error": "gcm_decrypt"}
        case "gfpoly_add":
            try:
                return {"S": gfpoly_add(testcase["arguments"])}
            except:
                return {"error": "gfpoly_add"}
        case "gfpoly_mul":
            try:
                return {"P": gfpoly_mul(testcase["arguments"])}
            except:
                return {"error": "gfpoly_mul"}
        case "gfpoly_pow":
            try:
                return {"Z": gfpoly_pow(testcase["arguments"])}
            except:
                return {"error": "gfpoly_pow"}
        case "gfdiv":
            try:
                return {"q": bytes_to_base64(gfdiv(testcase["arguments"]))}
            except:
                return {"error": "gfdiv"}
        case "gfpoly_divmod":
            try:
                return gfpoly_divmod(testcase["arguments"])
            except:
                return {"error": "gfpoly_divmod"}
        case "gfpoly_powmod":
            try:
                return {"Z": gfpoly_powmod(testcase["arguments"])}
            except:
                return {"error": "gfpoly_powmod"}
        case "gfpoly_sort":
            try:
                return {"sorted_polys": gfpoly_sort(testcase["arguments"])}
            except:
                return {"error": "gfpoly_sort"}
        case "gfpoly_make_monic":
            try:
                return {"A*": gfpoly_make_monic(testcase["arguments"])}
            except Exception as e:
                raise ValueError(f"Error in testcase {testcase}: {e}")
                return {"error": "gfpoly_make_monic"}

        case _:
            return {"error": "not implemented"}
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
