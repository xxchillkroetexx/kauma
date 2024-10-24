import json
import argparse

from task01 import *


def evaluate_testcases(testcase_json: dict) -> dict:
    """
    Evaluate all testcases and return the results
    """
    responses = {}

    for testcase in testcase_json["testcases"]:
        try:
            responses[testcase] = evaluate_testcase(
                testcase_json["testcases"][testcase]
            )
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
                return {
                    "output": bytes_to_base64(
                        full_disc_encryption(testcase["arguments"])
                    )
                }
            except ValueError as e:
                raise ValueError(f"Error in block2poly: {e}")

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
