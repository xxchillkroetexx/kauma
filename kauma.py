import json
import argparse

from task01 import *


def evaluate_testcases(testcase_json):
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


def evaluate_testcase(testcase):
    """
    Evaluate a single testcase and return the result
    """

    match testcase["action"]:
        case "add_numbers":
            return add_numbers(testcase["arguments"])
        case "subtract_numbers":
            return subtract_numbers(testcase["arguments"])
        case _:
            raise ValueError("Invalid action")
    pass


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="evaluate testcases from json file")
    parser.add_argument("json_file", type=str, help="json file containing testcases")
    args = parser.parse_args()

    with open(args.json_file, "r") as f:
        testcase_json = json.load(f)

    print(evaluate_testcases(testcase_json))
