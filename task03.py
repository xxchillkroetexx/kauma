from classes import GALOIS_ELEMENT_128
from helper import *


def gfpoly_add(args: dict) -> list[str]:
    A_b64 = args["A"]
    B_b64 = args["B"]

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(coeff) for coeff in A_b64]
    B_bytes = [base64_to_bytes(coeff) for coeff in B_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=int.from_bytes(coeff), mode="gcm") for coeff in A_bytes]
    B = [GALOIS_ELEMENT_128(value=int.from_bytes(coeff), mode="gcm") for coeff in B_bytes]

    # Pad shorter list with zeroes
    max_len = max(len(A), len(B))
    A.extend([GALOIS_ELEMENT_128(0, mode="gcm")] * (max_len - len(A)))
    B.extend([GALOIS_ELEMENT_128(0, mode="gcm")] * (max_len - len(B)))

    # * Element-wise addition
    S = [a + b for a, b in zip(A, B)]

    # Convert result back to bytes and then to base64 strings
    S_bytes = [_.to_bytes("big") for _ in S]
    S_b64 = [bytes_to_base64(coeff) for coeff in S_bytes]

    return S_b64
