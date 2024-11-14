from classes import GALOIS_ELEMENT_128, GALOIS_POLY_128
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
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    B = GALOIS_POLY_128(B)

    # * Element-wise addition
    S = A + B

    # Convert result back to bytes and then to base64 strings
    S_bytes = S.to_bytes("big")
    S_b64 = [bytes_to_base64(coeff) for coeff in S_bytes]

    return S_b64


def gfpoly_mul(args: dict) -> list[str]:
    A_b64 = args["A"]
    B_b64 = args["B"]

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(coeff) for coeff in A_b64]
    B_bytes = [base64_to_bytes(coeff) for coeff in B_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=int.from_bytes(coeff, "little"), mode="gcm") for coeff in A_bytes]
    B = [GALOIS_ELEMENT_128(value=int.from_bytes(coeff, "little"), mode="gcm") for coeff in B_bytes]
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    B = GALOIS_POLY_128(B)

    # # * Polynomial multiplication
    P = A * B

    # Convert result back to bytes and then to base64 strings
    P_bytes = P.to_bytes()
    P_b64 = [bytes_to_base64(coeff) for coeff in P_bytes]

    return P_b64
