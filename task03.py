from classes import GALOIS_ELEMENT_128, GALOIS_POLY_128
from helper import *


def gfpoly_add(args: dict) -> list[str]:
    """
    Add two polinomials in a Galois Field

    args: dictionary containing the polynomials A and B

    returns: sum of the two
    """
    A_b64 = args["A"]
    B_b64 = args["B"]

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(coeff) for coeff in A_b64]
    B_bytes = [base64_to_bytes(coeff) for coeff in B_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff))) for coeff in A_bytes]
    B = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff))) for coeff in B_bytes]
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    B = GALOIS_POLY_128(B)

    # * Element-wise addition
    S = A + B

    # Convert result back to bytes and then to base64 strings
    S_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "big") for term in S.get_coefficients()]
    S_b64 = [bytes_to_base64(coeff) for coeff in S_bytes]

    return S_b64


def gfpoly_mul(args: dict) -> list[str]:
    """
    Multiply two polinomials in a Galois Field

    args: dictionary containing the polynomials A and B

    returns: polynomial P
    """
    A_b64 = args["A"]
    B_b64 = args["B"]

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(coeff) for coeff in A_b64]
    B_bytes = [base64_to_bytes(coeff) for coeff in B_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in A_bytes]
    B = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in B_bytes]
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    B = GALOIS_POLY_128(B)

    # # * Polynomial multiplication
    P = A * B

    # Convert result back to bytes and then to base64 strings
    P_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in P.get_coefficients()]
    P_b64 = [bytes_to_base64(coeff) for coeff in P_bytes]

    return P_b64


def gfpoly_pow(args: dict) -> list[str]:
    """
    Exponentiate a polynomial in a Galois Field by an exponent

    args: dictionary containing the polynomial A and the exponent k

    returns: polynomial Z
    """
    A_b64 = args["A"]
    k = int(args["k"])

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(term) for term in A_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(term, "little"))) for term in A_bytes]
    A = GALOIS_POLY_128(A)

    # * Polynomial exponentiation
    Z = A**k

    # Convert result back to bytes and then to base64 strings
    Z_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in Z.get_coefficients()]
    Z_b64 = [bytes_to_base64(term) for term in Z_bytes]

    return Z_b64


def gfdiv(args: dict) -> bytes:
    """
    Divide two elements in a Galois Field

    args: dictionary containing the elements a and b

    returns: quotient
    """
    a = base64_to_bytes(args["a"])
    b = base64_to_bytes(args["b"])
    a = GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(a, "little")))
    b = GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(b, "little")))

    q = a // b

    q = GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(q.get_block()))
    q_bytes = q.to_bytes()
    return q_bytes


def gfpoly_divmod(args: dict) -> dict:
    """
    Divide two polynomials in a Galois Field with remainder

    args: dictionary containing the polynomials A and B

    returns: dictionary containing the quotient and remainder
    """
    A_b64 = args["A"]
    B_b64 = args["B"]

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(coeff) for coeff in A_b64]
    B_bytes = [base64_to_bytes(coeff) for coeff in B_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in A_bytes]
    B = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in B_bytes]
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    B = GALOIS_POLY_128(B)

    # * Polynomial division
    Q, R = A // B

    # Convert result back to bytes and then to base64 strings
    Q_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in Q.get_coefficients()]
    R_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in R.get_coefficients()]
    Q_b64 = [bytes_to_base64(coeff) for coeff in Q_bytes]
    R_b64 = [bytes_to_base64(coeff) for coeff in R_bytes]

    return {"Q": Q_b64, "R": R_b64}


def gfpoly_powmod(args: dict) -> dict:
    """
    Exponentiate a polynomial in a Galois Field by an exponent modulo another polynomial

    args: dictionary containing the polynomial A, the exponent k and the modulo polynomial M

    returns: polynomial Z
    """
    A_b64 = args["A"]
    M_b64 = args["M"]
    k = int(args["k"])

    # Convert base64 strings to byte arrays
    A_bytes = [base64_to_bytes(term) for term in A_b64]
    M_bytes = [base64_to_bytes(term) for term in M_b64]
    # Convert byte arrays to GALOIS_ELEMENT_128 objects
    A = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(term, "little"))) for term in A_bytes]
    M = [GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(term, "little"))) for term in M_bytes]
    # Convert list of GALOIS_ELEMENT_128 objects to GALOIS_POLY_128 objects
    A = GALOIS_POLY_128(A)
    M = GALOIS_POLY_128(M)

    # * Polynomial exponentiation
    Z: GALOIS_POLY_128 = A.powmod(exponent=k, modulo=M)

    # Convert result back to bytes and then to base64 strings
    Z_bytes = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in Z.get_coefficients()]
    Z_b64 = [bytes_to_base64(term) for term in Z_bytes]

    return Z_b64
