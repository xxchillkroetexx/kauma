from classes import GALOIS_ELEMENT_128, GALOIS_POLY_128
from helper import base64_to_bytes, mergesort, reverse_bits_in_bytes, bytes_to_base64, split_blocks, xor_bytes


def gfpoly_sort(polys: dict[list[list]]) -> list[list[str]]:
    """
    Sort the polynomials in ascending order

    polys: dictionary containing the polynomials

    returns: sorted polynomials
    """
    polys = polys["polys"]
    for i in range(len(polys)):
        for j in range(len(polys[i])):
            polys[i][j] = base64_to_bytes(polys[i][j])

    for i in range(len(polys)):

        if len(polys[i]) == 0:
            polys[i] = GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0)])
            continue

        for j in range(len(polys[i])):
            polys[i][j] = GALOIS_ELEMENT_128(value=reverse_bits_in_bytes(int.from_bytes(polys[i][j], "little")))
        polys[i] = GALOIS_POLY_128(polys[i])

    # sort the polynomials by their degree
    # if they have the same degree, by the coefficients starting from the highest degree

    polys: list[GALOIS_POLY_128] = mergesort(polys)

    return_list = list()
    for poly in polys:
        poly: GALOIS_POLY_128
        poly = poly.get_coefficients()
        poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in poly]
        return_list.append([bytes_to_base64(coeff) for coeff in poly])

    return return_list


def gfpoly_make_monic(poly: dict[list[str]]) -> list[str]:
    """
    Make the polynomial monic

    poly: dictionary containing the polynomial

    returns: monic polynomial
    """
    poly = poly["A"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients)

    poly.make_monic()
    poly = poly.get_coefficients()
    poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in poly]
    return [bytes_to_base64(coeff) for coeff in poly]


def gfpoly_sqrt(poly: dict[list[str]]) -> list[str]:
    """
    Calculate the square root of the polynomial

    poly: dictionary containing the polynomial

    returns: square root of the polynomial
    """
    poly = poly["Q"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients)

    sqrt_poly = poly.sqrt()
    sqrt_poly = sqrt_poly.get_coefficients()
    sqrt_poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in sqrt_poly]
    return [bytes_to_base64(coeff) for coeff in sqrt_poly]


def gfpoly_diff(poly: dict[list[str]]) -> list[str]:
    """
    differentiate the polynomial

    poly: dictionary containing the polynomial

    returns: differentiated polynomial
    """
    poly = poly["F"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients)

    diff_poly = poly.diff()
    diff_poly = diff_poly.get_coefficients()
    diff_poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in diff_poly]
    return [bytes_to_base64(coeff) for coeff in diff_poly]


def gfpoly_gcd(dict: dict) -> list:
    """
    Calculate the greatest common divisor of the two polynomials

    dict: dictionary containing the polynomials A and B

    returns: greatest common divisor of the two polynomials
    """
    poly1 = dict["A"]
    poly2 = dict["B"]
    poly1 = [base64_to_bytes(coeff) for coeff in poly1]
    poly2 = [base64_to_bytes(coeff) for coeff in poly2]
    coefficients1 = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly1]
    coefficients2 = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly2]
    poly1: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients1)
    poly2: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients2)

    gcd_poly = poly1.gcd(poly2)
    gcd_poly = gcd_poly.get_coefficients()
    gcd_poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in gcd_poly]
    return [bytes_to_base64(coeff) for coeff in gcd_poly]


def gfpoly_factor_sff(input_dict: dict) -> list[dict]:
    """
    Factor the polynomial into square-free factors

    input_dict: dictionary containing the polynomial

    returns: square-free factors of the polynomial
    """
    poly = input_dict["F"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients)

    factors = poly.sff()

    return_list = list()
    for factor, exponent in factors:
        tmp_dict = dict()
        factor = factor.get_coefficients()
        factor = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in factor]
        tmp_dict["factor"] = [bytes_to_base64(coeff) for coeff in factor]
        tmp_dict["exponent"] = exponent

        return_list.append(tmp_dict)
    return return_list


def gfpoly_factor_ddf(input_dict: dict) -> list[dict]:
    """
    Factor the polynomial into distinct-degree factors

    input_dict: dictionary containing the polynomial

    returns: distinct-degree factors of the polynomial
    """
    poly = input_dict["F"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly: GALOIS_POLY_128 = GALOIS_POLY_128(coefficients=coefficients)

    factors = poly.ddf()

    return_list = list()
    for factor, degree in factors:
        tmp_dict = dict()
        factor = factor.get_coefficients()
        factor = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in factor]
        tmp_dict["factor"] = [bytes_to_base64(coeff) for coeff in factor]
        tmp_dict["degree"] = degree

        return_list.append(tmp_dict)
    return return_list


def gfpoly_factor_edf(input_dict: dict) -> list[dict]:
    """
    Factor the polynomial into equal-degree factors

    input_dict: dictionary containing the polynomial

    returns: equal-degree factors of the polynomial
    """
    poly = input_dict["F"]
    d = input_dict["d"]
    poly = [base64_to_bytes(coeff) for coeff in poly]
    coefficients = [GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(coeff, "little"))) for coeff in poly]
    poly = GALOIS_POLY_128(coefficients=coefficients)

    edf = poly.edf(d)
    factors = list()
    for factor in edf:
        factors.append(factor)

    return_list = list()
    for factor in factors:
        factor = factor.get_coefficients()
        factor = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in factor]
        return_list.append([bytes_to_base64(coeff) for coeff in factor])
    return return_list


def gcm_crack(args: dict) -> dict:
    """
    Crack GCM authentication tag

    args: dictionary containing the nonce, m1, m2, m3 and forgery

    returns: tag, H and mask
    """
    nonce = args["nonce"]
    nonce = reverse_bits_in_bytes(int.from_bytes(base64_to_bytes(nonce), byteorder="little"))
    # extract all the message data from the input
    m1 = args["m1"]
    m1_ciphertext = base64_to_bytes(m1["ciphertext"])
    m1_ass_data = base64_to_bytes(m1["associated_data"])
    m1_tag = base64_to_bytes(m1["tag"])

    m2 = args["m2"]
    m2_ciphertext = base64_to_bytes(m2["ciphertext"])
    m2_ass_data = base64_to_bytes(m2["associated_data"])
    m2_tag = base64_to_bytes(m2["tag"])

    m3 = args["m3"]
    m3_ciphertext = base64_to_bytes(m3["ciphertext"])
    m3_ass_data = base64_to_bytes(m3["associated_data"])
    m3_tag = base64_to_bytes(m3["tag"])

    forgery = args["forgery"]
    forgery_ciphertext = base64_to_bytes(forgery["ciphertext"])
    forgery_ass_data = base64_to_bytes(forgery["associated_data"])

    # Calculate polynomial for m1, starting with the associated data padded to 16 bytes
    (
        m1_scalar,
        m1_scalar_reversed,
        m1_ciphertext_len,
        m1_ass_data_len,
        m1_ass_data_padded,
        m1_ciphertext_padded,
    ) = prepare(ciphertext=m1_ciphertext, ass_data=m1_ass_data, tag=m1_tag)

    # Calculate polynomial for m2, starting with the associated data padded to 16 bytes
    (
        m2_scalar,
        m2_scalar_reversed,
        m2_ciphertext_len,
        m2_ass_data_len,
        m2_ass_data_padded,
        m2_ciphertext_padded,
    ) = prepare(ciphertext=m2_ciphertext, ass_data=m2_ass_data, tag=m2_tag)

    # Calculate polynomial for m3, starting with the associated data padded to 16 bytes
    (
        m3_scalar,
        m3_scalar_reversed,
        m3_ciphertext_len,
        m3_ass_data_len,
        m3_ass_data_padded,
        m3_ciphertext_padded,
    ) = prepare(ciphertext=m3_ciphertext, ass_data=m3_ass_data, tag=m3_tag)

    # Calculate polynomial for forgery, starting with the associated data padded to 16 bytes
    forgery_scalar = []
    forgery_coeff_bytes = []
    forgery_ass_data_padded = []
    forgery_ass_data_padded = forgery_ass_data + b"\x00" * ((16 - len(forgery_ass_data)) % 16)
    for block in split_blocks(forgery_ass_data_padded, 16):
        forgery_coeff_bytes.append(block)
        forgery_scalar.append(GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))

    forgery_ciphertext_padded = forgery_ciphertext + b"\x00" * ((16 - len(forgery_ciphertext)) % 16)
    for block in split_blocks(forgery_ciphertext_padded, 16):
        forgery_coeff_bytes.append(block)
        forgery_scalar.append(GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
    forgery_ciphertext_len = len(forgery_ciphertext_padded) // 16
    forgery_ass_data_len = len(forgery_ass_data_padded) // 16

    # padd smaller polynomial to the size of the larger polynomial
    m1_poly = GALOIS_POLY_128(m1_scalar_reversed)
    m2_poly = GALOIS_POLY_128(m2_scalar_reversed)
    poly_sub = m1_poly - m2_poly
    poly_sub.make_monic()
    result = []
    block = bytearray(16)

    # Calculate factors of poly_sub
    # First step is to calculate the SFF of poly_sub
    sff_factors = poly_sub.sff()
    # sff output is a tuple of polynomials and integers(factors)

    for poly, degree in sff_factors:
        # Second step is to calculate the DDF of the polynomial
        ddf_factors = poly.ddf()
        # ddf output is a tuple of polynomials and integers(degree)
        for ddf_poly, ddf_degree in ddf_factors:
            irreducible_factors = ddf_poly.edf(ddf_degree)
            # Add factors with their multiplicity
            for factor in irreducible_factors:
                result.append((factor, degree))

    result: list[tuple[GALOIS_POLY_128, int]]  # type hinting
    for candidate_factor, candidate_degree in result:
        block = bytearray(16)
        auth_key_h = candidate_factor._coefficients[0]
        if candidate_degree == 1:
            for i in range(m1_ass_data_len):
                block = xor_bytes(block, m1_ass_data_padded[i * 16 : (i + 1) * 16])
                block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
                block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

            for i in range(m1_ciphertext_len):
                block = xor_bytes(block, m1_ciphertext_padded[i * 16 : (i + 1) * 16])
                block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
                block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

            block = bytearray(xor_bytes(block, calc_L(input_data=m1_ciphertext, ass_data=m1_ass_data)))

            block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
            block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")
            auth_tag_candidate = bytearray(xor_bytes(block, m1_tag))
            block = bytearray(16)

            for i in range(m3_ass_data_len):
                block = xor_bytes(block, m3_ass_data_padded[i * 16 : (i + 1) * 16])

                block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
                block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

            for i in range(m3_ciphertext_len):
                block = xor_bytes(block, m3_ciphertext_padded[i * 16 : (i + 1) * 16])
                block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
                block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

            block = bytearray(xor_bytes(block, calc_L(input_data=m3_ciphertext, ass_data=m3_ass_data)))
            block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
            block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")
            auth_tag = bytearray(xor_bytes(block, auth_tag_candidate))
            if auth_tag == m3_tag:
                break
        block = bytearray(16)
    block = bytearray(16)
    for i in range(forgery_ass_data_len):
        block = xor_bytes(block, forgery_ass_data_padded[i * 16 : (i + 1) * 16])

        block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
        block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

    for i in range(forgery_ciphertext_len):
        block = xor_bytes(block, forgery_ciphertext_padded[i * 16 : (i + 1) * 16])
        block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
        block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")

    block = bytearray(xor_bytes(block, calc_L(input_data=forgery_ciphertext, ass_data=forgery_ass_data)))
    block = GALOIS_ELEMENT_128((reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
    block = (reverse_bits_in_bytes((block * auth_key_h)._value)).to_bytes(16, byteorder="little")
    auth_tag = bytearray(xor_bytes(block, auth_tag_candidate))

    return {
        "tag": bytes_to_base64(auth_tag),
        "H": bytes_to_base64(reverse_bits_in_bytes(auth_key_h._value).to_bytes(16, byteorder="little")),
        "mask": bytes_to_base64(auth_tag_candidate),
    }


def calc_L(input_data: bytes, ass_data: bytes) -> bytes:
    L = (len(ass_data) * 8).to_bytes(8, "big") + (len(input_data) * 8).to_bytes(8, "big")
    return L


def prepare(ciphertext, ass_data, tag):
    coefficient = []
    coeff_bytes = []
    ass_data_padded = []

    ass_data_padded = ass_data + b"\x00" * ((16 - len(ass_data)) % 16)
    for block in split_blocks(ass_data_padded, 16):
        coeff_bytes.append(block)
        coefficient.append(GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))
    ciphertext_padded = ciphertext + b"\x00" * ((16 - len(ciphertext)) % 16)

    for block in split_blocks(ciphertext_padded, 16):
        coeff_bytes.append(block)
        coefficient.append(GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(block, byteorder="little"))))

    coefficient.append(
        GALOIS_ELEMENT_128(
            reverse_bits_in_bytes(int.from_bytes(calc_L(input_data=ciphertext, ass_data=ass_data), byteorder="little"))
        )
    )
    coeff_bytes.append(calc_L(input_data=ciphertext, ass_data=ass_data))
    coefficient.append(GALOIS_ELEMENT_128(reverse_bits_in_bytes(int.from_bytes(tag, byteorder="little"))))
    coeff_bytes.append(tag)
    scalar_reversed = coefficient[::-1]
    ciphertext_len = len(ciphertext_padded) // 16
    ass_data_len = len(ass_data_padded) // 16

    return coefficient, scalar_reversed, ciphertext_len, ass_data_len, ass_data_padded, ciphertext_padded
