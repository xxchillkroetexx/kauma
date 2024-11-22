from classes import GALOIS_ELEMENT_128, GALOIS_POLY_128
from helper import base64_to_bytes, reverse_bits_in_bytes, bytes_to_base64


def gfpoly_sort(polys: dict[list[list]]) -> list[list[str]]:
    """
    Sort the polynomials in ascending order
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

    polys: list[GALOIS_POLY_128] = sorted(
        polys, key=lambda poly: (poly.get_degree(), poly.get_coefficients()), reverse=False
    )

    return_list = list()
    for poly in polys:
        poly: GALOIS_POLY_128
        poly = poly.get_coefficients()
        poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in poly]
        return_list.append([bytes_to_base64(coeff) for coeff in poly])

    return return_list
