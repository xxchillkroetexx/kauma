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

    polys: list[GALOIS_POLY_128] = mergesort(polys)

    return_list = list()
    for poly in polys:
        poly: GALOIS_POLY_128
        poly = poly.get_coefficients()
        poly = [reverse_bits_in_bytes(term).to_bytes(16, "little") for term in poly]
        return_list.append([bytes_to_base64(coeff) for coeff in poly])

    return return_list


def mergesort(list: list) -> list:
    length = len(list)
    if length <= 1:
        return list
    mid = length // 2
    left = list[:mid]
    right = list[mid:]
    left = mergesort(left)
    right = mergesort(right)
    return merge(left, right)


def merge(left: list[GALOIS_POLY_128], right: list[GALOIS_POLY_128]) -> list[GALOIS_POLY_128]:
    if left == []:
        return right
    if right == []:
        return left
    x1, *R1 = left
    x2, *R2 = right
    if compare(x1, x2):
        return [x1] + merge(R1, right)
    else:
        return [x2] + merge(left, R2)


def compare(poly1: GALOIS_POLY_128, poly2: GALOIS_POLY_128) -> bool:
    poly1_deg = poly1.get_degree()
    poly2_deg = poly2.get_degree()
    if poly1_deg < poly2_deg:
        return True
    elif poly1_deg > poly2_deg:
        return False

    poly1_coeffs = poly1.get_coefficients()
    poly2_coeffs = poly2.get_coefficients()
    for i in range(1, poly1_deg + 2):
        # same degree? -> compare coefficient starting with largest power
        if poly1_coeffs[-i] > poly2_coeffs[-i]:
            return False
        if poly1_coeffs[-i] < poly2_coeffs[-i]:
            return True
    return True
