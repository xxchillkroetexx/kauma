import base64
import cryptography.hazmat.primitives.ciphers as ciphers


def set_bit(self: int, bit_index: int) -> int:
    """
    Set a bit in a byte

    self: the byte
    bit_index: the index of the bit to set

    returns: the byte with the bit set
    """
    self |= 1 << bit_index
    return self


def mask_bytes(bytestr: bytes, mask: bytes) -> bytes:
    """
    Mask a byte string

    bytestr: the byte string
    mask: the mask

    returns: the masked byte string
    """
    for i in range(len(bytestr)):
        bytestr[i] &= mask[i]
    return bytestr


def bytes_to_base64(bytestr: bytes) -> str:
    """
    Convert a byte string to a base64 encoded string

    bytestr: the byte string

    returns: the base64 encoded string
    """
    return base64.b64encode(bytestr).decode()


def base64_to_bytes(b64str: str) -> bytes:
    """
    Convert a base64 encoded string to a byte string

    b64str: the base64 encoded string

    returns: the byte string
    """
    return base64.b64decode(b64str)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings

    a: the first byte string
    b: the second byte string

    returns: the XOR of the two byte strings
    """
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ecb(input: bytes, key: bytes, mode: str) -> bytes:
    """
    Encrypt a block using AES-ECB

    input: input block
    key: key
    mode: "encrypt" or "decrypt"

    returns: the ciphertext
    """

    cipher_aes_ecb = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.ECB())

    match mode:
        case "encrypt":
            encryptor = cipher_aes_ecb.encryptor()
            return encryptor.update(input) + encryptor.finalize()
        case "decrypt":
            decryptor = cipher_aes_ecb.decryptor()
            return decryptor.update(input) + decryptor.finalize()
        case _:
            raise ValueError("Invalid mode")
    pass


def split_blocks(bytestr: bytes, block_size: int) -> list[bytes]:
    """
    Split a byte string into blocks

    bytestr: the byte string
    block_size: the size of each block

    returns: a list of blocks
    """
    return [bytestr[i : i + block_size] for i in range(0, len(bytestr), block_size)]


def block2poly_xex(block: bytes) -> list:
    """
    convert a 16 byte block to a polynom using XEX mode

    block: bytes of the block

    returns: list of coefficients
    """
    coefficients = []

    for byte_index in range(len(block)):
        for bit_index in range(8):
            if block[byte_index] & (1 << bit_index):
                coefficients.append(byte_index * 8 + bit_index)

    coefficients.sort()

    return coefficients


def block2poly_gcm(block: bytes) -> list:
    """
    convert a 16 byte block to a polynom using GCM mode

    block: bytes of the block

    returns: list of coefficients
    """
    coefficients = []

    for byte_index in range(16):
        for bit_index in range(8):
            if block[byte_index] & (1 << bit_index):
                coefficients.append(byte_index * 8 + 7 - bit_index)

    coefficients.sort()

    return coefficients


def poly2block_xex(coefficients: list) -> bytes:
    """
    convert a polynom to a 16 byte block using XEX mode

    coefficients: list of coefficients

    returns: bytes of the block
    """
    block = bytearray(16)

    for coeff in coefficients:
        byte_index = coeff // 8
        bit_index = coeff % 8
        block[byte_index] = set_bit(block[byte_index], bit_index)

    return bytes(mask_bytes(block, b"\xff" * 16))


def poly2block_gcm(coefficients: list) -> bytes:
    """
    convert a polynom to a 16 byte block using GCM mode

    coefficients: list of coefficients

    returns: bytes of the block
    """
    block = bytearray(16)

    for coeff in coefficients:
        byte_index = coeff // 8
        bit_index = 7 - (coeff % 8)
        block[byte_index] = set_bit(block[byte_index], bit_index)

    return bytes(block)


def coefficients_to_min_polynom(coefficients: list) -> int:
    """
    Convert a list of coefficients to a minimal polynomial

    coefficients: list of coefficients

    returns: the minimal polynomial
    """
    minimal_polynomial = 0

    for coeff in coefficients:
        minimal_polynomial |= 1 << coeff

    return minimal_polynomial


def reverse_bits_in_bytes(n):
    """
    Reverse the bits in a 16 byte integer

    n: the integer
    byte_size: the size of the integer in bytes

    returns: the integer with the bits reversed
    """
    result = 0
    shift = 0

    while n > 0:
        # Get the lowest 8 bits of n
        byte = n & 0xFF

        # Swap the 4-bit groups of the byte -> Example: 10100111
        rotated_byte = ((byte & 0b11110000) >> 4) | ((byte & 0b00001111) << 4)  # -> 01111010
        # Swap the 2-bit groups of the byte in their respective 4-bit groups
        rotated_byte = ((rotated_byte & 0b11001100) >> 2) | ((rotated_byte & 0b00110011) << 2)  # -> 11011010
        # Swap the 1-bit groups of the byte in their respective 4-bit groups
        rotated_byte = ((rotated_byte & 0b10101010) >> 1) | ((rotated_byte & 0b01010101) << 1)  # -> 11100101

        # Add the rotated byte to the result
        result |= rotated_byte << shift
        shift += 8

        # Shift n to the right by 8 bits
        n >>= 8
    return result


def mergesort(polys: list) -> list:
    """
    Sort the polynomials using mergesort
    """
    if len(polys) <= 1:
        return polys
    if len(polys) == 2:
        if polys[0] > polys[1]:
            return [polys[1], polys[0]]
        return polys

    mid = len(polys) // 2
    left = polys[:mid]
    right = polys[mid:]

    left = mergesort(left)
    right = mergesort(right)

    return merge(left, right)


def merge(left, right):
    """
    Merge the two sorted lists
    """
    result = []
    i = j = 0

    while i < len(left) and j < len(right):
        if left[i] < right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1

    result += left[i:]
    result += right[j:]

    return result


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


def merge(left: list, right: list) -> list:
    """
    Merge two sorted lists
    """
    if left == []:
        return right
    if right == []:
        return left
    x1, *R1 = left
    x2, *R2 = right
    try:
        if compare(x1[0], x2[0]):
            return [x1] + merge(R1, right)
        else:
            return [x2] + merge(left, R2)
    except:
        if compare(x1, x2):
            return [x1] + merge(R1, right)
        else:
            return [x2] + merge(left, R2)


def compare(poly1, poly2) -> bool:
    """
    Compare two polynomials
    """
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
