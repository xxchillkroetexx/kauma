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


def reduce_polynomial(polynomial: int, minimal_polynomial: int) -> int:
    """
    Reduce a polynomial using the minimal polynomial

    a: the polynomial
    minimal_polynomial: the non-reducable polynomial

    returns: the reduced polynomial
    """
    while polynomial.bit_length() >= minimal_polynomial.bit_length():
        shift = polynomial.bit_length() - minimal_polynomial.bit_length()
        polynomial ^= minimal_polynomial << shift
        # a ^= minimal_polynomial << shift

    return polynomial


def gf_mult_polynomial(a: int, b: int, minimal_polynomial: int) -> int:
    """
    Multiply two numbers in GF(2^128) using multiply and reduce method

    a: the first polynomial
    b: the second polynomial
    minimal_polynomial: the non-reducable polynomial

    returns: the product
    """

    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
        a = reduce_polynomial(polynomial=a, minimal_polynomial=minimal_polynomial)

    # reduce the result one last time
    result = reduce_polynomial(polynomial=result, minimal_polynomial=minimal_polynomial)

    return result


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


def xex_to_gcm(block: bytes) -> bytes:
    """
    Convert a block from XEX mode to GCM mode

    block: the block in XEX mode

    returns: the block in GCM mode
    """
    reversed_block = bytearray(b"\x00" * 16)

    for byte in block:
        # reverse the bits in each byte
        reversed_byte = 0
        for i in range(8):
            reversed_byte |= ((byte >> i) & 1) << (7 - i)
        reversed_block.append(reversed_byte)

    return bytes(reversed_block)
