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


def convert_to_general_poly(polynom: int, mode: str) -> int:
    """
    Convert a polynomial to a general polynomial

    polynom: the polynomial
    mode: "xex" or "gcm"

    returns: the general polynomial
    """
    match mode:
        case "xex":
            # reorder the bytes of the polynomial so that the most left byte is now the most right byte
            polynom = reverse_byte_order(polynom)
            return polynom
        case "gcm":
            # reverse the bits of the polynomial
            polynom = int(bin(polynom)[2:].zfill(128)[::-1], 2)
            return polynom
        case _:
            raise ValueError("Invalid mode")


def reverse_byte_order(data: int) -> int:
    """
    Convert the number to bytes (big-endian), reverse them, and convert back to an integer

    data: the number to reverse

    returns: the reversed number
    """
    # Calculate how many bytes are needed
    byte_length = (data.bit_length() + 7) // 8
    # Convert to bytes (big-endian)
    data_bytes = data.to_bytes(byte_length, byteorder="big")
    # Reverse the byte order
    reversed_bytes = data_bytes[::-1]
    # Convert back to integer
    reversed_data = int.from_bytes(reversed_bytes, byteorder="big")

    return reversed_data


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
