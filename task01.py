from helper import (
    aes_ecb,
    gf_mult_polynomial,
    set_bit,
    bytes_to_base64,
    mask_bytes,
    base64_to_bytes,
)


def add_numbers(args: dict) -> int:
    """
    Add two numbers
    """

    return args["number1"] + args["number2"]


def subtract_numbers(args: dict) -> int:
    """
    Subtract two numbers
    """

    return args["number1"] - args["number2"]


def poly2block(args: dict) -> bytes:
    """
    Convert a polynom to a block

    args: dictionary containing the semantic and the polynom coefficients

    returns: bytes of the block
    """
    mode = args["semantic"]
    match mode:
        case "xex":
            return poly2block_xex(args["coefficients"])
        case _:
            raise ValueError("Invalid semantic")
    pass


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

    return mask_bytes(block, b"\xff" * 16)


def block2poly(args: dict) -> list:
    """
    Convert a 16 byte block to a polynom

    args: dictionary containing the semantic and the block

    returns: list of coefficients
    """
    mode = args["semantic"]
    match mode:
        case "xex":
            try:
                return block2poly_xex(base64_to_bytes(args["block"]))
            except ValueError as e:
                raise ValueError(f"Error in block2poly: {e}")
        case _:
            raise ValueError("Invalid semantic")
    pass


def block2poly_xex(block: bytes) -> list:
    """
    convert a 16 byte block to a polynom using XEX mode

    block: bytes of the block

    returns: list of coefficients
    """
    coefficients = []

    for byte_index in range(16):
        for bit_index in range(8):
            if block[byte_index] & (1 << bit_index):
                coefficients.append(byte_index * 8 + bit_index)

    return coefficients


def gfmul(args: dict) -> dict:
    """
    Multiply two numbers in GF(2^128)

    args: dictionary containing the semantic, a and b

    returns: dictionary containing the product
    """

    match args["semantic"]:
        case "xex":
            return gfmul_xex(args)
        case _:
            raise ValueError("Invalid semantic")
    pass


def gfmul_xex(args: dict) -> bytes:
    """
    Multiply two numbers in GF(2^128) using XEX mode

    args: dictionary containing a and b

    returns: bytes of the product
    """
    minimal_polynomial = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

    a_bytes = base64_to_bytes(args["a"])
    b_bytes = base64_to_bytes(args["b"])

    a = int.from_bytes(a_bytes, "little")
    b = int.from_bytes(b_bytes, "little")

    product = gf_mult_polynomial(a, b, minimal_polynomial)

    return product.to_bytes(16, "little")


def sea128(args: dict) -> bytes:
    """
    Encrypt or decrypt a block using SEA128.

    args: dictionary containing the mode, key and input

    returns: bytes of the output
    """
    mode = args["mode"]
    match mode:
        case "encrypt":
            return sea128_encrypt(
                key=base64_to_bytes(args["key"]), input=base64_to_bytes(args["input"])
            )
        case "decrypt":
            return sea128_decrypt(
                key=base64_to_bytes(args["key"]), input=base64_to_bytes(args["input"])
            )
        case _:
            raise ValueError("Invalid mode")
    pass


def sea128_encrypt(input: bytes, key: bytes) -> bytes:
    """
    Encrypt a block using SEA128
    S_K(P) = E_K(P) XOR c0ffeec0ffeec0ffeec0ffeec0ffee11

    input: input block in bytes
    key: key in bytes

    returns: bytes of the ciphertext
    """
    COFFEE = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")

    ciphertext = aes_ecb(input=input, key=key, mode="encrypt")
    ciphertext = bytes(ciphertext[i] ^ COFFEE[i] for i in range(16))

    return ciphertext


def sea128_decrypt(input: bytes, key: bytes) -> bytes:
    """
    Encrypt a block using SEA128
    S_K(P) = E_K(P) XOR c0ffeec0ffeec0ffeec0ffeec0ffee11

    input: input block in bytes
    key: key in bytes

    returns: bytes of the plaintext
    """
    COFFEE = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")

    ciphertext = bytes(input[i] ^ COFFEE[i] for i in range(16))
    plaintext = aes_ecb(input=ciphertext, key=key, mode="decrypt")

    return plaintext
