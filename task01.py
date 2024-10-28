from helper import (
    SEA128,
    gf_mult_polynomial,
    set_bit,
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

    return bytes(mask_bytes(block, b"\xff" * 16))


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

    coefficients.sort()

    return coefficients


def gfmul(args: dict) -> bytes:
    """
    Multiply two numbers in GF(2^128)

    args: dictionary containing the semantic, a and b

    returns: bytes of the product
    """

    match args["semantic"]:
        case "xex":
            return gfmul_xex(a=base64_to_bytes(args["a"]), b=base64_to_bytes(args["b"]))
        case _:
            raise ValueError("Invalid semantic")
    pass


def gfmul_xex(a: bytes, b: bytes) -> bytes:
    """
    Multiply two numbers in GF(2^128) using XEX mode

    args: dictionary containing a and b

    returns: bytes of the product
    """
    minimal_polynomial = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

    a = int.from_bytes(a, "little")
    b = int.from_bytes(b, "little")

    product = gf_mult_polynomial(a, b, minimal_polynomial)

    return product.to_bytes(16, "little")


def sea128(args: dict) -> bytes:
    """
    Encrypt or decrypt a block using SEA128.

    args: dictionary containing the mode, key and input

    returns: bytes of the output
    """
    mode = args["mode"]
    sea128 = SEA128(key=base64_to_bytes(args["key"]))
    match mode:
        case "encrypt":
            return sea128.encrypt(input=base64_to_bytes(args["input"]))
        case "decrypt":
            return sea128.decrypt(input=base64_to_bytes(args["input"]))
        case _:
            raise ValueError("Invalid mode")
    pass


def full_disc_encryption(args: dict) -> bytes:
    """
    Full disk encryption with XEX using SEA128

    args: dictionary containing the mode, tweak, key and input

    returns: bytes of the output
    """
    mode = args["mode"]
    match mode:
        case "encrypt":
            return xex(
                tweak=base64_to_bytes(args["tweak"]),
                key=base64_to_bytes(args["key"]),
                input=base64_to_bytes(args["input"]),
                mode="encrypt",
            )
        case "decrypt":
            return xex(
                tweak=base64_to_bytes(args["tweak"]),
                key=base64_to_bytes(args["key"]),
                input=base64_to_bytes(args["input"]),
                mode="decrypt",
            )
        case _:
            raise ValueError("Invalid mode")
    pass


def xex(tweak: bytes, key: bytes, input: bytes, mode: str) -> bytes:
    """
    Encrypt/Decrypt a block using XEX mode

    tweak: tweak in bytes
    key: key in bytes
    input: input block in bytes
    mode: "encrypt" or "decrypt"

    returns: bytes of the output
    """
    key1 = key[:16]
    key2 = key[16:]

    ALPHA = poly2block_xex([1])
    tweaked_key2 = SEA128(key=key2).encrypt(input=tweak)
    out_blocks = []

    sea = SEA128(key=key1)
    for block_index in range(0, len(input), 16):
        input_block = input[block_index : block_index + 16]

        input_block = bytes(input_block[i] ^ tweaked_key2[i] for i in range(16))

        match mode:
            case "encrypt":
                out_block = sea.encrypt(input_block)
            case "decrypt":
                out_block = sea.decrypt(input_block)
            case _:
                raise ValueError("Invalid mode")

        # xor tweaked_key2
        out_block = bytes(out_block[i] ^ tweaked_key2[i] for i in range(16))
        out_blocks.append(out_block)

        if block_index + 16 < len(input):
            # tweaked_key2 gf_mul block_index
            tweaked_key2 = gfmul_xex(a=tweaked_key2, b=ALPHA)
        pass

    out_blocks = b"".join(out_blocks)
    return out_blocks
