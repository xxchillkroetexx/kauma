from helper import (
    gf_mult_polynomial,
    set_bit,
    bytes_to_base64,
    mask_bytes,
    base64_to_bytes,
)


def add_numbers(args: dict) -> dict:
    """
    Add two numbers
    """

    return {"sum": args["number1"] + args["number2"]}


def subtract_numbers(args: dict) -> dict:
    """
    Subtract two numbers
    """

    return {"difference": args["number1"] - args["number2"]}


def poly2block(args: dict) -> dict:
    """
    Convert a polynom to a block
    """
    mode = args["semantic"]
    match mode:
        case "xex":
            return xex_polynom(args["coefficients"])
        case _:
            raise ValueError("Invalid semantic")
    pass

    return {"block": args["polygon"]}


def xex_polynom(coefficients: list) -> dict:
    """
    convert a polynom to a 16 byte block using XEX mode
    """
    block = bytearray(16)

    for coeff in coefficients:
        byte_index = coeff // 8
        bit_index = coeff % 8
        block[byte_index] = set_bit(block[byte_index], bit_index)

    block = mask_bytes(block, b"\xff" * 16)

    return {"block": bytes_to_base64(block)}


def block2poly(args: dict) -> dict:
    """
    Convert a 16 byte block to a polynom
    """
    mode = args["semantic"]
    match mode:
        case "xex":
            return xex_block(args["block"])
        case _:
            raise ValueError("Invalid semantic")
    pass


def xex_block(block: str) -> dict:
    """
    convert a 16 byte block to a polynom using XEX mode
    """
    coefficients = []
    try:
        block = base64_to_bytes(block)
    except Exception as e:
        raise ValueError(f"Invalid block: {e}")

    for byte_index in range(16):
        for bit_index in range(8):
            if block[byte_index] & (1 << bit_index):
                coefficients.append(byte_index * 8 + bit_index)

    return {"coefficients": coefficients}


def gfmul(args: dict) -> dict:
    """
    Multiply two numbers in GF(2^128)
    """

    match args["semantic"]:
        case "xex":
            return gfmul_xex(args)
        case _:
            raise ValueError("Invalid semantic")
    pass


def gfmul_xex(args: dict) -> dict:
    """
    Multiply two numbers in GF(2^128) using XEX mode
    """
    minimal_polynomial = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

    a_bytes = base64_to_bytes(args["a"])
    b_bytes = base64_to_bytes(args["b"])

    a = int.from_bytes(a_bytes, "little")
    b = int.from_bytes(b_bytes, "little")

    product = gf_mult_polynomial(a, b, minimal_polynomial)

    return {"product": bytes_to_base64(product.to_bytes(16, "little"))}
