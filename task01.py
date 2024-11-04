from classes import SEA128, GALOIS_FIELD_128
from helper import (
    block2poly_gcm,
    block2poly_xex,
    poly2block_gcm,
    poly2block_xex,
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
        case "gcm":
            return poly2block_gcm(args["coefficients"])
        case _:
            raise ValueError("Invalid semantic")
    pass


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
        case "gcm":
            try:
                return block2poly_gcm(base64_to_bytes(args["block"]))
            except ValueError as e:
                raise ValueError(f"Error in block2poly: {e}")
        case _:
            raise ValueError("Invalid semantic")
    pass


def gfmul(args: dict) -> bytes:
    """
    Multiply two numbers in GF(2^128)

    args: dictionary containing the semantic, a and b

    returns: bytes of the product
    """
    coefficients = [128, 7, 2, 1, 0]
    a = base64_to_bytes(args["a"])
    b = base64_to_bytes(args["b"])
    a_int = int.from_bytes(a, "little")
    b_int = int.from_bytes(b, "little")
    match args["semantic"]:
        case "xex":
            gf = GALOIS_FIELD_128(min_poly_coefficients=coefficients, mode="xex")
            product = gf.multiply(a=a_int, b=b_int)
        case "gcm":
            gf = GALOIS_FIELD_128(min_poly_coefficients=coefficients, mode="gcm")
            product = gf.multiply(a=a_int, b=b_int)
        case _:
            raise ValueError("Invalid semantic")
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

    # Process each 16-byte block
    for block_index in range(0, len(input), 16):
        input_block = input[block_index : block_index + 16]

        # Handle incomplete blocks (padding if necessary)
        if len(input_block) < 16:
            input_block += b"\x00" * (16 - len(input_block))  # Pad with zeros

        # XOR input block with tweaked_key2
        input_block = bytes(input_block[i] ^ tweaked_key2[i] for i in range(16))

        # Encrypt or decrypt based on mode
        match mode:
            case "encrypt":
                out_block = sea.encrypt(input_block)
            case "decrypt":
                out_block = sea.decrypt(input_block)
            case _:
                raise ValueError("Invalid mode")

        # XOR output block with tweaked_key2 again
        out_block = bytes(out_block[i] ^ tweaked_key2[i] for i in range(16))
        out_blocks.append(out_block)

        if block_index + 16 < len(input):
            # Multiply tweaked_key2 by ALPHA in GF(2^128)
            gf = GALOIS_FIELD_128(min_poly_coefficients=[128, 7, 2, 1, 0], mode="xex")
            tweaked_key2_int = int.from_bytes(tweaked_key2, "little")
            ALPHA_int = int.from_bytes(ALPHA, "little")

            tweaked_key2_int = gf.multiply(a=tweaked_key2_int, b=ALPHA_int)
            tweaked_key2 = tweaked_key2_int.to_bytes(16, "little")  # Convert back to bytes

    return b"".join(out_blocks)
