from helper import set_bit, bytes_to_base64, mask_bytes


def add_numbers(args):
    """
    Add two numbers
    """

    return {"sum": args["number1"] + args["number2"]}


def subtract_numbers(args):
    """
    Subtract two numbers
    """

    return {"difference": args["number1"] - args["number2"]}


def poly2block(args):
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


def xex_polynom(coefficients):
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
