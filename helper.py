import base64


def set_bit(self: int, bit_index: int) -> int:
    self |= 1 << bit_index
    return self


def mask_bytes(bytestr: str, mask: str) -> str:
    for i in range(len(bytestr)):
        bytestr[i] &= mask[i]
    return bytestr


def bytes_to_base64(bytestr: str) -> str:
    return base64.b64encode(bytestr).decode()


def base64_to_bytes(b64str: str) -> str:
    return base64.b64decode(b64str)
