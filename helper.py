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


def gf_mult_polynomial(a: int, b: int, minimal_polynomial: int) -> int:
    """
    Multiply two numbers in GF(2^128) using XEX mode

    a: the first polynomial
    b: the second polynomial
    minimal_polynomial: the non-reducable polynomial

    returns: the product
    """
    result = a * b

    while result.bit_length() >= minimal_polynomial.bit_length():
        shift = result.bit_length() - minimal_polynomial.bit_length()
        result ^= minimal_polynomial << shift

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
