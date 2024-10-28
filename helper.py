import base64
import cryptography.hazmat.primitives.ciphers as ciphers


class SEA128:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, input: bytes) -> bytes:
        """
        Encrypt a block using SEA128
        S_K(P) = E_K(P) XOR c0ffeec0ffeec0ffeec0ffeec0ffee11

        input: input block in bytes

        returns: bytes of the ciphertext
        """
        COFFEE = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")

        ciphertext = aes_ecb(input=input, key=self.key, mode="encrypt")
        ciphertext = bytes(ciphertext[i] ^ COFFEE[i] for i in range(16))

        return ciphertext

    def decrypt(self, input: bytes) -> bytes:
        """
        Encrypt a block using SEA128
        S_K(P) = E_K(P) XOR c0ffeec0ffeec0ffeec0ffeec0ffee11

        input: input block in bytes

        returns: bytes of the plaintext
        """
        COFFEE = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")

        ciphertext = bytes(input[i] ^ COFFEE[i] for i in range(16))
        plaintext = aes_ecb(input=ciphertext, key=self.key, mode="decrypt")

        return plaintext


class GFMUL:
    """
    Class to multiply two numbers in GF(2^128)

    minimal_polynomial: the non-reducable polynomial
    """

    def __init__(
        self, minimal_polynomial: int = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
    ):
        self.minimal_polynomial = minimal_polynomial

    def xex(self, a: bytes, b: bytes) -> bytes:
        """
        Multiply two numbers in GF(2^128) using XEX mode

        a: bytes of the first number
        b: bytes of the second number

        returns: bytes of the product
        """
        a = int.from_bytes(a, "little")
        b = int.from_bytes(b, "little")

        product = gf_mult_polynomial(a, b, self.minimal_polynomial)

        return product.to_bytes(16, "little")

    def gcm(self, a: bytes, b: bytes) -> bytes:
        """
        Multiply two numbers in GF(2^128) using GCM mode

        a: bytes of the first number
        b: bytes of the second number

        returns: bytes of the product
        """
        a = int.from_bytes(a, "little")
        b = int.from_bytes(b, "little")

        product = gf_mult_polynomial(a, b, self.minimal_polynomial)

        return product.to_bytes(16, "little")


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


def carryless_xor(a: int, b: int) -> int:
    """
    Carryless XOR of two numbers

    a: the first number
    b: the second number

    returns: the carryless XOR
    """

    bin_a = bin(a)[2:]
    bin_b = bin(b)[2:]

    # find the maximum length
    max_len = max(len(bin_a), len(bin_b))

    # Pad with zeros to make same length
    bin_a = bin_a.zfill(max_len)
    bin_b = bin_b.zfill(max_len)

    # XOR the bits
    result = ""
    for bit_a, bit_b in zip(bin_a, bin_b):
        result += str(int(bit_a) ^ int(bit_b))

    # convert the result back to an integer
    return int(result, 2)


def reduce_polynomial(polynomial: int, minimal_polynomial: int) -> int:
    """
    Reduce a polynomial using the minimal polynomial

    a: the polynomial
    minimal_polynomial: the non-reducable polynomial

    returns: the reduced polynomial
    """
    while polynomial.bit_length() >= minimal_polynomial.bit_length():
        shift = polynomial.bit_length() - minimal_polynomial.bit_length()
        polynomial = carryless_xor(a=polynomial, b=minimal_polynomial << shift)
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
            result = carryless_xor(a=result, b=a)
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
