import socket
from helper import (
    aes_ecb,
    bytes_to_base64,
    coefficients_to_min_polynom,
    reverse_bits_in_bytes,
    split_blocks,
    xor_bytes,
)
from typing import Self


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


class GALOIS_ELEMENT_128:
    def __init__(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Value must be an integer", type(value), value)
        self._value = value
        self._minimal_polynomial = coefficients_to_min_polynom([128, 7, 2, 1, 0])

    def __mul__(self, other: Self) -> Self:
        """
        Multiply two elements in GF(2^128)

        other: the other element

        returns: the product
        """

        self_val_copy = self._value
        other_val_copy = other._value

        result = 0

        while other_val_copy:
            if other_val_copy & 1:
                result ^= self_val_copy
            self_val_copy <<= 1
            other_val_copy >>= 1
            # reduce the result if necessary
            if self_val_copy & (1 << 128):
                self_val_copy ^= self._minimal_polynomial

        return GALOIS_ELEMENT_128(value=result)

    def __add__(self, other: Self) -> Self:
        """
        Add two elements in GF(2^128)

        other: the other element

        returns: the sum
        """
        sum = self._value ^ other._value
        return GALOIS_ELEMENT_128(value=sum)

    def __sub__(self, other: Self) -> Self:
        """
        Subtract two elements in GF(2^128)

        other: the other element

        returns: the difference
        """
        return self + other

    def __pow__(self, exponent: int) -> Self:
        """
        Raise an element to the power of another element

        exponent: the exponent

        returns: the result
        """
        a = self
        result = GALOIS_ELEMENT_128(0x01)
        while exponent:
            if exponent & 1:
                result *= a
            a *= a
            exponent >>= 1
        return result

    def __str__(self) -> str:
        return f"{hex(self._value)}"

    def __floordiv__(self, other: Self) -> Self:
        """
        Divide two elements in GF(2^128)

        other: the other element

        returns: the qoutient
        """
        if other.get_block() == 0:
            raise ValueError("Division by zero")

        below = other.inverse()
        result = self * below
        return result

    def inverse(self) -> Self:
        """
        Calculate the multiplicative inverse of an element in GF(2^128)
        using an adapted version of the extended Euclidean algorithm

        returns: the multiplicative inverse
        """
        a = self._value
        m = self._minimal_polynomial
        u, v = 1, 0
        g, x = a, m

        while g != 1:
            j = g.bit_length() - x.bit_length()

            if j < 0:
                g, x = x, g
                u, v = v, u
                j = -j

            g ^= x << j
            u ^= v << j

        return GALOIS_ELEMENT_128(value=u)

    def __eq__(self, other: Self) -> bool:
        return self._value == other._value

    def __ne__(self, other: Self) -> bool:
        return not self == other

    def __lt__(self, other: Self) -> bool:
        return self._value < other._value

    def __le__(self, other: Self) -> bool:
        return self._value <= other._value

    def __gt__(self, other: Self) -> bool:
        return self._value > other._value

    def __ge__(self, other: Self) -> bool:
        return self._value >= other._value

    def to_bytes(self, byteorder: str = "little") -> bytes:
        return self._value.to_bytes(16, byteorder)

    def get_block(self) -> int:
        return self._value


class GALOIS_POLY_128:
    def __init__(self, coefficients: list[GALOIS_ELEMENT_128]):
        self._coefficients = coefficients
        self._minimal_polynomial = coefficients_to_min_polynom([128, 7, 2, 1, 0])

    def __mul__(self, other: Self) -> Self:
        """
        Multiply two polynomials in GF(2^128)

        other: the other polynomial

        returns: the product
        """
        product = [GALOIS_ELEMENT_128(0) for _ in range(len(self._coefficients) + len(other._coefficients) - 1)]
        for i, self_coeff in enumerate(self._coefficients):
            for j, other_coeff in enumerate(other._coefficients):
                product[i + j] = product[i + j] + self_coeff * other_coeff

        return_product = GALOIS_POLY_128(coefficients=product)

        if return_product._coefficients == [GALOIS_ELEMENT_128(0)]:
            return_product = GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0)])

        return_product._clean_zeroes()

        return return_product

    def __add__(self, other: Self) -> Self:
        """
        Add two polynomials in GF(2^128)

        other: the other polynomial

        returns: the sum
        """
        # pad the polynomials with zeros
        self_coeff = self._coefficients
        other_coeff = other._coefficients
        max_len = max(len(self._coefficients), len(other._coefficients))
        self_coeff.extend([GALOIS_ELEMENT_128(0)] * (max_len - len(self_coeff)))
        other_coeff.extend([GALOIS_ELEMENT_128(0)] * (max_len - len(other_coeff)))

        # add the coefficients
        sum = [self_coeff + other_coeff for self_coeff, other_coeff in zip(self_coeff, other_coeff)]
        return_sum = GALOIS_POLY_128(coefficients=sum)

        if len(return_sum) == 0:
            return GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0)])

        return_sum._clean_zeroes()

        return return_sum

    def __sub__(self, other: Self) -> Self:
        """
        Subtract two polynomials in GF(2^128)

        other: the other polynomial

        returns: the difference
        """
        return self + other

    def __pow__(self, exponent: int) -> Self:
        """
        Raise a polynomial to the power of another polynomial

        exponent: the exponent

        returns: the result
        """
        result = GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0x01)])

        # square and multiply
        while exponent > 0:
            if exponent % 2 == 1:
                result *= self
            self *= self
            exponent >>= 1
        return result

    def __floordiv__(self, other: Self) -> tuple[Self, Self]:
        """
        Divide with remainder (DIVMOD) in GF(2^128)

        other: the other polynomial

        returns: the quotient and the remainder
        """
        if other._coefficients == [GALOIS_ELEMENT_128(0)]:
            raise ValueError("Division by zero")

        # initialize the quotient and the remainder
        quotient = list()
        remainder = self.get_coefficients_GF_ELEMENT()[:]
        unten = other.get_coefficients_GF_ELEMENT()[:]

        for i in range(len(self) - len(other), -1, -1):

            obtained_term = remainder[-1] // unten[-1]

            quotient.insert(0, obtained_term)

            temp = GALOIS_POLY_128(coefficients=[obtained_term]) * GALOIS_POLY_128(coefficients=unten)

            # insert i * GF_ELEMENT_128(0) to the front of the temp coefficients
            temp = GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0)] * i + temp.get_coefficients_GF_ELEMENT())

            remainder = (GALOIS_POLY_128(coefficients=remainder) - temp).get_coefficients_GF_ELEMENT()

        if len(quotient) == 0:
            quotient = [GALOIS_ELEMENT_128(0)]

        quotient = GALOIS_POLY_128(coefficients=quotient)
        remainder = GALOIS_POLY_128(coefficients=remainder)

        return quotient, remainder

    def powmod(self, exponent: int, modulo: Self) -> Self:
        """
        Raise a polynomial to the power of another polynomial modulo a polynomial

        exponent: the exponent
        modulo: the modulo

        returns: the result
        """
        result = GALOIS_POLY_128(coefficients=[GALOIS_ELEMENT_128(0x01)])

        # square and multiply
        while exponent:
            if exponent & 1:
                result *= self
                _, result = result // modulo
            self *= self
            _, self = self // modulo
            exponent >>= 1

        return result

    def __str__(self) -> str:
        return f"{[str(coeff) for coeff in self._coefficients]}"

    def get_degree(self):
        return len(self._coefficients) - 1

    def __lt__(self, other: Self) -> bool:
        if self.get_degree() == other.get_degree():
            return self._coefficients[-1] < other._coefficients[-1]
        else:
            return self.get_degree() < other.get_degree()

    def __le__(self, other: Self) -> bool:
        if self.get_degree() == other.get_degree():
            return self._coefficients[-1] <= other._coefficients[-1]
        else:
            return self.get_degree() <= other.get_degree()

    def __gt__(self, other: Self) -> bool:
        if self.get_degree() == other.get_degree():
            return self._coefficients[-1] > other._coefficients[-1]
        else:
            return self.get_degree() > other.get_degree()

    def __ge__(self, other: Self) -> bool:
        if self.get_degree() == other.get_degree():
            return self._coefficients[-1] >= other._coefficients[-1]
        else:
            return self.get_degree() >= other.get_degree()

    def __eq__(self, other: Self) -> bool:
        return self._coefficients == other._coefficients

    def __ne__(self, other: Self) -> bool:
        return not self._coefficients == other._coefficients

    def to_bytes(self, byteorder: str = "little") -> list[bytes]:
        return [coeff.to_bytes(byteorder) for coeff in self._coefficients]

    def to_hex(self, byteorder: str = "little") -> str:
        return [coeff.to_bytes(byteorder).hex() for coeff in self._coefficients]

    def get_coefficients(self) -> list[int]:
        return [coeff.get_block() for coeff in self._coefficients]

    def get_coefficients_GF_ELEMENT(self) -> list[GALOIS_ELEMENT_128]:
        return self._coefficients

    def _clean_zeroes(self):
        while self._coefficients[-1].get_block() == 0 and len(self._coefficients) > 1:
            self._coefficients.pop()

    def __len__(self):
        return len(self._coefficients)


class PADDING_ORACLE:
    def __init__(self, hostname: str, port: int):
        self.hostname = hostname
        self.port = port

    def attack_padding_oracle(self, ciphertext: bytes, IV: bytes) -> bytes:
        self.plaintext = b""
        plaintext_block = b""
        ciphertext_blocks = split_blocks(ciphertext, 16)

        preceding_block = IV

        # we iterate over the ciphertext from the beginning
        for ct_block in ciphertext_blocks:
            self.Q = bytearray(b"\x00" * 16)
            self.block_cipher_output = b""

            for padding_byte in range(1, 16 + 1):

                # q_n = p_n ^ D(C)_n => p_n = padding
                q_n = self.__find_correct_q(padding_byte=padding_byte, ciphertext_block=ct_block)

                # D(C)_15 = q_15 ^ p_15
                D_C_n = self.__calc_decrypted_ciphertext_byte(q_n=q_n, padding=padding_byte)

                self.block_cipher_output = D_C_n.to_bytes(1, "big") + self.block_cipher_output

                # p_15 = 0x01, p_15-14 = 0x02, ... p_15-1 = 0x0F
                self.__set_padding_in_Q_for_next_byte(padding_byte, self.block_cipher_output)

            # decrypt the ciphertext block
            plaintext_block = xor_bytes(self.block_cipher_output, preceding_block)
            self.plaintext += plaintext_block

            # set the preceding block to be the current ciphertext block
            preceding_block = ct_block

        return self.plaintext

    def __set_padding_in_Q_for_next_byte(self, padding_byte: int, IV_xor_PT_raw: int) -> None:
        # set the padding in Q
        # q_n = D(C)_n ^ padding_byte
        for i in range(1, padding_byte + 1):
            self.Q[-i] = IV_xor_PT_raw[-i] ^ (padding_byte + 1)

    def __find_correct_q(self, padding_byte: int, ciphertext_block: bytes) -> int:
        # * server request

        # iterate over the possible values for q_n and add all possible values to a list
        # q_n = 0x00, 0x01, ..., 0xFF
        if padding_byte != 1:
            known_padding = bytearray()
            for i in range(1, padding_byte):
                known_padding.append(padding_byte ^ self.block_cipher_output[-i])
            known_padding.reverse()
            known_padding = bytes(known_padding)
        else:
            known_padding = b""

        Qs_to_try = []
        for i in range(256):
            q_n = i.to_bytes(1, "big")

            # create a new Q for
            if padding_byte == 1:
                temp_Q = q_n
            else:
                temp_Q = q_n + known_padding

            Qs_to_try.append(temp_Q.rjust(16, b"\x00"))

        # concatenate all qs to a single byte string
        Qs_to_try = b"".join(Qs_to_try)

        # send all possible values to the server at once
        try:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.connect((self.hostname, self.port))
            tcp_socket.sendall(ciphertext_block)
            tcp_socket.sendall(int(256).to_bytes(2, "little"))
            tcp_socket.sendall(Qs_to_try)
            # get an response from the server
            response = tcp_socket.recv(256)
        finally:
            tcp_socket.close()

        # check where the padding is correct
        positions = [index for index, byte in enumerate(response) if byte == 0x01]

        # edge case: 2 at rightmost byte
        if padding_byte == 1:
            if len(positions) > 1:
                temp_Q = Qs_to_try[positions[0] * 16 : (positions[0] + 1) * 16]
                temp_Q = bytearray(temp_Q)
                temp_Q[-1] = ~temp_Q[-1] & 0xFF
                temp_Q = bytes(temp_Q)
                # send the new Q to the server
                try:
                    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp_socket.connect((self.hostname, self.port))
                    tcp_socket.sendall(ciphertext_block)
                    tcp_socket.sendall(b"\x01\x00")
                    tcp_socket.sendall(temp_Q)
                    # get an response from the server
                    response = tcp_socket.recv(1)
                finally:
                    tcp_socket.close()
                # check if the padding is correct
                if response == 1:
                    return temp_Q[-1]
                else:
                    temp_Q = Qs_to_try[positions[1] * 16 : (positions[1] + 1) * 16]
                    return temp_Q[-1]
        local_Q = Qs_to_try[positions[0] * 16 : (positions[0] + 1) * 16]
        return local_Q[-padding_byte]

    def __calc_decrypted_ciphertext_byte(self, q_n: int, padding: int) -> int:
        # calculate the decrypted ciphertext byte
        # D(C)_n = q_n ^ padding
        return q_n ^ padding


class GCM_CRYPT:
    """
    GCM encryption and decryption

    algorithm: the algorithm to use (aes128, sea128)
    nonce: the nonce
    key: the key
    """

    def __init__(self, algorithm: str, nonce: bytes, key: bytes):
        self.algorithm = algorithm
        self.nonce = nonce
        self.key = key

    def encrypt(self, plaintext: bytes, ass_data: bytes) -> dict:
        """
        Encrypt the given plaintext using GCM mode

        plaintext: the plaintext to encrypt as a byte string
        ass_data: additional authenticated data (AAD) as a byte string

        returns: a dictionary containing the ciphertext, authentication tag, L value, and authentication key (encoded in base64)
        """
        plaintext_blocks = split_blocks(plaintext, 16)
        ciphertext_blocks = self.__process_encr_and_decr_of_blocks(input_blocks=plaintext_blocks)

        self.ciphertext = b"".join(ciphertext_blocks)

        self.__calc_auth_key()

        self.__calc_ghash(ass_data=ass_data, ciphertext_blocks=ciphertext_blocks)

        return {
            "ciphertext": bytes_to_base64(self.ciphertext),
            "tag": bytes_to_base64((self.__auth_tag()).to_bytes(16, "little")),
            "L": bytes_to_base64(self.L),
            "H": bytes_to_base64(self.auth_key),
        }

    def decrypt(self, ciphertext: bytes, ass_data: bytes, auth_tag: bytes) -> dict:
        """
        Decrypt the given ciphertext using GCM mode and verify its authenticity.

        ciphertext: the ciphertext to decrypt as a byte string
        ass_data: additional authenticated data (AAD) as a byte string
        auth_tag: the authentication tag to verify as a byte string

        returns: a dictionary containing whether the tag is authentic and the decrypted plaintext (encoded in base64)
        """
        self.ciphertext = ciphertext
        ciphertext_blocks = split_blocks(self.ciphertext, 16)
        plaintext_blocks = self.__process_encr_and_decr_of_blocks(input_blocks=ciphertext_blocks)

        self.plaintext = b"".join(plaintext_blocks)

        self.__calc_auth_key()

        self.__calc_ghash(ass_data=ass_data, ciphertext_blocks=ciphertext_blocks)

        return {
            "authentic": self.__check_auth_tag(auth_tag=auth_tag),
            "plaintext": bytes_to_base64(self.plaintext),
        }

    def __check_auth_tag(self, auth_tag: bytes):
        """
        check if the provided authentication tag matches the computed tag.

        auth_tag: the provided authentication tag

        returns: bool
        """
        return auth_tag == self.__auth_tag().to_bytes(16, "little")

    def __calc_auth_key(self) -> None:
        """
        Calculate the authentication key based on the selected algorithm.
        """
        if self.algorithm == "aes128":
            # H = ecb(000...000)
            self.auth_key = aes_ecb(input=bytes(b"\x00" * 16), key=self.key, mode="encrypt")
        elif self.algorithm == "sea128":
            # H = sea(000...000)
            self.auth_key = SEA128(key=self.key).encrypt(bytes(b"\00" * 16))
        else:
            raise ValueError("Invalid algorithm")

    def __process_encr_and_decr_of_blocks(self, input_blocks: list[bytes]) -> list[bytes]:
        """
        Process encryption or decryption of blocks using CTR mode

        input_blocks: the blocks to process

        returns: the processed blocks
        """
        # calc Y_n
        self.Y = list()
        ctr_len = 16 - len(self.nonce)

        for i in range(1, len(input_blocks) + 1 + 1):
            self.Y.append(self.nonce + i.to_bytes(ctr_len, "big"))

        # decrypt blocks
        output_blocks = list()
        if self.algorithm == "aes128":
            for i in range(len(input_blocks)):
                xorblock = aes_ecb(input=self.Y[i + 1], key=self.key, mode="encrypt")
                out_block = xor_bytes(xorblock, input_blocks[i])
                output_blocks.append(out_block)
        elif self.algorithm == "sea128":
            sea = SEA128(key=self.key)
            for i in range(len(input_blocks)):
                xorblock = sea.encrypt(input=self.Y[i + 1])
                out_block = xor_bytes(xorblock, input_blocks[i])
                output_blocks.append(out_block)
        else:
            raise ValueError("Invalid algorithm")

        return output_blocks

    def __calc_ghash(self, ass_data: bytes, ciphertext_blocks: list) -> None:
        """
        Calculate the GHASH value based on additional data and ciphertext blocks.

        ass_data: associated data
        ciphertext_blocks: list of ciphertext blocks for ghash calculation
        """
        # init GHASH
        self.GHASH = int(0)
        ass_data_blocks = split_blocks(ass_data, 16)

        # GHASH ass_data rounds
        for block in ass_data_blocks:
            padded_ass_data = block.ljust(16, b"\x00")
            padded_ass_data_int = int.from_bytes(padded_ass_data, "little")
            self.__ghash_one_round(input=padded_ass_data_int)

        # GHASH ciphertext rounds
        for block in ciphertext_blocks:
            self.__ghash_one_round(input=int.from_bytes(block, "little"))

        # GHASH last round
        self.L = (len(ass_data) * 8).to_bytes(8, "big") + (len(self.ciphertext) * 8).to_bytes(8, "big")
        L_int = int.from_bytes(self.L, "little")
        self.__ghash_one_round(input=L_int)

    def __ghash_one_round(self, input: int) -> None:
        """
        Perform one round of GHASH calculation by XORing and multiplying in GF(2^128).

        input: integer representation of the input block
        """
        # XOR
        self.GHASH ^= input

        # GF multiply
        H_int = int.from_bytes(self.auth_key, "little")
        H_gf_ele = GALOIS_ELEMENT_128(reverse_bits_in_bytes(H_int))
        ghash_gf_ele = GALOIS_ELEMENT_128(reverse_bits_in_bytes(self.GHASH))

        ghash_gf_ele *= H_gf_ele

        self.GHASH = reverse_bits_in_bytes(ghash_gf_ele.get_block())

    def __auth_tag(self) -> int:
        """
        compute and return the authentication tag

        returns: the authentication tag as integer
        """
        if self.algorithm == "aes128":
            encrypted_Y_0 = aes_ecb(input=self.Y[0], key=self.key, mode="encrypt")
        elif self.algorithm == "sea128":
            sea = SEA128(key=self.key)
            encrypted_Y_0 = sea.encrypt(input=self.Y[0])
        else:
            encrypted_Y_0 = b"\x00"

        return self.GHASH ^ int.from_bytes(encrypted_Y_0, "little")
