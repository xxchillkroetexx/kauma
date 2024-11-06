import socket
from helper import (
    aes_ecb,
    bytes_to_base64,
    coefficients_to_min_polynom,
    reverse_bits_in_bytes,
    split_blocks,
    xor_bytes,
)


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


class GALOIS_FIELD_128:
    def __init__(self, min_poly_coefficients: list[int], mode: str):
        self._mode = mode
        self._minimal_polynomial = coefficients_to_min_polynom(min_poly_coefficients)

    def multiply(self, a: int, b: int) -> int:
        """
        Multiply two numbers in GF(2^128)

        a: the first polynomial
        b: the second polynomial

        returns: the product
        """
        if self._mode == "gcm":
            a = reverse_bits_in_bytes(a)
            b = reverse_bits_in_bytes(b)
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
            a = self.reduce_polynomial(polynomial=a)

        # reduce the result one last time
        result = self.reduce_polynomial(polynomial=result)

        # convert the result back to gcm mode
        if self._mode == "gcm":
            result = reverse_bits_in_bytes(result)

        return result

    def reduce_polynomial(self, polynomial: int) -> int:
        """
        Reduce a polynomial using the minimal polynomial

        a: the polynomial
        minimal_polynomial: the non-reducable polynomial

        returns: the reduced polynomial
        """
        while polynomial.bit_length() >= self._minimal_polynomial.bit_length():
            shift = polynomial.bit_length() - self._minimal_polynomial.bit_length()
            polynomial ^= self._minimal_polynomial << shift

        return polynomial


class PADDING_ORACLE:
    def __init__(self, hostname: str, port: int):
        self.hostname = hostname
        self.port = port

    def __del__(self):
        if self.socket:
            self.socket.close()

    def attack_padding_oracle(self, ciphertext: bytes, IV: bytes) -> bytes:
        # split the ciphertext into blocks of 16 bytes
        blocks = split_blocks(ciphertext, 16)
        xor_iv = IV
        plaintext = bytes()
        for block in blocks:
            Q = bytearray(b"\x00" * 16)

            for current_byte in range(15, -1, -1):
                Q = self.bruteforce_new_Q(Q=Q, ciphertext=block, current_byte=current_byte)

            print(f"Decrypted block: {Q.hex()}")
            print(f"plaintext block: {xor_bytes(Q, xor_iv).hex()}")
            plaintext += xor_bytes(Q, xor_iv)
            print(f"Plaintext: {plaintext.hex()}")
            xor_iv = block

        return plaintext

    def bruteforce_new_Q(self, Q: bytearray, ciphertext: bytearray, current_byte: int) -> bytes:
        working_iv = bytearray(b"\x00" * 16)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.hostname, self.port))

        self.socket.send(ciphertext)

        for i in range(15, current_byte, -1):
            bytes_to_generate = 16 - current_byte
            working_iv[i] = Q[i] ^ bytes_to_generate

        new_Q = self.bruteforce_byte(Q=Q, working_iv=working_iv, current_byte=current_byte)
        self.socket.close()
        return new_Q

    def bruteforce_byte(self, Q: bytearray, working_iv: bytearray, current_byte: int) -> bytes:
        for guess in range(256):
            # set the guess for the current byte
            working_iv[current_byte] = guess
            if self.check_padding(IV=working_iv):
                # if last byte, check for false positives
                if current_byte == 15:
                    temp_working_iv = bytearray(working_iv)
                    # invert the second last byte and check again
                    temp_working_iv[-2] = ~temp_working_iv[-2] & 0xFF
                    if self.check_padding(IV=temp_working_iv) == False:
                        continue  # continue with next guess as this is a false positive
                print(f"Found correct guess for byte {current_byte}: {hex(guess)}")
                # return the correct guess
                Q = bytearray(Q)
                Q[current_byte] = guess ^ (16 - current_byte)
                return bytes(Q)

        raise ValueError(f"No valid padding found for byte: {current_byte}")

    def check_padding(self, IV: bytes) -> bool:
        self.socket.send(int(1).to_bytes(2, "little"))
        self.socket.send(IV)
        response = self.socket.recv(1)
        return response == b"\x01"


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
        gf = GALOIS_FIELD_128(min_poly_coefficients=[0, 1, 2, 7, 128], mode="gcm")
        H_int = int.from_bytes(self.auth_key, "little")

        self.GHASH = gf.multiply(a=(self.GHASH), b=(H_int))

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
