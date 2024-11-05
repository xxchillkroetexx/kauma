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
    """
    Class to multiply two numbers in GF(2^128)

    minimal_polynomial: the non-reducable polynomial
    """

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
    def __init__(self, algorithm: str, nonce: bytes, key: bytes):
        self.algorithm = algorithm
        self.nonce = nonce
        self.key = key

    def encrypt(self, plaintext: bytes, ass_data: bytes) -> dict:
        plaintext_blocks = split_blocks(plaintext, 16)
        ciphertext_blocks = self.__encrypt_blocks(plaintext_blocks=plaintext_blocks)

        self.ciphertext = b"".join(ciphertext_blocks)

        self.__calc_auth_key()

        self.__calc_ghash(ass_data=ass_data, ciphertext_blocks=ciphertext_blocks)

        self.__auth_tag

        return {
            "ciphertext": bytes_to_base64(self.ciphertext),
            "tag": bytes_to_base64((self.__auth_tag()).to_bytes(16, "little")),
            "L": bytes_to_base64(self.L.to_bytes(16, "big")),
            "H": bytes_to_base64(self.auth_key),
        }

    def __calc_auth_key(self) -> None:
        """this works"""
        if self.algorithm == "aes128":
            # H = ecb(000...000)
            self.auth_key = aes_ecb(input=bytes(b"\x00" * 16), key=self.key, mode="encrypt")
        elif self.algorithm == "sea128":
            # H = sea(000...000)
            self.auth_key = SEA128(key=self.key).encrypt(bytes(b"\00" * 16))
        else:
            raise ValueError("Invalid algorithm")

    def __encrypt_blocks(self, plaintext_blocks: bytes) -> list[bytes]:
        """this works"""
        # calc Y_n
        self.Y = list()
        self.Y_len = 16 - len(self.nonce)

        for i in range(1, len(plaintext_blocks) + 1 + 1):
            self.Y.append(self.nonce + i.to_bytes(self.Y_len, "big"))

        # encrypt blocks
        ciphertext_blocks = list()
        mode = "encrypt"
        if self.algorithm == "aes128":
            for i in range(len(plaintext_blocks)):
                xorblock = aes_ecb(input=self.Y[i + 1], key=self.key, mode=mode)
                ct_block = xor_bytes(xorblock, plaintext_blocks[i])
                ciphertext_blocks.append(ct_block)
        elif self.algorithm == "sea128":
            sea = SEA128(key=self.key)
            for i in range(len(plaintext_blocks)):
                xorblock = sea.encrypt(input=self.Y[i + 1])
                ct_block = xor_bytes(xorblock, plaintext_blocks[i])
                ciphertext_blocks.append(ct_block)
        else:
            raise ValueError("Invalid algorithm")

        return ciphertext_blocks

    def __calc_ghash(self, ass_data: bytes, ciphertext_blocks: list) -> None:  # TODO
        self.GHASH = int(0)

        padded_ass_data = ass_data.ljust(16, b"\x00")
        padded_ass_data_int = int.from_bytes(padded_ass_data, "big")

        print("GHASH 0 -> ", hex(self.GHASH))
        print(padded_ass_data.hex())
        print(hex(padded_ass_data_int)[2:])
        # ass_data rounds
        # for block in padded_ass_data_block:
        self.__ghash_one_round(input=padded_ass_data_int)
        print("GHASH A -> ", hex(self.GHASH))

        # ciphertext rounds
        for block in ciphertext_blocks:
            self.__ghash_one_round(input=int.from_bytes(block, "big"))
            print("GHASH C -> ", hex(self.GHASH))

        # last round
        self.L = (len(ass_data) * 8) << 64 | (len(self.ciphertext) * 8)
        self.__ghash_one_round(input=self.L)
        print("GHASH L -> ", hex(self.GHASH))

    def __ghash_one_round(self, input: int) -> None:  # TODO
        # XOR
        self.GHASH ^= input

        # GF multiply
        gf = GALOIS_FIELD_128(min_poly_coefficients=[0, 1, 2, 7, 128], mode="gcm")

        H_int = int.from_bytes(self.auth_key, "big")
        print("H_int: ", hex(H_int)[2:])
        print("H_key: ", self.auth_key.hex())
        self.GHASH = gf.multiply(a=reverse_bits_in_bytes(self.GHASH), b=reverse_bits_in_bytes(H_int))
        pass

    def __auth_tag(self) -> int:
        return self.GHASH ^ int.from_bytes(self.Y[0], "big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        pass

    # ! ######################### Death Below ######################### ! #
    def encrypt_old(self, plaintext: bytes, ass_data: bytes):

        ciphertext_blocks = list()
        plaintext_blocks = split_blocks(plaintext, 16)
        mode = "encrypt"
        Y = list()
        Y_len = 16 - len(self.nonce)

        # padd associated data with 0x00 right to 16 byte length
        ass_data_padded = ass_data.ljust(16, b"\x00")

        for i in range(1, len(plaintext_blocks) + 1 + 1):
            # Y_0 = nonce || ctr 1
            # Y_n = nonce || ctr n+1
            Y.append(self.nonce + i.to_bytes(Y_len, "big"))

        match self.algorithm:
            case "aes128":
                # *for auth_key H
                H = aes_ecb(input=bytes(b"\x00" * 16), key=self.key, mode=mode)

                # *Block Encrypt
                # CT_1 = ecb_K(Y_1) ^ PT_1
                # CT_n = ecb_K(Y_n) ^ PT_n
                for i in range(len(plaintext_blocks)):
                    xorblock = aes_ecb(input=Y[i + 1], key=self.key, mode=mode)
                    ct_block = xor_bytes(xorblock, plaintext_blocks[i])
                    ciphertext_blocks.append(ct_block)

            case "sea128":
                # *for auth_key H
                sea = SEA128(key=self.key)
                H = sea.encrypt(input=bytes(b"\x00" * 16))

                # *Block Encrypt
                # CT_1 = sea(Y_1) ^ PT_1
                # CT_n = sea(Y_n) ^ PT_n
                for i in range(len(plaintext_blocks)):
                    xorblock = sea.encrypt(input=Y[i + 1])
                    ct_block = xor_bytes(xorblock, plaintext_blocks[i])
                    ciphertext_blocks.append(ct_block)

            case _:
                raise ValueError("Invalid algorithm")

        ciphertext = b"".join(ciphertext_blocks)

        # TODO: GHASH still not working correctly. rotate the bytes before gfmul!!
        # *for GHASH
        # init_xor = 0000...0000
        init_xor = bytes(b"\x00" * 16)
        # init_xor = gfmul((ass_data ^ init_xor), H)
        gf = GALOIS_FIELD_128(min_poly_coefficients=[128, 7, 2, 1, 0], mode="gcm")
        init_xor_int = int.from_bytes(xor_bytes(ass_data_padded, init_xor), "little")
        H_int = int.from_bytes(H, "little")
        # reverse for gcm mul
        init_xor_int = reverse_bits_in_bytes(init_xor_int)
        H_int = reverse_bits_in_bytes(H_int)
        init_xor_int = gf.multiply(a=init_xor_int, b=H_int)

        # solange CT_blöcke:
        for ct_block in ciphertext_blocks:
            # init_xor = gfmul((CT_n ^ init_xor), H)
            init_xor_int ^= int.from_bytes(ct_block, "little")
            init_xor_int = reverse_bits_in_bytes(init_xor_int)
            init_xor_int = gf.multiply(a=init_xor_int, b=H_int)
        # TODO ###################################################### TODO #

        # L = bit_length(ass_data) || bit_length(ciphertext)
        L = (len(ass_data) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
        L_int = int.from_bytes(L, "big")
        L_int = reverse_bits_in_bytes(L_int)
        # print("L     = ", L.hex())
        # print("L_int = ", hex(L_int)[2:])

        # ghash = gfmul((L ^ init_xor), H)
        init_xor_int ^= L_int
        init_xor_int = reverse_bits_in_bytes(init_xor_int)
        GHASH = gf.multiply(a=init_xor_int, b=H_int)

        # *for auth_tag
        # auth_tag = ecb_K(Y_0) ^ ghash
        auth_tag = GHASH ^ int.from_bytes(Y[0], "little")

        return {
            "ciphertext": bytes_to_base64(bytes(ciphertext)),
            "tag": bytes_to_base64(auth_tag.to_bytes(16, "little")),
            "L": bytes_to_base64(L),
            "H": bytes_to_base64(H),
        }

    ############################################################
