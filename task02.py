import cryptography.hazmat.primitives.ciphers as ciphers
import socket
from helper import base64_to_bytes, bytes_to_base64, split_blocks, aes_ecb, xor_bytes, SEA128, GFMUL

def padding_oracle(args: dict) -> dict:
    ciphertext = base64_to_bytes(args["ciphertext"])
    IV = base64_to_bytes(args["iv"])
    hostname = args["hostname"]
    port = args["port"]

    padding_oracle = PaddingOracle(hostname, port)
    plaintext = padding_oracle.attack_padding_oracle(ciphertext, IV)

    return {"plaintext": plaintext}

def gcm_encrypt(args: dict) -> dict:
    plaintext = base64_to_bytes(args["plaintext"])
    nonce = base64_to_bytes(args["nonce"])
    key = base64_to_bytes(args["key"])
    algorithm = args["algorithm"]
    ass_data = base64_to_bytes(args["ad"])

    gcm_dict = GCM_Crypt(algorithm=algorithm, nonce=nonce, key=key).encrypt(plaintext=plaintext, ass_data=ass_data)
    return gcm_dict

class PaddingOracle:
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

    def bruteforce_byte(self, Q: bytearray, working_iv:bytearray, current_byte: int) -> bytes:
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



class GCM_Crypt():
    def __init__(self, algorithm: str, nonce: bytes, key: bytes):
        self.algorithm = algorithm
        self.nonce = nonce
        self.key = key
        
    def encrypt(self, plaintext: bytes, ass_data: bytes) -> bytes:
        ciphertext_blocks = bytearray()
        plaintext_blocks = split_blocks(plaintext, 16)
        mode = "encrypt"
        Y = list()
        Y_len = 16 - len(self.nonce)
        for i in range(1,len(plaintext_blocks)):
            # Y_0 = nonce || ctr 1
            # Y_n = nonce || ctr n+1
            Y.append(self.nonce + i.to_bytes(Y_len, "big"))
        
        match self.algorithm:
            case "aes128":
                #*for auth_key H
                # H = ecb(000...000)
                H = aes_ecb(input=bytes(16), key=self.key, mode=mode)
                
                #*Block Encrypt
                # CT_1 = ecb_K(Y_1) ^ PT_1
                # CT_n = ecb_K(Y_n) ^ PT_n
                for pt_block in plaintext_blocks:
                    xorblock = aes_ecb(input=pt_block, key=self.key, mode=mode)
                    ct_block = xor_bytes(xorblock, pt_block)
                    ciphertext_blocks.append(ct_block)

            case "sea128":
                pass
            
            case _:
                raise ValueError("Invalid algorithm")
        
        #*for GHASH
        # init_xor = 0000...0000
        init_xor = bytes(16)
        # init_xor = gfmul((ass_data ^ init_xor), H)
        init_xor = GFMUL.gcm(a=xor_bytes(init_xor, ass_data), b=H)
        
        # solange CT_blöcke: 
        for ct_block in ciphertext_blocks:
            # init_xor = gfmul((CT_n ^ init_xor), H)
            init_xor = GFMUL.gcm(a=xor_bytes(init_xor, ct_block), b=H)
        
        # ghash = gfmul((L ^ init_xor), H)
        L = len(plaintext).to_bytes(16, "big")
        GHASH = GFMUL.gcm(a=xor_bytes(init_xor, L), b=H)
        
        #*for auth_tag
        # auth_tag = ecb_K(Y_0) ^ ghash
        auth_tag = xor_bytes(Y[0], GHASH)

        return {
            "ciphertext": bytes_to_base64(bytes(ciphertext_blocks)),
            "tag": bytes_to_base64(auth_tag),
            "L": bytes_to_base64(L),
            "H": bytes_to_base64(H),
        }        
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
    
    def _ghash():
        pass