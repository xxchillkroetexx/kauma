import socket
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

import time

class PaddingOracleServer:
    def __init__(self, key):
        # Initialize the server with the specified AES key
        self.key = bytes.fromhex(key)
        backend = default_backend()
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=backend)

    def decrypt_ciphertext(self, ciphertext):
        # Decrypts the provided ciphertext with AES-ECB and returns the plaintext
        decryptor = self.cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted

    def check_padding(self, q_block, plaintext):
        # XOR the Q block with the decrypted plaintext to simulate padding oracle check
        pt = bytes(x ^ y for x, y in zip(q_block, plaintext))
        padder = PKCS7(128).unpadder()
        padder.update(pt)
        try:
            padder.finalize()
            return True  # Padding is correct
        except ValueError:
            return False  # Padding is incorrect

def start_server(host, port, key):
    # Start the server and wait for client connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen()
        print(f"Padding Oracle Server running on {host}:{port}")

        oracle = PaddingOracleServer(key)

        while True:
            conn, addr = server.accept()
            with conn:
                print(f"Connected by {addr}")

                # Step 1: Receive initial 16-byte ciphertext from client
                received_ciphertext = conn.recv(16)
                if len(received_ciphertext) != 16:
                    print("Invalid ciphertext received. Closing connection.")
                    conn.close()
                    continue
                print(f"Received Ciphertext: {received_ciphertext.hex()}")

                # Decrypt the ciphertext once at the beginning
                initial_plaintext = oracle.decrypt_ciphertext(received_ciphertext)

                while True:
                    # Step 2: Receive length field l (2 bytes, little endian)
                    length_field = conn.recv(2)
                    if not length_field:
                        break

                    # Convert length field to integer
                    l = struct.unpack('<H', length_field)[0]
                    print(f"Length field l: {l}")

                    # If l = 0, terminate the connection
                    if l == 0:
                        print("Connection terminated by client request.")
                        break

                    # Step 3: Collect all Q-blocks (l blocks of 16 bytes each)
                    q_blocks = conn.recv(16 * l)
                    if len(q_blocks) != 16 * l:
                        print(len(q_blocks))
                        print("Invalid Q-blocks received. Closing connection.")
                        break
                    print(f"Received Q-blocks: {len(q_blocks)} bytes")

                    # Step 4: Prepare response for each Q-block (l bytes, 00 or 01)
                    response = bytearray()
                    for i in range(l):
                        q_block = q_blocks[i*16:(i+1)*16]
                        # Check padding and generate response byte
                        if oracle.check_padding(q_block, initial_plaintext):
                            response.append(0x01)  # Padding correct
                        else:
                            response.append(0x00)  # Padding incorrect

                    # Send all responses as one response after processing all Q-blocks
                    conn.sendall(response)
                
                    print(f"Sent response: {response.hex()}")

if __name__ == '__main__':
    # Example key for server initialization
    key = "00000000000000000000000000000000"
    start_server("127.0.0.1", 18652, key)
