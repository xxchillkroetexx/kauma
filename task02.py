from classes import GCM_CRYPT, PADDING_ORACLE
from helper import base64_to_bytes


def padding_oracle(args: dict) -> dict:
    ciphertext = base64_to_bytes(args["ciphertext"])
    IV = base64_to_bytes(args["iv"])
    hostname = args["hostname"]
    port = args["port"]

    padding_oracle = PADDING_ORACLE(hostname, port)
    plaintext = padding_oracle.attack_padding_oracle(ciphertext, IV)

    return {"plaintext": plaintext}


def gcm_encrypt(args: dict) -> dict:
    plaintext = base64_to_bytes(args["plaintext"])
    nonce = base64_to_bytes(args["nonce"])
    key = base64_to_bytes(args["key"])
    algorithm = args["algorithm"]
    ass_data = base64_to_bytes(args["ad"])

    gcm_dict = GCM_CRYPT(algorithm=algorithm, nonce=nonce, key=key).encrypt(plaintext=plaintext, ass_data=ass_data)
    return gcm_dict
