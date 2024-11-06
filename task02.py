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
    gcm_encrypt_dict = GCM_CRYPT(algorithm=algorithm, nonce=nonce, key=key).encrypt(
        plaintext=plaintext, ass_data=ass_data
    )
    return gcm_encrypt_dict


def gcm_decrypt(args: dict) -> dict:
    algorithm = args["algorithm"]
    nonce = base64_to_bytes(args["nonce"])
    key = base64_to_bytes(args["key"])
    ciphertext = base64_to_bytes(args["ciphertext"])
    ass_data = base64_to_bytes(args["ad"])
    auth_tag = base64_to_bytes(args["tag"])
    gcm_decrypt_dict = GCM_CRYPT(algorithm=algorithm, nonce=nonce, key=key).decrypt(
        ciphertext=ciphertext, ass_data=ass_data, auth_tag=auth_tag
    )
    return gcm_decrypt_dict
