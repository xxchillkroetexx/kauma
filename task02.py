from classes import GCM_CRYPT, PADDING_ORACLE
from helper import base64_to_bytes


def padding_oracle(args: dict) -> bytes:
    """
    Decrypt a ciphertext using a padding oracle attack

    args: dictionary containing the ciphertext, IV, hostname and port

    returns: plaintext
    """
    ciphertext = base64_to_bytes(args["ciphertext"])
    IV = base64_to_bytes(args["iv"])
    hostname = args["hostname"]
    port = args["port"]

    padding_oracle = PADDING_ORACLE(hostname, port)
    plaintext = padding_oracle.attack_padding_oracle(ciphertext=ciphertext, IV=IV)

    return plaintext


def gcm_encrypt(args: dict) -> dict:
    """
    Encrypt a plaintext using GCM

    args: dictionary containing the plaintext, nonce, key, algorithm and associated data

    returns: ciphertext, tag and IV
    """
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
    """
    Decrypt ciphertext using GCM

    args: dictionary containing ciphertext, nonce, key, algorithm and associated data

    returns: plaintext and authenticity of auth tag
    """
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
