import base64


def set_bit(self, bit_index):
    self |= 1 << bit_index
    return self


def mask_bytes(bytestr, mask):
    for i in range(len(bytestr)):
        bytestr[i] &= mask[i]
    return bytestr


def bytes_to_base64(bytestr):
    return base64.b64encode(bytestr).decode()
