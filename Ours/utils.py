
def byteXor(b1, b2):
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)

def strXor(s1, s2):
    return str(int(s1)^int(s2))