# feistel_with_padding.py
from hashlib import sha256

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def round_function(right, key):
    return sha256(key + right).digest()[:len(right)]

def round_key(master_key, i):
    return sha256(master_key + i.to_bytes(4, 'big')).digest()

def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def process_block(block, key, rounds, encrypt=True):
    half = len(block)//2
    L, R = block[:half], block[half:]
    if encrypt:
        for i in range(rounds):
            rk = round_key(key, i)
            L, R = R, xor_bytes(L, round_function(R, rk))
    else:
        for i in range(rounds-1, -1, -1):
            rk = round_key(key, i)
            L, R = xor_bytes(R, round_function(L, rk)), L
    return L + R

def feistel_encrypt(data: bytes, key: bytes, rounds=8, block_size=16) -> bytes:
    data = pad(data, block_size)
    out = b""
    for i in range(0, len(data), block_size):
        out += process_block(data[i:i+block_size], key, rounds, True)
    return out

def feistel_decrypt(data: bytes, key: bytes, rounds=8, block_size=16) -> bytes:
    out = b""
    for i in range(0, len(data), block_size):
        out += process_block(data[i:i+block_size], key, rounds, False)
    return unpad(out)

if __name__ == "__main__":
    key = b"supersecretkey"
    msg = b"HELLO FEISTEL CIPHER!"
    cipher = feistel_encrypt(msg, key)
    plain = feistel_decrypt(cipher, key)
    print("Feistel cipher:", cipher.hex())
    print("Feistel plain :", plain)
