# spn_with_padding.py

SBOX = [0xE, 0x4, 0xD, 0x1,
        0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC,
        0x5, 0x9, 0x0, 0x7]
INV_SBOX = [SBOX.index(x) for x in range(16)]

PBOX = [0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15]
INV_PBOX = [PBOX.index(i) for i in range(16)]

def substitute(block, sbox):
    output = 0
    for i in range(4):
        nibble = (block >> (i * 4)) & 0xF
        output |= sbox[nibble] << (i * 4)
    return output

def permute(block, pbox):
    output = 0
    for i in range(16):
        bit = (block >> i) & 1
        output |= bit << pbox[i]
    return output

def spn_encrypt_block(block, keys):
    blk = block
    for i in range(3):
        blk ^= keys[i]
        blk = substitute(blk, SBOX)
        blk = permute(blk, PBOX)
    blk ^= keys[3]
    blk = substitute(blk, SBOX)
    blk ^= keys[4]
    return blk

def spn_decrypt_block(block, keys):
    blk = block
    blk ^= keys[4]
    blk = substitute(blk, INV_SBOX)
    blk ^= keys[3]
    for i in range(2, -1, -1):
        blk = permute(blk, INV_PBOX)
        blk = substitute(blk, INV_SBOX)
        blk ^= keys[i]
    return blk

# --- PKCS#7 padding ---
def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# --- Обработка сообщения ---
def spn_encrypt(data: bytes, keys, block_size: int = 2) -> bytes:
    data = pad(data, block_size)
    cipher = b""
    for i in range(0, len(data), block_size):
        block = int.from_bytes(data[i:i+block_size], "big")
        enc = spn_encrypt_block(block, keys)
        cipher += enc.to_bytes(block_size, "big")
    return cipher

def spn_decrypt(data: bytes, keys, block_size: int = 2) -> bytes:
    plain = b""
    for i in range(0, len(data), block_size):
        block = int.from_bytes(data[i:i+block_size], "big")
        dec = spn_decrypt_block(block, keys)
        plain += dec.to_bytes(block_size, "big")
    return unpad(plain)

if __name__ == "__main__":
    keys = [0x3A94, 0x0512, 0x4F8A, 0xBADC, 0x1234]
    msg = b"HELLO WORLD"
    cipher = spn_encrypt(msg, keys)
    plain = spn_decrypt(cipher, keys)
    print("SPN cipher:", cipher.hex())
    print("SPN plain :", plain)
