#! /usr/bin/env python
# Python-3 port:
#   - All byte/str operations updated: str is text, bytes is binary.
#   - chr()/ord() removed; bytes indexing already yields int in Python 3.
#   - String concatenation (+=) changed to bytes concatenation.
#   - Integer division /  changed to //.
#   - SHA256.update() now receives bytes, not str.
#   - a2b_hex replaced by bytes.fromhex().
#   - encrypt() returns hex string; decrypt() accepts hex string.
#     This lets network.py handle everything as UTF-8 text (base64 over the wire).

from random import randint
from Crypto.Cipher import AES


def gen_rand_data(length=16):
    return bytes(randint(0, 255) for i in range(length))


def pkcs_7_pad(data, final_len=None):
    if final_len is None:
        final_len = (len(data) // 16 + 1) * 16   # // avoids float
    padding_len = final_len - len(data)
    return data + bytes([padding_len] * padding_len)


class PaddingException(Exception):

    """ Padding for input data incorrect """


def pkcs_7_unpad(data):
    padding_len = data[-1]   # Python 3: bytes[i] is already int, no ord() needed
    if padding_len > 16:  # Block size
        raise PaddingException
    if padding_len == 0:
        raise PaddingException
    for i in range(len(data) - padding_len, len(data)):
        if data[i] != padding_len:   # comparing int to int
            raise PaddingException
    return data[:-padding_len]


def AES_128_ECB_encrypt(data, key, pad=False):
    cipher = AES.new(key, AES.MODE_ECB)
    if pad:
        data = pkcs_7_pad(data)
    return cipher.encrypt(data)


def AES_128_ECB_decrypt(data, key, unpad=False):
    cipher = AES.new(key, AES.MODE_ECB)
    decr = cipher.decrypt(data)
    if unpad:
        decr = pkcs_7_unpad(decr)
    return decr


def xor_data(A, B):
    return bytes(A[i] ^ B[i] for i in range(len(A)))   # bytes[i] gives int; ^ is fine


def AES_128_CBC_encrypt(data, key, iv):
    if isinstance(data, str):
        data = data.encode('utf-8')   # accept plain-text str input
    data = pkcs_7_pad(data)
    block_count = len(data) // 16   # // avoids float
    encrypted_data = b''            # bytes accumulator (was '' in Python 2)
    prev_block = iv
    for b in range(block_count):
        cur_block = data[b * 16:(b + 1) * 16]
        encrypted_block = AES_128_ECB_encrypt(
            xor_data(cur_block, prev_block), key)
        encrypted_data += encrypted_block
        prev_block = encrypted_block
    return encrypted_data


def AES_128_CBC_decrypt(data, key, iv):
    if len(data) % 16 != 0:
        print("Invalid size of data %s (len = %d)" % (repr(data), len(data)))
        return b''
    block_count = len(data) // 16   # // avoids float
    decrypted_data = b''            # bytes accumulator
    prev_block = iv
    for b in range(block_count):
        cur_block = data[b * 16:(b + 1) * 16]
        decrypted_block = AES_128_ECB_decrypt(cur_block, key)
        decrypted_data += xor_data(decrypted_block, prev_block)
        prev_block = cur_block
    return pkcs_7_unpad(decrypted_data)


class CryptoProtocol:

    def __init__(self, key):
        from Crypto.Hash import SHA256
        h = SHA256.new()
        h.update(str(key).encode('utf-8'))   # update() needs bytes in Python 3
        long_key = bytes.fromhex(h.hexdigest())   # replaces a2b_hex(h.hexdigest())
        self.AES_key = long_key[:16]
        self.AES_iv = long_key[16:]

    def encrypt(self, data):
        raw = AES_128_CBC_encrypt(data, self.AES_key, self.AES_iv)
        return raw.hex()   # hex string: safe UTF-8 text for network.send()

    def decrypt(self, data):
        raw = bytes.fromhex(data)   # hex string → raw cipher bytes
        result = AES_128_CBC_decrypt(raw, self.AES_key, self.AES_iv)
        return result.decode('utf-8')

if __name__ == '__main__':
    text = 'abcdefghijklmnopqrstuvwxyz!'
    key = 'abcdef1234567890'

    c = CryptoProtocol(key)
    assert(c.decrypt(c.encrypt(text)) == text)
    print("[+] CBC decrypt(encrypt(text))==text test passed")
