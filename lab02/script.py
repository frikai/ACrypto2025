from Crypto.Hash import SHA256
from Crypto.Cipher import AES

message = ...  # REDACTED
seed = ...  # REDACTED
iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")


def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder="big")
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key


def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def aes_cbc_decryption(ctext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ctext)
    return plaintext

    # Be careful when running this script: it will override your existing flag.enc
    # with open("flag.enc", "w") as f:
    #     f.write(aes_cbc_encryption(message, key, iv).hex())


ciphertext = "79b04593c08cb44da3ed9393e3cbb094ad1ea5b7af8a40457ce87f2c3095e29980a28da9b2180061e56f61cd3ee023ebb08e8607bc44ae37682b1a4a39ca7eaf285b32f575a8bfb630ccd1548c6a7c6d78ceec8e1f45866a0f17bf5216c29ca3"
ciphertext = bytes.fromhex(ciphertext)
for i in range(2**16):
    k = generate_aes_key(i, 16)
    ptxt = aes_cbc_decryption(ciphertext, k, iv)
    # print(ptxt)
    try:
        print(ptxt.decode())
    except:
        pass
