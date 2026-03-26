from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad


def xor(X: bytes | bytearray, Y: bytes | bytearray) -> bytes:
    return bytes(x ^ y for (x, y) in zip(X, Y))


def blocks(X: bytes | bytearray | str, size=16):
    return [X[i : i + size] for i in range(0, len(X), size)]


class StrangeCBC:
    def __init__(self, key: bytes, iv: bytes | None = None, block_length: int = 16):
        """Initialize the CBC cipher."""

        if iv is None:
            iv = get_random_bytes(16)

        self.iv = iv
        self.key = key
        self.block_length = block_length
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.leet = (1336).to_bytes(16, "big")

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        padded_plaintext = pad(plaintext, self.cipher.block_size)
        ctext = b""
        c_i = self.iv
        for ptxt_block in blocks(padded_plaintext):
            assert type(ptxt_block is bytes)
            c_i = self.cipher.encrypt(xor(xor(ptxt_block, c_i), self.leet))
            ctext += c_i
        return ctext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        ctxt_blocks = blocks(ciphertext)
        ptxt = b""
        for i in reversed(range(len(ctxt_blocks))):
            d_i = self.cipher.decrypt(ctxt_blocks[i])
            c_im1 = self.iv
            if i != 0:
                c_im1 = ctxt_blocks[i - 1]
            p_i = xor(xor(d_i, self.leet), c_im1)
            ptxt = p_i + ptxt

        return unpad(ptxt, self.cipher.block_size)


def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
        "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
        "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
        "3fd46234ff7b62ad365d1db13bb249721b"
    )
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")


if __name__ == "__main__":
    main()
