import json
import socket
from Crypto.Hash import HMAC, MD5, SHA1, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50343
REMOTE = False
REMOTE = True
HOST = "aclabs.ethz.ch"

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())


def xor(X: bytes | bytearray, Y: bytes | bytearray) -> bytes:
    return bytes(x ^ y for (x, y) in zip(X, Y))


def pad(X: bytes | bytearray, k: int) -> bytes:
    klmk = k - (len(X) % k)
    p = [klmk] * klmk
    return bytes([x for x in X] + p)


def blocks(X: bytes | bytearray | str, size=16):
    return [X[i : i + size] for i in range(0, len(X), size)]


def onion(pw: str, salt: str) -> bytes:
    SECRET = "6275742061726520617765736f6d6520f09f988b"

    md5 = MD5.new()
    md5.update(bytes.fromhex(pw))
    h1 = md5.digest()

    hmac_sha1 = HMAC.new(bytes.fromhex(salt), digestmod=SHA1)
    hmac_sha1.update(h1)
    h2 = hmac_sha1.digest()

    hmac_sha256 = HMAC.new(bytes.fromhex(SECRET), digestmod=SHA256)
    hmac_sha256.update(h2)
    h3 = hmac_sha256.digest()

    h4 = scrypt(
        h3, salt=bytes.fromhex(salt), key_len=64, N=2**10, r=32, p=2, num_keys=1
    )
    assert isinstance(h4, bytes)

    hmac_sha256_2 = HMAC.new(bytes.fromhex(salt), digestmod=SHA256)
    hmac_sha256_2.update(h4)
    h5 = hmac_sha256_2.digest()

    return h5


PW = "6f6e696f6e732061726520736d656c6c79"
SALT = "696e2061206e69636520736f6666726974746f21"
print(onion(PW, SALT).hex())
