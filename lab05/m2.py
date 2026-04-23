import json
import socket
import string
from string import ascii_letters, digits
from Crypto.Hash import HMAC, MD5, SHA1, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import itertools

from passlib.hash import argon2

ALPHABET = ascii_letters + digits
PORT = 50501
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


def pw_hash(pw, salt):
    return argon2.hash(secret=pw)


# r = bytes.fromhex(run_command({"command": "password"})["res"])
# h = argon2.hash(secret=r)
# print(h)
# r = run_command({"command": "guess", "guess": h})
# print(r)

SALT = "b49d3002f2a089b371c3"
HASH = "d262db83f67a37ff672cf5e1d0dfabc696e805bc"

ctr = 0
for pw in itertools.product(string.ascii_lowercase, repeat=6):
    pws = "".join(pw)
    hmac_sha1 = HMAC.new(pws.encode(), digestmod=SHA1)
    hmac_sha1.update(bytes.fromhex(SALT))
    h = hmac_sha1.hexdigest()

    if HASH == h:
        print(pws)
        break

    if ctr % 100000 == 0:
        print(ctr)
    ctr += 1
