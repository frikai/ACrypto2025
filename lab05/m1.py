import json
import socket
from Crypto.Hash import HMAC, MD5, SHA1, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from string import ascii_letters, digits
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


r = bytes.fromhex(run_command({"command": "password"})["res"])
h = argon2.hash(secret=r)
print(h)
r = run_command({"command": "guess", "guess": h})
print(r)
