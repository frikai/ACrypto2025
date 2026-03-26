import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50301
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


intro = (run_command({"command": "howto"}))["res"].split(" ")[-1]
print(intro)
enc_flag = xor(xor(bytes.fromhex(intro), pad(b"intro", 16)), pad(b"flag", 16)).hex()
print(run_command({"command": "encrypted_command", "encrypted_command": enc_flag}))
