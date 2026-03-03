import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50221
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


def blocks(X: list | bytes | bytearray | str, size=16):
    return [X[i : i + size] for i in range(0, len(X), size)]


for _ in range(5):
    r = run_command({"command": "encrypt", "prepend_pad": "00" * 0})["res"]
    l = len(r)
    for i in range(16):
        r = run_command({"command": "encrypt", "prepend_pad": b"a".hex() * i})["res"]
        if len(r) != l:
            r = run_command(
                {"command": "encrypt", "prepend_pad": b"a".hex() * (i + 1)}
            )["res"]
            break

    lb = blocks(r, 32)[-1]  # one char + padding, encrypted

    for i in range(256):
        b = pad(bytes([i]), 16)
        r = blocks(
            run_command({"command": "encrypt", "prepend_pad": b.hex()})["res"], 32
        )[0]
        if lb == r:
            print(
                run_command({"command": "solve", "solve": bytes([i]).decode()})
            )  # your guess
            break
print(run_command({"command": "solve"}))
