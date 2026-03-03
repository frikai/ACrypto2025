import json
import socket
import math

PORT = 50220
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


m = "flag, please!"
mp = pad(m.encode(), 16)
res = run_command({"command": "encrypt", "prepend_pad": mp.hex()})["res"]
print(blocks(res, 32))
encm = res[0 : len(blocks(mp)) * 32]
print(run_command({"command": "solve", "ciphertext": encm}))
