import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50390
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

res = run_command({"command":"hex_command", "hex_command":"ff", })
print(res["res"])
#
# ctxt = run_command({"command": "encrypt", "prepend_pad": "00" * 0})["res"]
# init_len = len(ctxt)
# msglen = 0
# padlen = 0
# for i in range(16):
#     ctxt = run_command({"command": "encrypt", "prepend_pad": b"a".hex() * i})["res"]
#     if len(ctxt) != init_len:
#         msglen = init_len // 2 - i
#         padlen = i + 1
#         break
#
# block_index = len(blocks(ctxt, 32)) - 1
#
# known = bytes([])
# for _ in range(msglen):
#     known_block_ctxt = blocks(
#         run_command({"command": "encrypt", "prepend_pad": b"a".hex() * padlen})["res"],
#         32,
#     )[block_index]
#
#     for i in range(256):
#         b: bytes = blocks(pad(bytes([i]) + known, 16))[0]
#         ctxt = blocks(
#             run_command({"command": "encrypt", "prepend_pad": b.hex()})["res"], 32
#         )[0]
#         if known_block_ctxt == ctxt:
#             known = bytes([i]) + known
#             print(known.decode())
#             break
#     padlen += 1
