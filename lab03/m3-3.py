import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50303
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


enc = run_command({"command": "howto"})["res"].split(" ")[-1]
encrypted_command = bytes.fromhex(enc)
iv, ctxt = encrypted_command[:16], encrypted_command[16:]
new_iv = xor(xor(pad(b"flag", 16), pad(b"intro", 16)), iv)
new_command = new_iv + ctxt
r = run_command(
    {"command": "encrypted_command", "encrypted_command": new_command.hex()}
)
print(r["res"])
# otp = b""
# for j in range(15):
#     for i in range(256):
#         r = run_command(
#             {
#                 "command": "encrypted_command",
#                 "encrypted_command": (
#                     bytes([0] * (15 - j) + [i]) + xor(otp, bytes([j + 1] * (j)))
#                 ).hex(),
#             }
#         )["res"]
#         if not r.startswith("No"):
#             continue
#         otp = xor(bytes([i]), bytes([j + 1])) + otp
#         print(len(otp), otp)
# for i in range(256):
#     r = run_command(
#         {
#             "command": "encrypted_command",
#             "encrypted_command": xor(pad(b"flag", 16), bytes([i]) + otp).hex(),
#         }
#     )["res"]
#
#     if not r.startswith("flag"):
#         continue
#     print(r)
