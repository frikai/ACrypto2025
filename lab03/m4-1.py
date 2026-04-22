import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50341
REMOTE = False
# REMOTE = True
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


for j in range(100):
    command_ctxt = run_command({"command": "challenge"})["res"]
    command_ctxt_b = bytes.fromhex(command_ctxt)
    iv_b = command_ctxt_b[:16]
    ctxt_b = command_ctxt_b[16:]

    for i in range(256):
        # iv_nb = xor(iv_b, bytes(15 * [0] + [i]))
        iv_nb = bytes(15 * [0] + [i])
        r = run_command({"command": "decrypt", "ciphertext": (iv_nb + ctxt_b).hex()})
        # print(i, len(r["res"]))
        if len(r["res"]) != 128:
            # print("Positive:", len(r["res"]))
            r = run_command(
                {
                    "command": "decrypt",
                    "ciphertext": (
                        xor(iv_nb, bytes(14 * [0] + [1] + [0])) + ctxt_b
                    ).hex(),
                }
            )
            if len(r["res"]) == 128:
                print("False positive:", len(r["res"]))
                continue
            # Perform XOR logic natively using integers:
            # p = IV_orig ^ I, where I = i ^ 0x01
            p_int = iv_b[-1] ^ i ^ 1
            last_byte = chr(p_int)

            g = run_command({"command": "guess", "guess": last_byte})
            if j % 1000 == 0:
                print(g)
            break
    # exit()
    # c0;c1;c2;c3
    # d0;d1;d2;d3
    # v0;v1;v2;v3+i
    # p0;p1;p2;p3

print(run_command({"command": "flag"}))
