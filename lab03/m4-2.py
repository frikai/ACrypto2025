import json
import socket
import math
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits
PORT = 50342
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


for j in range(10):
    command_ctxt = run_command({"command": "challenge"})["res"]
    command_ctxt_b = bytes.fromhex(command_ctxt)
    iv_b = command_ctxt_b[:16]
    ctxt_b = command_ctxt_b[16:]
    ptxt_b = bytes([])

    for k in range(16):
        # print(f"Round {k}:", ptxt_b, ptxt_c)
        for i in range(256):
            # new iv is zeroed up until target ptxt byte, then known ptxt bytes xored with the target padding value
            iv_new_b = bytes((15 - k) * [0] + [i]) + xor(
                iv_b[16 - k :], xor(ptxt_b, bytes(k * [k + 1]))
            )
            # print(list(iv_new_b))
            assert len(iv_new_b) == 16
            r = run_command(
                {"command": "decrypt", "ciphertext": (iv_new_b + ctxt_b).hex()}
            )
            # print(len(r["res"]))
            if len(r["res"]) != 128:
                # print("Match:", k, i)
                if k != 15:  # no false positive for first byte of block
                    mask = 16 * [0]
                    mask[14 - k] = 1  # byte before our target
                    check = run_command(
                        {
                            "command": "decrypt",
                            "ciphertext": (
                                # change byte before our target plaintext byte to rule out false positives
                                xor(iv_new_b, bytes(mask))
                                + ctxt_b
                            ).hex(),
                        }
                    )
                    if len(check["res"]) == 128:
                        print("False positive:", len(check["res"]))
                        continue
                # Perform XOR logic natively using integers:
                # p = IV_orig ^ I, where I = i ^ 0x01
                p_int = iv_b[15 - k] ^ i ^ (k + 1)
                new_ptxt_byte = chr(p_int)
                ptxt_b = bytes([p_int]) + ptxt_b
                break
        # print(ptxt_c, len(ptxt_c))
        # print(ptxt_b.decode())
        # exit()

    g = run_command({"command": "guess", "guess": ptxt_b.decode()})
    print(g)

print(run_command({"command": "flag"}))
