import json
import socket

PORT = 50200
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


file_path = "lab02/aes.data"

try:
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            # .strip() removes trailing newlines (\n) and whitespace
            l = line.strip()
            lbs = [l[i : i + 32] for i in range(0, len(l), 32)]
            s = set(lbs)
            if len(s) < len(lbs):
                print(l)


except FileNotFoundError:
    print(f"Error: The file {file_path} was not found.")

# print(run_command({"command": "flag", "token": "534554454320415354524f4e4f4d59"}))
