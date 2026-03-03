x = bytes.fromhex(
    "210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
)
for i in range(256):
    try:
        print(bytes([b ^ i for b in x]).decode())
    except:
        pass
