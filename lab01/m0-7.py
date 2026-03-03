from Crypto.Random import get_random_bytes


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


ptxt1 = b" REDACTED "
ptxt2 = b"flag{" + ptxt1 + b"}"

key = get_random_bytes(len(ptxt1))

c1 = "9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0"
c2 = "b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4"
c1b = bytes.fromhex(c1)
c2b = bytes.fromhex(c2)
c1x2b = xor(c1b, c2b)
known = bytearray(b"flag{")
p = bytes([])
for i in range(0, len(c1b), len(known)):
    known = xor(c1x2b[i : i + len(known)], known)
    p += known

print(p.decode())
