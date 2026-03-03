from Crypto.Hash import SHA256

x = b"LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs."
x2 = bytearray([x[i] for i in range(15, len(x), 16)])
print(SHA256.new(data=x2).hexdigest())
