import hashlib
import base64

i = 0

with open("hashes.txt", "w") as output_file:
    while True:
        i += 1
        number = str(i)

        md5_hash = hashlib.md5()
        md5_hash.update(number.encode('utf-8'))
        md5_hex = md5_hash.hexdigest()

        sha1_hash = hashlib.sha1()
        sha1_hash.update(number.encode('utf-8'))
        sha1_hex = sha1_hash.hexdigest()

        sha224_hash = hashlib.sha224()
        sha224_hash.update(number.encode('utf-8'))
        sha224_hex = sha224_hash.hexdigest()

        sha256_hash = hashlib.sha256()
        sha256_hash.update(number.encode('utf-8'))
        sha256_hex = sha256_hash.hexdigest()

        sha384_hash = hashlib.sha384()
        sha384_hash.update(number.encode('utf-8'))
        sha384_hex = sha384_hash.hexdigest()

        sha512_hash = hashlib.sha512()
        sha512_hash.update(number.encode('utf-8'))
        sha512_hex = sha512_hash.hexdigest()

        sha3_256_hash = hashlib.sha3_256()
        sha3_256_hash.update(number.encode('utf-8'))
        sha3_256_hex = sha3_256_hash.hexdigest()

        sha3_512_hash = hashlib.sha3_512()
        sha3_512_hash.update(number.encode('utf-8'))
        sha3_512_hex = sha3_512_hash.hexdigest()

        blake2b_hash = hashlib.blake2b()
        blake2b_hash.update(number.encode('utf-8'))
        blake2b_hex = blake2b_hash.hexdigest()

        blake2s_hash = hashlib.blake2s()
        blake2s_hash.update(number.encode('utf-8'))
        blake2s_hex = blake2s_hash.hexdigest()

        base64_encoded = base64.b64encode(number.encode('utf-8')).decode('utf-8')
        base32_encoded = base64.b32encode(number.encode('utf-8')).decode('utf-8')
        base85_encoded = base64.b85encode(number.encode('utf-8')).decode('utf-8')

        pbkdf2_sha256 = hashlib.pbkdf2_hmac('sha256', number.encode('utf-8'), b'salt', 100000)
        pbkdf2_sha256_hex = pbkdf2_sha256.hex()

        try:
            import hashlib
            whirlpool_hash = hashlib.new('whirlpool')
            whirlpool_hash.update(number.encode('utf-8'))
            whirlpool_hex = whirlpool_hash.hexdigest()
        except Exception:
            whirlpool_hex = "Not Supported"

        output_file.write(f"{number}: MD5={md5_hex}, SHA-1={sha1_hex}, SHA-224={sha224_hex}, "
                          f"SHA-256={sha256_hex}, SHA-384={sha384_hex}, SHA-512={sha512_hex}, "
                          f"SHA3-256={sha3_256_hex}, SHA3-512={sha3_512_hex}, BLAKE2b={blake2b_hex}, "
                          f"BLAKE2s={blake2s_hex}, Base64={base64_encoded}, Base32={base32_encoded}, "
                          f"Base85={base85_encoded}, PBKDF2-SHA256={pbkdf2_sha256_hex}, Whirlpool={whirlpool_hex}\n\n\n")

print("Hashes and encodings generated and written to hashes.txt")
