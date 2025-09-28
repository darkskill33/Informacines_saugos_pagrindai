import hashlib      # MD5, SHA-256, scrypt
import bcrypt       # bcrypt
from argon2 import PasswordHasher  # argon2-cffi
from collections import Counter
from math import gcd

def search_hashes(MD5_inputs, SHA_inputs, bcrypt_inputs, scrypt_inputs, argon2_inputs):
    # MD5 and SHA-256 (with salt)
    with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as f:
        print("Starting MD5 and SHA-256 password search...")
        for password in f:
            password = password.strip()
            # MD5
            if MD5_inputs[1]:  # salt exists
                md5_hash = hashlib.md5((password + MD5_inputs[1]).encode()).hexdigest()
            else:
                md5_hash = hashlib.md5(password.encode()).hexdigest()
            if md5_hash == MD5_inputs[0]:
                print(f"MD5 match: {password}")
            # SHA-256
            if SHA_inputs[1]:  # salt exists
                sha256_hash = hashlib.sha256((password + SHA_inputs[1]).encode()).hexdigest()
            else:
                sha256_hash = hashlib.sha256(password.encode()).hexdigest()
            if sha256_hash == SHA_inputs[0]:
                print(f"SHA-256 match: {password}")

    # bcrypt, scrypt, argon2
    with open("rockyou_1000.txt", "r", encoding="utf-8", errors="ignore") as f:
        print("Starting bcrypt, scrypt, and argon2 password search...")
        for password in f:
            password = password.strip()
            # bcrypt
            if bcrypt_inputs[0]:
                try:
                    if bcrypt.checkpw(password.encode(), bcrypt_inputs[0].encode()):
                        print(f"bcrypt match: {password}")
                except Exception:
                    pass
            # scrypt
            if scrypt_inputs[0] and scrypt_inputs[1]:
                try:
                    scrypt_hash = hashlib.scrypt(password.encode(), salt=scrypt_inputs[1].encode(), n=2**16, r=2, p=1).hex()
                    if scrypt_hash == scrypt_inputs[0]:
                        print(f"scrypt match: {password}")
                except Exception:
                    pass
            # argon2
            if argon2_inputs[0]:
                ph = PasswordHasher()
                try:
                    if ph.verify(argon2_inputs[0], password):
                        print(f"argon2 match: {password}")
                except Exception:
                    pass
                
                
def main():    
    MD5_inputs = ["", ""]
    SHA_inputs = ["", ""]
    bcrypt_inputs = [""]
    scrypt_inputs = ["", ""]
    argon2_inputs = [""]
    with open("4.txt", "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line.startswith("MD5"):
                Split_Array = line.strip().replace("MD5", "").split(",")
                MD5_inputs[0] = Split_Array[0].strip()
                MD5_inputs[1] = Split_Array[1].strip()
                continue
            elif line.startswith("SHA-256"):
                Split_Array = line.strip().replace("SHA-256", "").split(",")
                SHA_inputs[0] = Split_Array[0].strip()
                SHA_inputs[1] = Split_Array[1].strip()
                continue
            elif line.startswith("bcrypt"):
                bcrypt_inputs[0] = line.strip().replace("bcrypt", "").strip()
                continue
            elif line.startswith("scrypt"):
                Split_Array = line.strip().replace("scrypt", "").split(",")
                scrypt_inputs[0] = Split_Array[0].strip()
                scrypt_inputs[1] = Split_Array[1].strip()
                continue
            elif line.startswith("argon2"):
                line_test = line.strip().replace("argon2", "",1)
                print(line_test)
                argon2_inputs[0] = line_test.strip()
                continue
            else:
                continue
            
    search_hashes(MD5_inputs, SHA_inputs, bcrypt_inputs, scrypt_inputs, argon2_inputs)               
             
if __name__ == "__main__":
    main()


