import secrets, math
import hashlib, time
from pagalbines_funkcijos import *


def createFingerprint(e, n, d, name, output_file, answers_file="atsakymai.txt"):
    # Atspausdiname sertifikato turinį (Vardas Pavardė, Viešojo rakto n, Viešojo rakto e);
    main_content = "1. " + name + "\n2. " + str(n) + "\n3. " + str(e) + "\n"
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(main_content)
    
    # 2. Apskaičiuojame SHA256 piršto antspaudą
    digest_hex = hashlib.sha256(open(output_file, "rb").read()).hexdigest()
    print(f"Piršto antspaudas patikrinimui (SHA256): {digest_hex}\n") # Sutampa su https://md5file.com/calculator
    
    digest = hashlib.sha256(open(output_file, "rb").read()).digest()
    digest_int = bytes_to_int(digest)
    # 3. Pasirašome piršto antspaudą savo privačiuoju raktu
    signature = pow(digest_int, d, n)
    
    # 4. Sukuriame laiko žymą
    ts10 = int(time.time())
    ts16 = ts10.to_bytes(8, 'big')
    
    # 5. Prie sertifikato pridedame pasirašytą piršto antspaudą ir laiko žymą
    combined_hash = hashlib.sha256(open(output_file, "rb").read() + ts16).digest()
    combined_hash_int = bytes_to_int(combined_hash)
    combined_hash_hex = combined_hash.hex()
    print(f"Kombinuotas piršto antspaudas su laiko žyma (SHA256): {combined_hash_hex}\n")
    
    # 6. Pasirašome kombinuotą hash
    signature2 = pow(combined_hash_int, d, n)
    
     # 7. Įrašome visus rezultatus į atsakymai.txt
    with open(answers_file, "w", encoding="utf-8") as f:
        f.write("Atsakymai:\n")
        f.write(f"Sertifikato piršto antspaudas (SHA256): {digest_hex}\n")
        f.write(f"Piršto antspaudo parašas (dešimtainis): {signature}\n")
        f.write(f"Laiko žyma (ts10): {ts10}\n")
        f.write(f"Sertifikato ir laiko žymos piršto antspaudas (SHA256): {combined_hash_hex}\n")
        f.write(f"Sertifikato ir laiko žymos piršto antspaudo parašas (dešimtainis): {signature2}\n")
    
    

def main():   

    name = "Alanas Pauša"
    (e, n) = (64187, 10264596522195264193101292602500842237088665262478841942337212900576996965832267894330927735603173415943949382272828363164013800580943578693594284145018409)
    d = 5653228093790405915377316197843913470380628564879018204676380158728362748518069424777312188456040631736083677636256721343874730755644711023412330190331223
    
    output_file = "sertifikatas.txt"
    answers_file = "atsakymai.txt"
    createFingerprint(e, n, d, name, output_file, answers_file)
             
if __name__ == "__main__":
    main()