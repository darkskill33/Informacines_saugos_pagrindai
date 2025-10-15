import secrets, math
from pagalbines_funkcijos import *

# Miller-Rabin pirminio skaičiaus testas
def is_probable_prime(n, k=10):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    s = 0
    d = n-1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = (x*x) % n
            if x == n-1:
                break
        else:
            return False
    return True

# Funkcija, generuojanti atsitiktinį pirminį su tuo pačiu bitų skaičiumi
def generate_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p):
            return p

# Išplėstas Euklido algoritmas, kuris randa didžiausią bendrą daliklį (gcd) tarp dviejų skaičių ir Bezout tapatybes koeficientus
def egcd(a,b):
    if b==0:
        return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a,m):
    g,x,y = egcd(a,m)
    if g != 1:
        raise Exception("modinv does not exist")
    return x % m

# Ši funkcija suranda ⌊n-tąją šaknį⌋ iš didelio skaičiaus x, net jei x turi šimtus bitų
def integer_nth_root(x, n):
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0, True
    lo = 0
    hi = 1 << ((x.bit_length() + n - 1)//n)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = pow(mid, n)
        if p == x:
            return mid, True
        if p < x:
            lo = mid
        else:
            hi = mid
    return lo, (pow(lo,n) == x)

# Pollard's Rho faktorizacijos algoritmas
def pollards_rho(n):
    if n%2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        x = secrets.randbelow(n-2) + 2
        y = x
        c = secrets.randbelow(n-1) + 1
        d = 1
        while d == 1:
            x = (x*x + c) % n
            y = (y*y + c) % n
            y = (y*y + c) % n
            d = math.gcd(abs(x-y), n)
            if d == n:
                break
        if d > 1 and d < n:
            return d

def factor(n):
    if n == 1:
        return []
    if is_probable_prime(n):
        return [n]
    d = pollards_rho(n)
    if d == n:
        for i in range(2, 1000000):
            if n % i == 0:
                d = i
                break
    factors = factor(d) + factor(n//d)
    return sorted(factors)

def task1_2(e1, name, bits=256):
    # generuojame p ir q 256-bitų pirminius su sąlyga, kad gcd(e,phi)=1
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue
        phi = (p-1)*(q-1)
        if math.gcd(e1, phi) == 1:
            break
    n1 = p * q
    d1 = modinv(e1, phi)
    
    m_name = string_to_int(name)
    c1 = pow(m_name, e1, n1)
    print(f"1. Atsakymas:\n 1) p = {p} \n 2) q = {q} \n 3) (e, n) = {(e1, n1)} \n 4) (d, n) = {(d1, n1)} \n")
    print(f"2. Šifras: {c1}\n")


def task3(e, pk, c):
    m_root, exact3 = integer_nth_root(c, 3)
    m = m_root
    try:
        decrypted3 = int_to_string(m)
    except Exception:
        decrypted3 = int_to_bytes(m).hex()
    print(f"3. Atsakymas: {decrypted3}\n")
    
def task4(e, pk, c):
    # Bandome paprastą faktorizavimo (skaidymo į pirminius daliklius) metodą
    factor_found = None
    for small in [2,3,5,7,11,13,17,19,23,29]:
        if pk % small == 0:
            factor_found = small
            break
    if factor_found is None:
        factor_found = pollards_rho(pk)
    p = factor_found
    q = pk // p
    if p > q:
        p, q = q, p
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    m = pow(c, d, pk)
    try:
        decrypted = int_to_string(m)
    except Exception:
        decrypted = int_to_bytes(m).hex()
    print(f"4. Atsakymas: {decrypted}\n")
        
def task5(vk, d, c):
    k = (vk.bit_length() + 7) // 8
    m = pow(c, d, vk)
    m_bytes = m.to_bytes(k, 'big')

    # Jei netyčia praleido leading zero, pridedame jį rankiniu būdu.
    # Dažniausiai tai nutinka dėl trūkstamo „leading zero“, 
    # kai int_to_bytes(m) arba m.to_bytes() su neteisingu ilgiu
    # k grąžina 1 baitu trumpesnį masyvą, todėl 0x00 (pirmas nulinis baitas) „nukrenta“.
    if m_bytes[0] != 0:
        m_bytes = b'\x00' + m_bytes

    decrypted = None
    if len(m_bytes) >= 2 and m_bytes[0] == 0 and m_bytes[1] == 2:
        try:
            sep_index = m_bytes.index(b'\x00', 2)
            message_bytes = m_bytes[sep_index+1:]
            try:
                decrypted = message_bytes.decode('utf-8')
            except UnicodeDecodeError:
                decrypted = message_bytes.hex()
        except ValueError:
            decrypted = "<no 0x00 separator found>"
    else:
        decrypted = "<invalid PKCS#1 v1.5 block header>"

    print(f"5. Atsakymas: {decrypted}\n")
    return decrypted


def main():   
    e = 0 
    pk1 = ""
    e1 = ""
    pk2 = ""
    e2 = ""
    vk1 = ""
    d1 = ""
    c1 = 0
    c2 = 0
    c3 = 0
    with open("4.txt", "r", encoding="utf-8") as f:
        counter = 0
        k = 0
        for line in f:
            line = line.strip()
            if(line.startswith("1.")):
                counter += 1
                continue
            elif(line.startswith("3.")):
                counter += 2
                continue
            elif(line.startswith("4.")):
                counter += 1
                continue
            elif(line.startswith("5.")):
                counter += 1
                continue
                
            print(counter)
            
            if(counter==1):
                e = int(line.strip())
            elif(counter==3):
                if(k==0):
                    pk1 = int(line.strip().split(" ")[1])
                    e1 = int(line.strip().split(" ")[0])
                    k+=1
                else:
                    c1 = int(line.strip())
                    k = 0
            elif(counter==4):
                if(k==0):
                    pk2 = int(line.strip().split(" ")[1])
                    e2 = int(line.strip().split(" ")[0])
                    k=+1
                else:
                    c2 = int(line.strip())
                    k=0
            elif(counter==5):
                if(k==0):
                    vk1 = int(line.strip().split(" ")[1])
                    d1 = int(line.strip().split(" ")[0])
                    print(f"vk1: {vk1}, d1: {d1}")
                    k=+1
                else:
                    c3 = int(line.strip())
                    k=0
                
    print("- Laboratorinis darbas 6 -")
    task1_2(e, "Alanas Pauša")
    task3(e1, pk1, c1)
    task4(e2, pk2, c2)
    task5(vk1, d1, c3)
             
if __name__ == "__main__":
    main()