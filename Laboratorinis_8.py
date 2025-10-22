def diffieHellman(g, p, a, b):
    A = pow(g, a, p)
    B = pow(g, b, p)
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    print("A:", A)
    print("B:", B)
    print("s1:", s1)
    print("s2:", s2)
    #return A, B, s1, s2
    
def babyStepGiantStep(g, p, x):
    from math import isqrt, ceil

    m = isqrt(p-1)
    table = {}
    
    # Baby step
    current = 1
    for j in range(m):
        table[current] = j
        current = (current * g) % p
    
    # Giant step
    g_m_inv = pow(g, p - m - 1, p)  # g^(-m) mod p
    current = x
    for i in range(m):
        if current in table:
            return i * m + table[current]
        current = (current * g_m_inv) % p
    
    return None

def generateHundredBitPrime(g):
    from sympy import isprime
    from random import getrandbits
    while True:
        q = getrandbits(99) | 1  # 99 bitų, nelyginis
        if not isprime(q):
            continue
        p = 2*q + 1
        if not isprime(p):
            continue
       # Patikriname, ar g=2 tinka generatoriui safe prime
        #    t.y. g^2 != 1 mod p ir g^q != 1 mod p
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return p



def main():   
    
    g1, p1, a1, b1 = 3, 13828935509176857547, 4242798754577874607, 1389856269650684353
    g2, p2, x2 = 5, 812691773477, 320595035733
    g3 = 2
    
    diffieHellman(g1, p1, a1, b1)
    print("a:", babyStepGiantStep(g2, p2, x2))
    print("Generated 100-bit prime:", generateHundredBitPrime(g3))
                   
             
if __name__ == "__main__":
    main()