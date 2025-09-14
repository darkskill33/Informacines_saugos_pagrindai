import re
from collections import Counter
from math import gcd

def friedman_ic(text):
    text = text.replace(" ", "").lower()
    N = len(text)
    freqs = Counter(text)
    ic = sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1)) if N > 1 else 0
    kp = 0.069
    kr = 1 / 32
    if ic - kr == 0:
        return 1
    estimated_length = (kp - kr) / (ic - kr)
    print(f"Friedman IC: {ic:.4f}")
    return round(estimated_length)

# def kasiski_examination(text, min_len=3, max_len=5):
#     text = text.replace(" ", "").lower()
#     seq_spacings = []
#     for seq_len in range(min_len, max_len + 1):
#         seqs = {}
#         for i in range(len(text) - seq_len):
#             seq = text[i:i+seq_len]
#             if seq in seqs:
#                 seqs[seq].append(i)
#             else:
#                 seqs[seq] = [i]
#         for seq, idxs in seqs.items():
#             if len(idxs) > 1:
#                 for j in range(len(idxs)-1):
#                     spacing = idxs[j+1] - idxs[j]
#                     seq_spacings.append(spacing)
   
#     from math import gcd
#     from functools import reduce
    
#     if not seq_spacings:
#         print("No repeated sequences found for Kasiski examination.")
#         return None
#     key_length = reduce(gcd, seq_spacings)
#     # print(f"Kasiski spacings: {seq_spacings}")
#     return key_length

def kasiski_examination(text, min_len=3, max_len=5):
    text = ''.join(c for c in text.lower() if c.isalpha())
    seq_spacings = []

    for seq_len in range(min_len, max_len + 1):
        seq_positions = {}
        for i in range(len(text) - seq_len):
            seq = text[i:i + seq_len]
            if seq in seq_positions:
                seq_positions[seq].append(i)
            else:
                seq_positions[seq] = [i]
        # collect spacings
        for positions in seq_positions.values():
            if len(positions) > 1:
                for j in range(len(positions) - 1):
                    seq_spacings.append(positions[j + 1] - positions[j])

    if not seq_spacings:
        print("No repeated sequences found for Kasiski examination.")
        return None

    # compute all GCDs of spacings
    gcd_counts = Counter()
    for i in range(len(seq_spacings)):
        for j in range(i + 1, len(seq_spacings)):
            d = gcd(seq_spacings[i], seq_spacings[j])
            if d > 1:
                gcd_counts[d] += 1

    if not gcd_counts:
        return None

    most_common_length, _ = gcd_counts.most_common(1)[0]
    print(f"Kasiski candidate key length: {most_common_length}")
    return most_common_length


def split_into_caesars(text, key_length, alphabet):
    cleaned = ''.join(c for c in text.lower() if c in alphabet)
    return [cleaned[i::key_length] for i in range(key_length)]



def caesar_shift(text, shift, alphabet):
    return ''.join(alphabet[(alphabet.index(c) - shift) % len(alphabet)] if c in alphabet else c for c in text)

def find_caesar_shift(group, alphabet):
    frequent_letters = "iasore"
    best_shift = 0
    best_score = -1.0

    group_letters = ''.join(c for c in group if c in alphabet)

    for shift in range(len(alphabet)):
        decrypted = caesar_shift(group_letters, shift, alphabet)
        N = len(decrypted)
        if N == 0:
            continue
        freq_count = sum(decrypted.count(l) for l in frequent_letters)
        score = freq_count / N
        if score > best_score:
            best_score = score
            best_shift = shift

    print(f"Pasirinktas poslinkis {best_shift}, atitikimas dažniui: {best_score*100:.2f}%")
    return best_shift



def shifts_to_key(shifts, alphabet):
    return ''.join(alphabet[shift] for shift in shifts)

def vigenere_cipher(text, password, lower, upper, type):
    encrypted_text = ""
    password_no_spaces = (password * ((len(text.replace(" ", "")) // len(password)) + 1))[:len(text.replace(" ", ""))]
    password_index = 0
    full_password = ""
    for char in text:
        if char == " ":
            encrypted_text += " "
            full_password += " "
        else:
            key_char = password_no_spaces[password_index]
            full_password += key_char
            if char in lower:
                tIndex = lower.index(char)
                pIndex = lower.index(key_char.lower())
                if type == "encrypt":
                    new_index = (tIndex + pIndex) % len(lower)
                else:
                    new_index = (tIndex - pIndex) % len(lower)
                encrypted_text += lower[new_index]
            elif char in upper:
                tIndex = upper.index(char)
                pIndex = upper.index(key_char.upper())
                if type == "encrypt":
                    new_index = (tIndex + pIndex) % len(upper)
                else:
                    new_index = (tIndex - pIndex) % len(upper)
                encrypted_text += upper[new_index]
            else:
                encrypted_text += char
            password_index += 1
    return encrypted_text



def main():
    lower_alphabet = "aąbcčdeęėfghiįyjklmnoprsštuųūvzž"
    upper_alphabet = lower_alphabet.upper()
    
    text_inputs = ["", ""]
    password = ""
    counter = -1
    step = 0
    with open("4.txt", "r", encoding="utf-8") as file:
        for idx, line in enumerate(file):
            line = line.strip() 
            if line.startswith(str(counter+2)+'.'):
                counter += 1
            elif idx == 2:
                password = line.strip()
                print("Password:", password)
            else:    
                text_inputs[counter] += line.strip()
                
    

    print("Decrypted text:", vigenere_cipher(text_inputs[0], password, lower_alphabet, upper_alphabet, "decrypt"))
    print("--------------------------------")
    print("Step 1: Rakto ilgis (Friedman):", friedman_ic(text_inputs[1].lower()))
    print("Step 1: Rakto ilgis (Kasiski):", kasiski_examination(text_inputs[1].lower()))
    #key_length = friedman_ic(text_inputs[1])+1
    key_length = kasiski_examination(text_inputs[1])
    print("Naudojamas rakto ilgis:", key_length)
 
    caesar_groups = split_into_caesars(text_inputs[1].lower(), key_length, lower_alphabet)
    print("Step 2: Cezario šifrai:")
    for i, group in enumerate(caesar_groups):
        print(f"Group {i+1}: {group}")
    
    print("Step 3: Poslinkiai:")
    shifts = []
    for group in caesar_groups:
        shift = find_caesar_shift(group, lower_alphabet)
        shifts.append(shift)
        print(f"Shift for group: {shift}")
  
    key = shifts_to_key(shifts, lower_alphabet)
    print("Step 4: Raktas iš poslinkių:", key)
    
    print("Decrypted with found key:", vigenere_cipher(text_inputs[1].lower(), key, lower_alphabet, upper_alphabet, "decrypt"))
                
if __name__ == "__main__":
    main()


