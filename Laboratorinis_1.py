def main():
    lower_alphabet = "aąbcčdeęėfghiįyjklmnoprsštuųūvzž"
    upper_alphabet = lower_alphabet.upper()
    
    variantas = 4
    text_inputs = ["", ""]
    counter = 0
    step = 0
    with open("variantai.txt", "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip() 
            if line.startswith(str(variantas)+'.'):
                text_inputs[counter] = line.replace(str(variantas)+'.', '').strip()
                if counter == 0:
                    step = int(line[-2:])
                    text_inputs[counter] = text_inputs[counter][:-2].strip()
                counter += 1
                
    encrypted_text = cesars_cipher(text_inputs[0], step, lower_alphabet, upper_alphabet)
    print("Original text:", text_inputs[0])
    print("Encrypted text:", encrypted_text)
    print("Decrypted text1:", cesars_cipher(encrypted_text, -step, lower_alphabet, upper_alphabet))

        
    print("Original text:", text_inputs[1])
    print("Decrypted text:", cesars_cipher(text_inputs[1], -31, lower_alphabet, upper_alphabet))
    # text = "kad, bet, čia, tai, iki, yra, net, tik"
    # for step in range(1, len(alphabet)):
    #     decrypted_attempt = cesars_cipher(text, step, alphabet)
    #     print(f"Step {step}: {decrypted_attempt}")
    #     #text = "kad, bet, čia, tai, iki, yra, net, tik"
    #     #Step 31: jžč, ądš, chž, šžh, hjh, įpž, mdš, šhj

def cesars_cipher(text, step, lower, upper):
    encrypted_text = ""
    for char in text:
        if char in lower:
            index = lower.index(char)
            new_index = (index + step) % (len(lower))
            encrypted_text += lower[new_index]
        elif char in upper:
            index = upper.index(char)
            new_index = (index + step) % (len(upper))
            encrypted_text += upper[new_index]
        else:
            encrypted_text += char
    return encrypted_text    
                
if __name__ == "__main__":
    main()
                
                
    