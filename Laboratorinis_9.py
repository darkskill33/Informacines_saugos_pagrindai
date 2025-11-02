from aes_helpers import *

# --- AES Extra pagalbinės funkcijos ---
def add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]
    return state

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sboxInv[state[i][j]]
    return state

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return state

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

def mix_columns(state):
    for i in range(4):
        a = [state[j][i] for j in range(4)]
        b = [
            mult_2[a[0]] ^ mult_3[a[1]] ^ a[2] ^ a[3],
            a[0] ^ mult_2[a[1]] ^ mult_3[a[2]] ^ a[3],
            a[0] ^ a[1] ^ mult_2[a[2]] ^ mult_3[a[3]],
            mult_3[a[0]] ^ a[1] ^ a[2] ^ mult_2[a[3]],
        ]
        for j in range(4):
            state[j][i] = b[j]
    return state

def inv_mix_columns(state):
    for i in range(4):
        a = [state[j][i] for j in range(4)]
        b = [
            mult_e[a[0]] ^ mult_b[a[1]] ^ mult_d[a[2]] ^ mult_9[a[3]],
            mult_9[a[0]] ^ mult_e[a[1]] ^ mult_b[a[2]] ^ mult_d[a[3]],
            mult_d[a[0]] ^ mult_9[a[1]] ^ mult_e[a[2]] ^ mult_b[a[3]],
            mult_b[a[0]] ^ mult_d[a[1]] ^ mult_9[a[2]] ^ mult_e[a[3]],
        ]
        for j in range(4):
            state[j][i] = b[j]
    return state

def get_round_keys(key_hex):
    key_bytes = bytes.fromhex(key_hex)
    keys = []
    for i in range(0, len(key_bytes), 16):
        key_block = key_bytes[i:i+16]
        key_block_matrix = [
            [key_block[0], key_block[4], key_block[8], key_block[12]],
            [key_block[1], key_block[5], key_block[9], key_block[13]],
            [key_block[2], key_block[6], key_block[10], key_block[14]],
            [key_block[3], key_block[7], key_block[11], key_block[15]],
        ]
        keys.append(key_block_matrix)
    return keys

def aes_encrypt_block(block, round_keys):
    state = [row[:] for row in block]
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 3):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[3])
    return state

def aes_decrypt_block(block, round_keys):
    state = [row[:] for row in block]
    state = add_round_key(state, round_keys[3])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for rnd in range(2, 0, -1):
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state

# --- Main ---
def main():
    with open("variantai.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("4."):
                key = next(f).strip()
                text = next(f).strip()

    print("Key:", key)
    print("Text:", text)

    # Dešifravimas
    round_keys = get_round_keys(key)
    ciphertext_blocks = byte_string_to_blocks(text)
    decrypted_blocks = [aes_decrypt_block(b, round_keys) for b in ciphertext_blocks]
    decrypted_text = blocks_to_string(decrypted_blocks)

    print(f"Atšifruotas tekstas: {decrypted_text}")
    
    # Šifravimas
    name = "Alanas Pauša" 
    plaintext_blocks = string_to_blocks(name)
    encrypted_blocks = [aes_encrypt_block(b, round_keys) for b in plaintext_blocks]
    encrypted_text_hex = blocks_to_byte_string(encrypted_blocks)

    print(f"Užšifruotas vardas ir pavarde: {encrypted_text_hex}")
    print(f"Naudotas raktas: {key}")

if __name__ == "__main__":
    main()
