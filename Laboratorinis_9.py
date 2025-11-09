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

def decrypt_ecb(ciphertext_blocks, round_keys):
    decrypted_blocks = []
    for block in ciphertext_blocks:
        decrypted_block = aes_decrypt_block(block, round_keys)
        decrypted_blocks.append(decrypted_block)
    return blocks_to_string(decrypted_blocks)


def decrypt_cbc(ciphertext_blocks, round_keys, iv_block):
    decrypted_blocks = []
    previous_block = iv_block
    for block in ciphertext_blocks:
        decrypted_block = aes_decrypt_block(block, round_keys)
        # XOR su ankstesniu šifro bloku arba IV
        decrypted_block = [[decrypted_block[i][j] ^ previous_block[i][j] for j in range(4)] for i in range(4)]
        decrypted_blocks.append(decrypted_block)
        previous_block = block  # kitam ciklui
    return blocks_to_string(decrypted_blocks)


def decrypt_pcbc(ciphertext_blocks, round_keys, iv_block):
    decrypted_blocks = []
    previous_cipher = iv_block
    previous_plain = [[0]*4 for _ in range(4)]
    for block in ciphertext_blocks:
        decrypted_block = aes_decrypt_block(block, round_keys)
        # PCBC formulė: P_i = D(C_i) XOR C_{i-1} XOR P_{i-1}
        decrypted_block = [[decrypted_block[i][j] ^ previous_cipher[i][j] ^ previous_plain[i][j] for j in range(4)] for i in range(4)]
        decrypted_blocks.append(decrypted_block)
        previous_plain = decrypted_block
        previous_cipher = block
    return blocks_to_string(decrypted_blocks)


def decrypt_cfb(ciphertext_blocks, round_keys, iv_block):
    decrypted_blocks = []
    feedback_block = iv_block
    for block in ciphertext_blocks:
        encrypted_iv = aes_encrypt_block(feedback_block, round_keys)
        decrypted_block = [[block[i][j] ^ encrypted_iv[i][j] for j in range(4)] for i in range(4)]
        decrypted_blocks.append(decrypted_block)
        feedback_block = block
    return blocks_to_string(decrypted_blocks)


def decrypt_ofb(ciphertext_blocks, round_keys, iv_block):
    decrypted_blocks = []
    output_block = iv_block
    for block in ciphertext_blocks:
        output_block = aes_encrypt_block(output_block, round_keys)
        decrypted_block = [[block[i][j] ^ output_block[i][j] for j in range(4)] for i in range(4)]
        decrypted_blocks.append(decrypted_block)
    return blocks_to_string(decrypted_blocks)

def main():
    with open("4.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("key"):
                key = line.replace("key = ", "").strip()
                iv = next(f).strip().replace("iv = ", "").strip()
            elif line.startswith("1."):
                aes_ECB = next(f).strip()
            elif line.startswith("2."):
                aes_CBC = next(f).strip()
            elif line.startswith("3."):
                aes_PCBC = next(f).strip()
            elif line.startswith("4."):
                aes_CFB = next(f).strip()
            elif line.startswith("5."):
                aes_OFB = next(f).strip()

    print("Key:", key)
    print("iv:", iv)
    print("AES ECB:", aes_ECB)
    print("AES CBC:", aes_CBC)
    print("AES PCBC:", aes_PCBC)
    print("AES CFB:", aes_CFB)
    print("AES OFB:", aes_OFB)      
    
    ecb_blocks = byte_string_to_blocks(aes_ECB)
    cbc_blocks = byte_string_to_blocks(aes_CBC)
    pcbc_blocks = byte_string_to_blocks(aes_PCBC)
    cfb_blocks = byte_string_to_blocks(aes_CFB)
    ofb_blocks = byte_string_to_blocks(aes_OFB)
    
    iv_block = byte_string_to_blocks(iv)[0]
    round_keys = get_round_keys(key)
    # Dešifravimas
    print("AES-ECB atviras tekstas:", decrypt_ecb(ecb_blocks, round_keys))
    print("AES-CBC atviras tekstas:", decrypt_cbc(cbc_blocks, round_keys, iv_block))
    print("AES-PCBC atviras tekstas:", decrypt_pcbc(pcbc_blocks, round_keys, iv_block))
    print("AES-CFB atviras tekstas:", decrypt_cfb(cfb_blocks, round_keys, iv_block))
    print("AES-OFB atviras tekstas:", decrypt_ofb(ofb_blocks, round_keys, iv_block))

if __name__ == "__main__":
    main()
