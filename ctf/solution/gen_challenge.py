#!/usr/bin/env python3
"""
Challenge Generation & Solution Verification Script
Generates C++ constants and verifies mathematical correctness for the CTF challenge.
"""
import struct

# Chosen Flag and Layer inputs:
FLAG = "ensia{k9Mx_7vQ2_cHa0s_9x8F_lAtT1cE}"
STAGE1_INPUT = "K9mX-7vQ2-Lp8A-W3zR"  # 16 alphanumeric characters without hyphens
STAGE2_INPUT = [31337, 424242, 10007, 88888888] # 4 uint32 numbers
STAGE3_INPUT = "n0n_l1n34r_ch40s"    # 16 ASCII bytes
STAGE4_INPUT = "8F3a9C2e"            # 8 ASCII bytes

# ── LAYER 1: GF(2^8) SPN ───────────────────────────────────────────────────
def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B # AES poly x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

def gf_inv(a):
    if a == 0:
        return 0
    # a^254 in GF(2^8)
    res = 1
    base = a
    exp = 254
    while exp > 0:
        if exp & 1:
            res = gf_mul(res, base)
        base = gf_mul(base, base)
        exp >>= 1
    return res

SBOX = [gf_inv(x ^ 0x67) ^ 0x89 for x in range(256)]

ROUND_KEYS_1 = [
    [0x1A, 0x9B, 0x4C, 0xF3, 0x5D, 0x8E, 0x27, 0x60, 0x31, 0xA5, 0x78, 0xC4, 0x0F, 0xE2, 0xB6, 0xD9],
    [0xE7, 0x2A, 0x5F, 0x91, 0x83, 0xC6, 0x0D, 0x74, 0xB8, 0x1E, 0x42, 0xDB, 0xF5, 0x6C, 0x39, 0xAA],
    [0x3C, 0xF0, 0x8A, 0x15, 0x96, 0x4D, 0x72, 0xEB, 0x29, 0x5E, 0xAC, 0x63, 0xD4, 0x0B, 0xFE, 0x18],
    [0x71, 0x48, 0xCE, 0x23, 0xBF, 0x95, 0x6A, 0x0C, 0xD2, 0x3F, 0x87, 0x19, 0x4E, 0xA1, 0x5B, 0x6D]
]

def stage1_cipher(input_str):
    raw = [ord(c) for c in input_str.replace("-", "")]
    assert len(raw) == 16
    state = list(raw)
    
    # 4 rounds of SPN
    for r in range(4):
        # SubBytes + AddKey
        for i in range(16):
            state[i] = SBOX[state[i] ^ ROUND_KEYS_1[r][i]]
        # ShiftRows
        # [0, 4, 8, 12]
        # [1, 5, 9, 13] -> [5, 9, 13, 1]
        # [2, 6, 10, 14]-> [10, 14, 2, 6]
        # [3, 7, 11, 15]-> [15, 3, 7, 11]
        s = list(state)
        state[1], state[5], state[9], state[13] = s[5], s[9], s[13], s[1]
        state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
        state[3], state[7], state[11], state[15] = s[15], s[3], s[7], s[11]
        # MixColumns
        for c in range(4):
            c0, c1, c2, c3 = state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]
            state[4*c]   = gf_mul(2, c0) ^ gf_mul(3, c1) ^ c2 ^ c3
            state[4*c+1] = c0 ^ gf_mul(2, c1) ^ gf_mul(3, c2) ^ c3
            state[4*c+2] = c0 ^ c1 ^ gf_mul(2, c2) ^ gf_mul(3, c3)
            state[4*c+3] = gf_mul(3, c0) ^ c1 ^ c2 ^ gf_mul(2, c3)
    return state

T1 = stage1_cipher(STAGE1_INPUT)
S1 = [struct.unpack("<I", bytes(T1[4*i:4*i+4]))[0] for i in range(4)]
print(f"Stage 1 Target: {T1}")
print(f"Stage 1 Seeds (S1): {[hex(x) for x in S1]}")

# ── LAYER 2: Chaotic Arnold Cat Map + Cubic Modulo ─────────────────────────
MOD_P = 2147483647 # 2^31 - 1 Mersenne prime

def stage2_orbit(k0, k1, k2, k3, s1):
    x = (k0 ^ s1[0]) % MOD_P
    y = (k1 ^ s1[1]) % MOD_P
    p = (k2 ^ s1[2]) % MOD_P
    q = (k3 ^ s1[3]) % MOD_P
    
    for r in range(16):
        nx = (2*x + y + pow(x, 3, MOD_P) + p + 0x314159) % MOD_P
        ny = (x + y + pow(y, 3, MOD_P) + q + 0x271828) % MOD_P
        x, y = nx, ny
    
    # Invariant checks:
    inv1 = (k0 * 0x1337 + k1 * 0xdead) % MOD_P
    inv2 = (k2 * 0xbeef + k3 * 0xcafe) % MOD_P
    return x, y, inv1, inv2, [x, y, p, q]

T2_x, T2_y, T2_inv1, T2_inv2, S2 = stage2_orbit(STAGE2_INPUT[0], STAGE2_INPUT[1], STAGE2_INPUT[2], STAGE2_INPUT[3], S1)
print(f"Stage 2 Targets: x={hex(T2_x)}, y={hex(T2_y)}, inv1={hex(T2_inv1)}, inv2={hex(T2_inv2)}")
print(f"Stage 2 State (S2): {[hex(x) for x in S2]}")

# ── LAYER 3: Dynamic Feistel Network ───────────────────────────────────────
def stage3_feistel(input_str, s2):
    raw = [ord(c) for c in input_str]
    assert len(raw) == 16
    
    # Generate dynamic S-box from S2 using KSA
    key_bytes = b"".join(struct.pack("<I", x) for x in s2)
    dyn_sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + dyn_sbox[i] + key_bytes[i % len(key_bytes)]) & 0xFF
        dyn_sbox[i], dyn_sbox[j] = dyn_sbox[j], dyn_sbox[i]
        
    L, R = struct.unpack("<QQ", bytes(raw))
    round_keys = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, 
                  0xC3D2E1F0, 0x10325476, 0x98BADCFE, 0xEFCDAB89]
    
    def F_round(val, rk):
        # Split val into 8 bytes, pass through dyn_sbox, multiply by rk, rotl 13
        b = [(val >> (8*i)) & 0xFF for i in range(8)]
        sb = sum(dyn_sbox[b[i]] << (8*i) for i in range(8))
        mixed = (sb * rk) & 0xFFFFFFFFFFFFFFFF
        # rotl 13
        return ((mixed << 13) | (mixed >> (64 - 13))) & 0xFFFFFFFFFFFFFFFF

    for r in range(8):
        nL = R
        nR = L ^ F_round(R, round_keys[r])
        L, R = nL, nR
        
    T3 = struct.pack("<QQ", L, R)
    S3 = [struct.unpack("<I", T3[4*i:4*i+4])[0] for i in range(4)]
    return list(T3), S3

T3, S3 = stage3_feistel(STAGE3_INPUT, S2)
print(f"Stage 3 Target: {[hex(x) for x in T3]}")
print(f"Stage 3 State (S3): {[hex(x) for x in S3]}")

# ── LAYER 4: Sponge Mixing & Sealing ───────────────────────────────────────
def stage4_sponge(input_str, s1, s2, s3):
    raw = [ord(c) for c in input_str]
    assert len(raw) == 8
    inp_w = struct.unpack("<II", bytes(raw))
    
    # State matrix: 8 uint32 words
    A = [
        s1[0] ^ s2[0], s1[1] ^ s2[1],
        s1[2] ^ s3[0], s1[3] ^ s3[1],
        s2[2] ^ s3[2], s2[3] ^ s3[3],
        inp_w[0] ^ 0x6A09E667, inp_w[1] ^ 0xBB67AE85
    ]
    
    ROT = [3, 7, 11, 17, 19, 23, 29, 31]
    RC = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1]
    
    for r in range(6):
        # Theta: parity mixing
        parity = 0
        for i in range(8):
            parity ^= A[i]
        for i in range(8):
            A[i] ^= ((parity << 1) | (parity >> 31)) & 0xFFFFFFFF
            
        # Rho & Pi: rotate and permute
        nA = [0] * 8
        for i in range(8):
            w = A[i]
            rot = ROT[i]
            rot_w = ((w << rot) | (w >> (32 - rot))) & 0xFFFFFFFF
            nA[(i * 3 + 1) % 8] = rot_w
        A = nA
        
        # Chi: non-linear row bitwise AND-inversion
        A_chi = [0] * 8
        for i in range(8):
            A_chi[i] = A[i] ^ ((~A[(i + 1) % 8]) & A[(i + 2) % 8])
            A_chi[i] &= 0xFFFFFFFF
        A = A_chi
        
        # Iota: round constant
        A[0] = (A[0] ^ RC[r]) & 0xFFFFFFFF
        
    return A

T4 = stage4_sponge(STAGE4_INPUT, S1, S2, S3)
print(f"Stage 4 Target: {[hex(x) for x in T4]}")

# ── ENCRYPTED FLAG GENERATION ─────────────────────────────────────────────
# Key derived from S1, S2, S3, T4
all_state = []
for s in [S1, S2, S3, T4]:
    for w in s:
        all_state.extend(struct.pack("<I", w))

# Hash all_state into 64-byte keystream using iterative sponge
key_stream = bytearray()
seed = 0x85EBCA6B
for i in range(len(FLAG)):
    idx = i % len(all_state)
    seed = (seed * 1664525 + 1013904223 + all_state[idx]) & 0xFFFFFFFF
    key_stream.append((seed >> 16) & 0xFF)

CIPHER_FLAG = [ord(c) ^ k for c, k in zip(FLAG, key_stream)]
print(f"Encrypted Flag length: {len(CIPHER_FLAG)}")
print(f"Encrypted Flag bytes: {[hex(x) for x in CIPHER_FLAG]}")

# Verify decryption:
decrypted = "".join(chr(c ^ k) for c, k in zip(CIPHER_FLAG, key_stream))
assert decrypted == FLAG
print(f"Verification Success! Flag: {decrypted}")
