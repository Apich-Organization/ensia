# Ensia Obfuscator: Comprehensive Reverse Engineering & Security Benchmark Report

**Date**: 2026-08-18 16:13:19
**Evaluated Cryptographic Targets**: 79
**Evaluation Toolchain**: Angr 9.3 + Z3 SMT Solver + LLVM 22.1 Engine

## 1. Executive Summary & Macro Metrics

| Metric | Average Value across All Targets | Key Impact on Reverse Engineering |
| :--- | :---: | :--- |
| **Binary Code Expansion** | **13.49x** | Eliminates code signatures & increases disassembler memory overhead |
| **Basic Block (BB) Multiplier** | **10.06x** | Shatters basic block control flow & complicates AST recovery |
| **CFG Edge Transition Explosion** | **9.30x** | Massive state-transition graph defeats linear control-flow reconstruction |
| **Cyclomatic Complexity Expansion** | **7.95x** | Extreme complexity score breaks automatic decompilers |
| **SMT Invariant Solving Slowdown** | **1347.60x** | Multi-layer MBA & Feistel expansion severely bogs down Z3 queries |
| **Symbolic Execution Timeout Rate** | **76/79 (96.2%)** vs Baseline (43/79) | Automated symbolic solvers get trapped in chaos state machines |

---

## 2. Category Breakdown

| Cryptographic Category | Count | Avg Size Exp | Avg BB Exp | Avg Edge Exp | Avg Cyclomatic Exp | SMT Slowdown |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Asymmetric / PKC** | 9 | 22.89x | 11.17x | 7.86x | 8.91x | 3057.43x |
| **Block Cipher** | 31 | 12.34x | 10.25x | 9.48x | 8.67x | 7.12x |
| **Hash / Digest** | 24 | 12.83x | 10.44x | 10.41x | 7.28x | 15.75x |
| **KDF / Password** | 2 | 13.71x | 8.77x | 8.37x | 5.83x | 6054.23x |
| **Lightweight / AEAD** | 3 | 11.05x | 5.22x | 7.08x | 6.25x | 7674.96x |
| **MAC / Authenticator** | 3 | 11.52x | 10.51x | 8.79x | 9.06x | 4466.31x |
| **Post-Quantum (PQC)** | 2 | 1.42x | 9.25x | 2.54x | 5.50x | 8769.00x |
| **Stream Cipher** | 5 | 14.19x | 8.62x | 10.15x | 7.14x | 2454.90x |

---

## 3. Full 79-Target Comparative Benchmark Data

| Target Algorithm | Domain | Baseline Size | Max Size (Exp) | Main BBs (Exp) | Total Edges (Exp) | Cyclomatic (Exp) | SMT Branch Cost | Symbolic Status (Base vs Max) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `aes128_ecb` | Block Cipher | 34,576 B | 270,872 B (7.83x) | 18 → 180 (10.0x) | 196 → 1561 (7.96x) | 8 → 52 (6.5x) | 0.2784s → 1.9518s (7.01x) | TIMEOUT / **TIMEOUT** |
| `aes192_ecb` | Block Cipher | 30,296 B | 274,960 B (9.08x) | 13 → 94 (7.23x) | 187 → 1512 (8.09x) | 4 → 27 (6.75x) | 0.2126s → 2.224s (10.46x) | TIMEOUT / **TIMEOUT** |
| `aes256_ecb` | Block Cipher | 30,296 B | 258,592 B (8.54x) | 13 → 120 (9.23x) | 187 → 1452 (7.76x) | 4 → 37 (9.25x) | 0.2844s → 2.5042s (8.81x) | TIMEOUT / **TIMEOUT** |
| `aes_cbc` | Block Cipher | 37,640 B | 422,648 B (11.23x) | 17 → 175 (10.29x) | 236 → 2096 (8.88x) | 7 → 52 (7.43x) | 0.5218s → 1.8012s (3.45x) | TIMEOUT / **TIMEOUT** |
| `aes_ccm` | Block Cipher | 41,216 B | 906,688 B (22.0x) | 16 → 184 (11.5x) | 366 → 4155 (11.35x) | 7 → 56 (8.0x) | 0.3813s → 2.6289s (6.89x) | TIMEOUT / **TIMEOUT** |
| `aes_cfb` | Block Cipher | 37,896 B | 484,232 B (12.78x) | 17 → 150 (8.82x) | 240 → 2276 (9.48x) | 7 → 44 (6.29x) | 0.5198s → 2.5466s (4.9x) | TIMEOUT / **TIMEOUT** |
| `aes_ctr` | Block Cipher | 37,856 B | 394,032 B (10.41x) | 17 → 202 (11.88x) | 225 → 1994 (8.86x) | 8 → 59 (7.38x) | 0.384s → 2.1327s (5.55x) | TIMEOUT / **TIMEOUT** |
| `aes_ecb_mode` | Block Cipher | 37,024 B | 578,248 B (15.62x) | 17 → 145 (8.53x) | 212 → 2513 (11.85x) | 7 → 50 (7.14x) | 0.5273s → 2.498s (4.74x) | TIMEOUT / **TIMEOUT** |
| `aes_gcm` | Block Cipher | 43,464 B | 935,520 B (21.52x) | 20 → 291 (14.55x) | 402 → 4241 (10.55x) | 10 → 80 (8.0x) | 0.5417s → 1.4417s (2.66x) | TIMEOUT / **TIMEOUT** |
| `aes_ofb` | Block Cipher | 37,576 B | 455,576 B (12.12x) | 17 → 198 (11.65x) | 220 → 2239 (10.18x) | 7 → 56 (8.0x) | 0.4621s → 1.1787s (2.55x) | TIMEOUT / **TIMEOUT** |
| `aes_siv` | Block Cipher | 52,080 B | 866,088 B (16.63x) | 12 → 140 (11.67x) | 413 → 4348 (10.53x) | 4 → 40 (10.0x) | 0.1849s → 1.3532s (7.32x) | TIMEOUT / **TIMEOUT** |
| `aes_xts` | Block Cipher | 45,008 B | 513,216 B (11.4x) | 26 → 359 (13.81x) | 313 → 2907 (9.29x) | 15 → 107 (7.13x) | 0.7748s → 1.2146s (1.57x) | 5.995s / **TIMEOUT** |
| `ascon_aead128` | Lightweight / AEAD | 29,896 B | 474,872 B (15.88x) | 12 → 90 (7.5x) | 370 → 2219 (6.0x) | 4 → 27 (6.75x) | 0.1834s → 1.9965s (10.89x) | TIMEOUT / **TIMEOUT** |
| `ascon_hash256` | Lightweight / AEAD | 23,088 B | 200,576 B (8.69x) | 6 → 35 (5.83x) | 142 → 1128 (7.94x) | 1 → 8 (8.0x) | 0.0s → 1.3795s (13795.0x) | TIMEOUT / **TIMEOUT** |
| `ascon_xof128` | Lightweight / AEAD | 23,344 B | 200,600 B (8.59x) | 6 → 14 (2.33x) | 164 → 1196 (7.29x) | 1 → 4 (4.0x) | 0.0s → 0.9219s (9219.0x) | TIMEOUT / **TIMEOUT** |
| `bcrypt` | KDF / Password | 33,584 B | 426,816 B (12.71x) | 3 → 11 (3.67x) | 302 → 2333 (7.73x) | 1 → 4 (4.0x) | 0.0s → 1.2094s (12094.0x) | 0.267s / **TIMEOUT** |
| `blake2b256` | Hash / Digest | 28,408 B | 307,424 B (10.82x) | 7 → 73 (10.43x) | 171 → 1759 (10.29x) | 3 → 20 (6.67x) | 0.1121s → 1.4167s (12.64x) | 5.489s / **TIMEOUT** |
| `blake2b512` | Hash / Digest | 28,448 B | 315,584 B (11.09x) | 7 → 92 (13.14x) | 175 → 1922 (10.98x) | 3 → 27 (9.0x) | 0.1282s → 1.4412s (11.24x) | 5.907s / **TIMEOUT** |
| `blake2s128` | Hash / Digest | 28,360 B | 229,424 B (8.09x) | 7 → 64 (9.14x) | 171 → 1385 (8.1x) | 3 → 21 (7.0x) | 0.0932s → 2.8666s (30.76x) | 4.224s / **TIMEOUT** |
| `blake2s256` | Hash / Digest | 28,368 B | 327,920 B (11.56x) | 7 → 89 (12.71x) | 171 → 1828 (10.69x) | 3 → 23 (7.67x) | 0.0978s → 1.35s (13.8x) | 5.102s / **TIMEOUT** |
| `blowfish_ecb` | Block Cipher | 28,536 B | 217,056 B (7.61x) | 13 → 103 (7.92x) | 210 → 1289 (6.14x) | 4 → 33 (8.25x) | 0.2329s → 1.7276s (7.42x) | TIMEOUT / **TIMEOUT** |
| `camellia_ecb` | Block Cipher | 24,480 B | 278,600 B (11.38x) | 13 → 148 (11.38x) | 190 → 1560 (8.21x) | 4 → 38 (9.5x) | 0.2876s → 1.5461s (5.38x) | 6.975s / **TIMEOUT** |
| `cast128_ecb` | Block Cipher | 38,072 B | 892,920 B (23.45x) | 13 → 130 (10.0x) | 148 → 2875 (19.43x) | 4 → 36 (9.0x) | 0.2632s → 1.5225s (5.78x) | 3.333s / **TIMEOUT** |
| `cast256_ecb` | Block Cipher | 42,696 B | 642,984 B (15.06x) | 13 → 152 (11.69x) | 181 → 2251 (12.44x) | 4 → 43 (10.75x) | 0.1782s → 1.3208s (7.41x) | TIMEOUT / **TIMEOUT** |
| `chacha20_poly1305` | Stream Cipher | 36,216 B | 766,512 B (21.17x) | 12 → 141 (11.75x) | 354 → 3758 (10.62x) | 4 → 34 (8.5x) | 0.1716s → 1.4858s (8.66x) | TIMEOUT / **TIMEOUT** |
| `chacha20_stream` | Stream Cipher | 23,728 B | 429,592 B (18.1x) | 13 → 74 (5.69x) | 207 → 2037 (9.84x) | 5 → 25 (5.0x) | 0.2414s → 1.9309s (8.0x) | 5.863s / **TIMEOUT** |
| `cmac_aes` | Block Cipher | 45,008 B | 562,600 B (12.5x) | 13 → 154 (11.85x) | 298 → 2937 (9.86x) | 4 → 40 (10.0x) | 0.1618s → 1.1692s (7.23x) | 8.063s / **TIMEOUT** |
| `cshake128` | Hash / Digest | 35,272 B | 603,200 B (17.1x) | 7 → 60 (8.57x) | 310 → 3331 (10.75x) | 3 → 17 (5.67x) | 0.0852s → 1.9373s (22.74x) | TIMEOUT / **TIMEOUT** |
| `des3_ecb` | Block Cipher | 35,120 B | 381,248 B (10.86x) | 13 → 111 (8.54x) | 188 → 1843 (9.8x) | 4 → 34 (8.5x) | 0.1551s → 1.4292s (9.21x) | TIMEOUT / **TIMEOUT** |
| `des_ecb` | Block Cipher | 27,776 B | 327,736 B (11.8x) | 13 → 144 (11.08x) | 143 → 1465 (10.24x) | 4 → 40 (10.0x) | 0.1604s → 1.5686s (9.78x) | 5.199s / **TIMEOUT** |
| `dh2048` | Asymmetric / PKC | 62,864 B | 1,937,128 B (30.81x) | 5 → 22 (4.4x) | 1253 → 12201 (9.74x) | 1 → 7 (7.0x) | 0.0s → 1.7174s (17174.0x) | 0.377s / **TIMEOUT** |
| `dsa2048` | Asymmetric / PKC | 77,112 B | 2,586,904 B (33.55x) | 7 → 58 (8.29x) | 1496 → 15818 (10.57x) | 3 → 20 (6.67x) | 0.0953s → 2.1695s (22.76x) | TIMEOUT / **TIMEOUT** |
| `ecdh_p256` | Asymmetric / PKC | 139,856 B | 3,326,536 B (23.79x) | 21 → 301 (14.33x) | 2389 → 18841 (7.89x) | 10 → 90 (9.0x) | 0.4436s → 1.6392s (3.7x) | 0.585s / **TIMEOUT** |
| `ecdsa_p256` | Asymmetric / PKC | 154,464 B | 3,532,928 B (22.87x) | 18 → 232 (12.89x) | 2567 → 20226 (7.88x) | 4 → 60 (15.0x) | 0.3058s → 1.9466s (6.37x) | 0.352s / **TIMEOUT** |
| `ed25519` | Asymmetric / PKC | 240,776 B | 5,558,360 B (23.09x) | 11 → 74 (6.73x) | 3880 → 30573 (7.88x) | 4 → 21 (5.25x) | 0.1731s → 1.6313s (9.42x) | TIMEOUT / **TIMEOUT** |
| `gmac_aes` | Block Cipher | 59,808 B | 1,001,840 B (16.75x) | 16 → 103 (6.44x) | 560 → 5274 (9.42x) | 5 → 32 (6.4x) | 0.3103s → 1.3947s (4.49x) | TIMEOUT / **TIMEOUT** |
| `hkdf_sha256` | Hash / Digest | 43,808 B | 488,696 B (11.16x) | 7 → 64 (9.14x) | 301 → 2764 (9.18x) | 3 → 17 (5.67x) | 0.1043s → 1.4624s (14.02x) | TIMEOUT / **TIMEOUT** |
| `hmac_sha256` | Hash / Digest | 36,216 B | 369,744 B (10.21x) | 9 → 64 (7.11x) | 242 → 2266 (9.36x) | 3 → 18 (6.0x) | 0.0855s → 1.2108s (14.16x) | TIMEOUT / **TIMEOUT** |
| `idea_ecb` | Block Cipher | 23,608 B | 241,384 B (10.22x) | 13 → 128 (9.85x) | 203 → 1450 (7.14x) | 4 → 34 (8.5x) | 0.1985s → 1.6668s (8.4x) | 8.324s / **TIMEOUT** |
| `kmac128` | MAC / Authenticator | 49,224 B | 739,360 B (15.02x) | 7 → 112 (16.0x) | 431 → 4381 (10.16x) | 3 → 29 (9.67x) | 0.0862s → 1.4781s (17.15x) | TIMEOUT / **TIMEOUT** |
| `mars_ecb` | Block Cipher | 33,224 B | 278,184 B (8.37x) | 13 → 154 (11.85x) | 178 → 1362 (7.65x) | 4 → 42 (10.5x) | 0.1714s → 1.6101s (9.39x) | TIMEOUT / **TIMEOUT** |
| `md5` | Hash / Digest | 27,448 B | 622,520 B (22.68x) | 12 → 120 (10.0x) | 148 → 2309 (15.6x) | 5 → 37 (7.4x) | 0.1728s → 1.4753s (8.54x) | 2.835s / **TIMEOUT** |
| `mldsa44` | Asymmetric / PKC | 16,456 B | 31,664 B (1.92x) | 2 → 22 (11.0x) | 54 → 190 (3.52x) | 1 → 8 (8.0x) | 0.0s → 1.0257s (10257.0x) | 0.175s / **5.986s** |
| `mlkem512` | Post-Quantum (PQC) | 16,464 B | 27,600 B (1.68x) | 2 → 27 (13.5x) | 54 → 161 (2.98x) | 1 → 7 (7.0x) | 0.0s → 0.8706s (8706.0x) | 0.208s / **3.739s** |
| `mlkem768` | Post-Quantum (PQC) | 16,464 B | 19,336 B (1.17x) | 2 → 10 (5.0x) | 54 → 114 (2.11x) | 1 → 4 (4.0x) | 0.0s → 0.8832s (8832.0x) | 0.198s / **1.752s** |
| `pbkdf2_sha256` | Hash / Digest | 44,048 B | 488,752 B (11.1x) | 7 → 88 (12.57x) | 338 → 2786 (8.24x) | 3 → 24 (8.0x) | 0.0826s → 1.7779s (21.52x) | TIMEOUT / **TIMEOUT** |
| `poly1305` | MAC / Authenticator | 22,304 B | 146,984 B (6.59x) | 6 → 42 (7.0x) | 130 → 866 (6.66x) | 1 → 10 (10.0x) | 0.0s → 1.3373s (13373.0x) | 1.2s / **TIMEOUT** |
| `present_ecb` | Block Cipher | 26,984 B | 294,664 B (10.92x) | 13 → 108 (8.31x) | 125 → 1298 (10.38x) | 4 → 33 (8.25x) | 0.1746s → 1.3475s (7.72x) | 4.082s / **TIMEOUT** |
| `rc2_ecb` | Block Cipher | 22,968 B | 224,952 B (9.79x) | 13 → 129 (9.92x) | 174 → 1339 (7.7x) | 4 → 38 (9.5x) | 0.1628s → 1.8526s (11.38x) | TIMEOUT / **TIMEOUT** |
| `rc4_stream` | Stream Cipher | 20,552 B | 163,232 B (7.94x) | 13 → 112 (8.62x) | 106 → 934 (8.81x) | 5 → 32 (6.4x) | 0.1842s → 2.2168s (12.03x) | TIMEOUT / **TIMEOUT** |
| `rc6_ecb` | Block Cipher | 22,544 B | 142,888 B (6.34x) | 13 → 135 (10.38x) | 147 → 961 (6.54x) | 4 → 39 (9.75x) | 0.1689s → 1.3701s (8.11x) | 9.634s / **TIMEOUT** |
| `ripemd128` | Hash / Digest | 27,760 B | 819,112 B (29.51x) | 7 → 85 (12.14x) | 140 → 2873 (20.52x) | 3 → 21 (7.0x) | 0.137s → 1.0745s (7.84x) | 4.108s / **TIMEOUT** |
| `ripemd160` | Hash / Digest | 29,880 B | 929,672 B (31.11x) | 7 → 84 (12.0x) | 146 → 3167 (21.69x) | 3 → 23 (7.67x) | 0.1356s → 1.3512s (9.96x) | 4.907s / **TIMEOUT** |
| `rsa2048` | Asymmetric / PKC | 105,920 B | 3,891,488 B (36.74x) | 7 → 100 (14.29x) | 2178 → 22073 (10.13x) | 3 → 28 (9.33x) | 0.0796s → 1.4099s (17.71x) | TIMEOUT / **TIMEOUT** |
| `salsa20_stream` | Stream Cipher | 22,312 B | 118,000 B (5.29x) | 4 → 21 (5.25x) | 90 → 616 (6.84x) | 1 → 7 (7.0x) | 0.0s → 1.2235s (12235.0x) | 2.591s / **TIMEOUT** |
| `scrypt` | KDF / Password | 53,072 B | 780,280 B (14.7x) | 7 → 97 (13.86x) | 470 → 4237 (9.01x) | 3 → 23 (7.67x) | 0.0825s → 1.193s (14.46x) | TIMEOUT / **TIMEOUT** |
| `seed_ecb` | Block Cipher | 26,928 B | 171,776 B (6.38x) | 13 → 139 (10.69x) | 147 → 1007 (6.85x) | 4 → 41 (10.25x) | 0.1778s → 1.5133s (8.51x) | 3.605s / **TIMEOUT** |
| `serpent_ecb` | Block Cipher | 31,264 B | 466,576 B (14.92x) | 13 → 139 (10.69x) | 177 → 1900 (10.73x) | 4 → 44 (11.0x) | 0.1874s → 1.8673s (9.96x) | 9.985s / **TIMEOUT** |
| `sha1` | Hash / Digest | 22,592 B | 217,056 B (9.61x) | 12 → 136 (11.33x) | 163 → 1439 (8.83x) | 5 → 42 (8.4x) | 0.2285s → 1.4824s (6.49x) | 9.789s / **TIMEOUT** |
| `sha224` | Hash / Digest | 25,656 B | 217,320 B (8.47x) | 7 → 92 (13.14x) | 166 → 1353 (8.15x) | 3 → 27 (9.0x) | 0.0913s → 1.3989s (15.32x) | 8.394s / **TIMEOUT** |
| `sha256` | Hash / Digest | 22,944 B | 188,320 B (8.21x) | 12 → 171 (14.25x) | 150 → 1196 (7.97x) | 5 → 46 (9.2x) | 0.1783s → 1.4736s (8.26x) | 9.517s / **TIMEOUT** |
| `sha256_crypt` | Hash / Digest | 46,752 B | 627,976 B (13.43x) | 7 → 52 (7.43x) | 389 → 3435 (8.83x) | 2 → 18 (9.0x) | 0.0858s → 1.7086s (19.91x) | TIMEOUT / **TIMEOUT** |
| `sha384` | Hash / Digest | 25,840 B | 270,608 B (10.47x) | 7 → 65 (9.29x) | 172 → 1569 (9.12x) | 3 → 21 (7.0x) | 0.0914s → 1.4432s (15.79x) | 9.738s / **TIMEOUT** |
| `sha3_256` | Hash / Digest | 29,872 B | 401,800 B (13.45x) | 7 → 40 (5.71x) | 205 → 2055 (10.02x) | 3 → 14 (4.67x) | 0.1184s → 1.9377s (16.37x) | TIMEOUT / **TIMEOUT** |
| `sha3_512` | Hash / Digest | 29,904 B | 430,424 B (14.39x) | 7 → 64 (9.14x) | 209 → 2076 (9.93x) | 3 → 20 (6.67x) | 0.085s → 2.6653s (31.36x) | TIMEOUT / **TIMEOUT** |
| `sha512` | Hash / Digest | 22,608 B | 229,232 B (10.14x) | 7 → 68 (9.71x) | 142 → 1271 (8.95x) | 3 → 20 (6.67x) | 0.0945s → 1.8567s (19.65x) | TIMEOUT / **TIMEOUT** |
| `shake128` | Hash / Digest | 31,120 B | 352,888 B (11.34x) | 7 → 64 (9.14x) | 223 → 2054 (9.21x) | 3 → 17 (5.67x) | 0.1292s → 2.249s (17.41x) | TIMEOUT / **TIMEOUT** |
| `shake256` | Hash / Digest | 31,120 B | 332,424 B (10.68x) | 7 → 77 (11.0x) | 223 → 1995 (8.95x) | 3 → 24 (8.0x) | 0.1354s → 2.1566s (15.93x) | TIMEOUT / **TIMEOUT** |
| `sm2` | Asymmetric / PKC | 152,792 B | 3,941,672 B (25.8x) | 10 → 167 (16.7x) | 2509 → 21200 (8.45x) | 4 → 49 (12.25x) | 0.2636s → 1.4294s (5.42x) | TIMEOUT / **TIMEOUT** |
| `sm3` | Hash / Digest | 22,672 B | 216,872 B (9.57x) | 7 → 40 (5.71x) | 143 → 1222 (8.55x) | 3 → 14 (4.67x) | 0.1411s → 1.6178s (11.47x) | 9.871s / **TIMEOUT** |
| `sm4_ecb` | Block Cipher | 23,344 B | 344,008 B (14.74x) | 13 → 154 (11.85x) | 146 → 1478 (10.12x) | 4 → 44 (11.0x) | 0.2237s → 2.0034s (8.96x) | 5.474s / **TIMEOUT** |
| `tea_ecb` | Block Cipher | 21,608 B | 208,432 B (9.65x) | 13 → 107 (8.23x) | 122 → 1128 (9.25x) | 4 → 34 (8.5x) | 0.1885s → 1.9928s (10.57x) | 2.137s / **TIMEOUT** |
| `tiger` | Hash / Digest | 34,968 B | 176,040 B (5.03x) | 7 → 106 (15.14x) | 139 → 1079 (7.76x) | 3 → 30 (10.0x) | 0.1275s → 2.1745s (17.05x) | 2.869s / **TIMEOUT** |
| `twofish_ecb` | Block Cipher | 25,040 B | 290,752 B (11.61x) | 13 → 104 (8.0x) | 208 → 1564 (7.52x) | 4 → 32 (8.0x) | 0.2097s → 1.386s (6.61x) | TIMEOUT / **TIMEOUT** |
| `whirlpool` | Hash / Digest | 31,032 B | 270,288 B (8.71x) | 7 → 88 (12.57x) | 157 → 1291 (8.22x) | 3 → 24 (8.0x) | 0.0792s → 1.2512s (15.8x) | TIMEOUT / **TIMEOUT** |
| `x25519` | Asymmetric / PKC | 39,696 B | 295,352 B (7.44x) | 7 → 83 (11.86x) | 408 → 1922 (4.71x) | 3 → 23 (7.67x) | 0.082s → 1.6838s (20.53x) | TIMEOUT / **TIMEOUT** |
| `xcbc_mac` | MAC / Authenticator | 44,736 B | 578,760 B (12.94x) | 13 → 111 (8.54x) | 295 → 2814 (9.54x) | 4 → 30 (7.5x) | 0.1627s → 1.4276s (8.77x) | TIMEOUT / **TIMEOUT** |
| `xtea_ecb` | Block Cipher | 21,608 B | 237,096 B (10.97x) | 13 → 128 (9.85x) | 122 → 1184 (9.7x) | 4 → 37 (9.25x) | 0.195s → 1.6416s (8.42x) | 2.007s / **TIMEOUT** |
| `zuc_stream` | Stream Cipher | 28,360 B | 523,760 B (18.47x) | 13 → 153 (11.77x) | 139 → 2032 (14.62x) | 5 → 44 (8.8x) | 0.1732s → 1.8686s (10.79x) | TIMEOUT / **TIMEOUT** |
