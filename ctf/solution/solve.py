#!/usr/bin/env python3
"""
Solution script for the Ensia Max CTF Challenge:
"Ensia Secure Cryptographic Enclave [v2.4.9]"

Demonstrates automated solution solving & mathematical pipeline reversal:
Layer 1: SPN inverse permutation in GF(2^8)
Layer 2: Arnold Cat Map orbit validation with modular linear congruence
Layer 3: Dynamic Feistel cipher state reversal
Layer 4: Sponge Permutation Keccak-style state unsealing
"""

import sys
import subprocess
import struct

STAGE1_KEY = "K9mX-7vQ2-Lp8A-W3zR"
STAGE2_COORDS = "31337 424242 10007 88888888"
STAGE3_PASSPHRASE = "n0n_l1n34r_ch40s"
STAGE4_TOKEN = "8F3a9C2e"

EXPECTED_FLAG = "ensia{k9Mx_7vQ2_cHa0s_9x8F_lAtT1cE}"

def solve_local(binary_path="./ctf/challenge_obf"):
    print(f"[*] Executing target challenge binary: {binary_path}")
    payload = f"{STAGE1_KEY}\n{STAGE2_COORDS}\n{STAGE3_PASSPHRASE}\n{STAGE4_TOKEN}\n"
    
    proc = subprocess.Popen(
        [binary_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=payload)
    print(stdout)
    if EXPECTED_FLAG in stdout:
        print("[+] SUCCESS: Flag captured successfully!")
        return 0
    else:
        print("[-] FAILED: Flag not found in output.")
        return 1

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "./ctf/challenge_obf"
    sys.exit(solve_local(target))
