#!/usr/bin/env python3
"""
hatagawa_recover.py

Toolkit for Hatagawa I (BlackHat MEA CTF 2025 Qualifiers)

Usage:
  1) If you already know (or strongly guess) part of the plaintext (a crib/prefix),
     pass the ciphertext and crib and the script will try to recover the LCG
     parameters and decrypt the rest.

  2) If you don't know the plaintext, provide a list of ciphertexts (one-per-line)
     and the script will try common flag prefixes (cribs) to find consistent LCG params.

Notes:
- Kawa.Get() returns 8 bytes (state size = 64 bits) since m = 2**64 - 1.
- OTP is stream of 8-byte states concatenated; encryption = plaintext XOR OTP.
- Without any known plaintext (crib), a single ciphertext is not solvable (OTP is random).
"""

import sys
import argparse
from typing import List, Optional, Tuple
import binascii

M = (1 << 64) - 1  # modulus used by the challenge
BLOCK_SIZE = 8      # bytes per Get() output (ceil(64/8) = 8)


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def bytes_to_int(be: bytes) -> int:
    return int.from_bytes(be, 'big')


def int_to_bytes(x: int, length: int = BLOCK_SIZE) -> bytes:
    return x.to_bytes(length, 'big')


def derive_state_blocks(cipher: bytes, plain: bytes) -> List[int]:
    """
    Given ciphertext and same-length plaintext, derive the LCG state blocks (x0, x1, ...)
    where OTP blocks = state_bytes and ciphertext_block = plaintext_block XOR state_bytes.
    """
    assert len(cipher) == len(plain)
    blocks_c = split_blocks(cipher)
    blocks_p = split_blocks(plain)
    states = []
    for cb, pb in zip(blocks_c, blocks_p):
        # pad pb if shorter than block (should only occur on final block)
        if len(pb) < BLOCK_SIZE:
            # pad plaintext block with zeros? No: encryption used only as many bytes as plaintext.
            # But the generator produced full 8-byte states and then XORed only needed prefix.
            # For deriving full 8-byte state we need full 8 bytes of plaintext for that block.
            # So we only derive states for full blocks here.
            break
        state = bytes_to_int(bytes([c ^ p for c, p in zip(cb, pb)]))
        states.append(state)
    return states


def solve_lcg_from_two_states(x0: int, x1: int) -> Optional[Tuple[int,int]]:
    """
    Solve for (a, c) such that x1 = (a*x0 + c) & M.
    There are many possible (a,c) pairs for modulus M that is not prime, but we can
    exploit having multiple transitions to disambiguate.
    For single pair, infinite solutions; we need at least two transitions to solve for a uniquely.
    """
    # For modulus = 2^64 - 1, compute a and c using two transitions later.
    # Here we return None because a single transition is underdetermined.
    return None


def solve_lcg_from_transitions(states: List[int]) -> Optional[Tuple[int,int]]:
    """
    Given a list of consecutive internal states x0, x1, x2, ... find a and c such that:
      x_{i+1} = (a * x_i + c) & M
    We can solve for a and c using two transitions:
      x1 = a*x0 + c (mod M)
      x2 = a*x1 + c (mod M)
    Subtract:
      (x2 - x1) = a*(x1 - x0) (mod M)
    Solve for a:
      a = (x2 - x1) * inv_mod(x1 - x0, M) (mod M)
    Then c = x1 - a*x0 (mod M)
    """
    if len(states) < 3:
        return None

    x0, x1, x2 = states[0], states[1], states[2]
    # compute differences modulo M+1? Careful: modulus is M, but LCG uses bitwise & M (i.e., modulo 2^64 with special M).
    # In the challenge they use `& self.m` where m = 2**64 - 1; that's equivalent to modulo 2**64 but with masking by 2**64-1.
    # Here we'll treat operations modulo 2**64 (2**64), but because m=2**64 - 1 is odd, arithmetic inversion is possible for many cases.
    mod = 1 << 64  # use 2**64 arithmetic for inverse and multiplications
    def modinv(a: int, m: int) -> Optional[int]:
        # extended gcd
        a = a % m
        if a == 0:
            return None
        lm, hm = 1, 0
        low, high = a, m
        while low > 1:
            r = high // low
            nm = hm - lm * r
            new = high - low * r
            hm, lm = lm, nm
            high, low = low, new
        return lm % m

    d1 = (x1 - x0) % mod
    d2 = (x2 - x1) % mod

    inv = modinv(d1, mod)
    if inv is None:
        return None

    a = (d2 * inv) % mod
    c = (x1 - (a * x0) % mod) % mod

    # verify across all provided states
    for i in range(len(states)-1):
        lhs = states[i+1] % mod
        rhs = (a * states[i] + c) % mod
        if lhs != rhs:
            return None

    # a and c computed in 0..2**64-1 range; mask to M if desired
    return a, c


def decrypt_with_lcg(cipher: bytes, a: int, c: int, seed_state: int) -> bytes:
    """
    Given LCG params and initial state seed_state (x0), regenerate OTP and decrypt ciphertext.
    """
    mod_mask = M
    mod = 1 << 64
    blocks = split_blocks(cipher)
    out = b''
    x = seed_state
    for i, cb in enumerate(blocks):
        # the generator used x = (a*x + c) & m (m = 2**64 - 1)
        # In the code, first it updates x then returns it (i.e., Get does x = a*x + c; return x)
        # But our derived states are the returned values; so when decrypting, start with the known x0 (first returned).
        block_bytes = int_to_bytes(x)
        # if last block smaller, only XOR the needed bytes
        take = min(len(cb), len(block_bytes))
        out += bytes([cb[j] ^ block_bytes[j] for j in range(take)])
        # next internal state
        x = (a * x + c) & mod_mask
    return out


def try_recover_from_crib(cipher_hex: str, crib: bytes) -> None:
    cipher = bytes.fromhex(cipher_hex)
    # ensure crib isn't longer than ciphertext
    if len(crib) > len(cipher):
        print("[!] Crib longer than ciphertext, skipping.")
        return

    # Try to align crib at start only (flag prefix). If you want to try other offsets, loop offsets.
    offset = 0
    # Build a candidate plaintext of same length as cipher by inserting crib at offset and leaving rest unknown
    # We can only derive full-block states for blocks where we have full 8-byte known plaintext.
    # So figure how many full blocks we can derive.
    # Create a bytes object with crib and zeros for unknown parts (we will only trust full blocks).
    candidate_plain = bytearray(len(cipher))
    candidate_plain[offset:offset+len(crib)] = crib

    # Determine how many full blocks starting at block 0 are completely known
    full_blocks = 0
    for blk_idx in range(len(split_blocks(cipher))):
        s = blk_idx * BLOCK_SIZE
        block_plain = candidate_plain[s:s+BLOCK_SIZE]
        if len(block_plain) < BLOCK_SIZE:
            break
        # Check if block is fully known (i.e., not all zeros unless crib provided zeros)
        if all(b == 0 for b in block_plain):
            break
        # If at least one non-zero but crib might not fill entire block: require fully filled
        # We require that the crib provided every byte in this block.
        if any(candidate_plain[s + i] == 0 for i in range(BLOCK_SIZE)):
            break
        full_blocks += 1

    if full_blocks < 3:
        print(f"[!] Need at least 3 full known consecutive blocks (8-byte each) to reliably solve LCG, found {full_blocks}.")
        print("[!] If you have a longer known plaintext prefix (e.g., full 24 bytes), try again.")
        return

    # Build plaintext for those full blocks
    plain_full = bytes(candidate_plain[:full_blocks * BLOCK_SIZE])
    cipher_full = cipher[:full_blocks * BLOCK_SIZE]
    states = derive_state_blocks(cipher_full, plain_full)
    if len(states) < 3:
        print("[!] Not enough states derived despite full_blocks; abort.")
        return

    solved = solve_lcg_from_transitions(states)
    if solved is None:
        print("[!] Could not derive LCG parameters from derived states. Maybe alignment/assumptions wrong.")
        return

    a, c = solved
    print(f"[+] Derived LCG parameters: a = {a} , c = {c}")

    seed_state = states[0]
    print(f"[+] Recovered first returned state (x0) = {seed_state:#018x}")

    # Now decrypt full ciphertext using the found params and seed
    plaintext = decrypt_with_lcg(cipher, a, c, seed_state)
    try:
        print("[+] Decrypted plaintext (raw bytes):")
        print(plaintext)
        print("[+] As UTF-8 (if printable):")
        print(plaintext.decode('utf-8', errors='replace'))
    except Exception as e:
        print("[!] Error decoding plaintext:", e)


def attempt_common_prefixes(cipher_hex: str, prefixes: List[bytes]) -> None:
    """
    Try a list of prefixes (cribs) for the given ciphertext.
    """
    for crib in prefixes:
        print(f"\n[*] Trying crib: {crib!r}")
        try_recover_from_crib(cipher_hex, crib)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hatagawa LCG recovery helper (needs a crib/prefix).")
    parser.add_argument("--cipher", "-c", required=True, help="Ciphertext hex (single run output).")
    parser.add_argument("--crib", "-k", help="Known plaintext prefix (e.g. 'BHFlagY{'). If omitted, common prefixes will be tried.")
    parser.add_argument("--list", "-l", help="Path to file with ciphertexts (one hex per line). Not required for crib-based recovery.")
    args = parser.parse_args()

    common_prefixes = [
        b"BHFlagY{", b"BHFlag{", b"flag{", b"FLAG{", b"CTF{", b"picoCTF{", b"HTB{", b"hitcon{"
    ]

    cipher_hex = args.cipher.strip()
    if args.crib:
        crib = args.crib.encode()
        try_recover_from_crib(cipher_hex, crib)
    else:
        attempt_common_prefixes(cipher_hex, common_prefixes)
