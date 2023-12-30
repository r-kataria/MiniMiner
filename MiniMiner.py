import math
import time

def _time():
    return time.time()

def right_rotate(x, n):
    # Right rotate x by n bits
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def hex_to_byte_list(hex_str):
    # Hex string to byte list
    if not isinstance(hex_str, str):
        raise TypeError("hex_to_byte_list expects a string input.")
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def byte_list_to_hex(byte_list):
    # Byte list to hex string
    return ''.join(['{:02x}'.format(byte) for byte in byte_list])

def little_endian(hex_str):
    # Convert hex to little endian
    return byte_list_to_hex(hex_to_byte_list(hex_str)[::-1])

def reverse_hex(hex_str):
    # Reverse byte order of hex
    return little_endian(hex_str)

# Constants for SHA-256
K_const = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def sha256(byte_list):
    # Compute SHA-256
    # See https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py for sane implementation
    msg = list(byte_list)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]
    orig_len_in_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg.extend([(orig_len_in_bits >> (8 * i)) & 0xFF for i in range(7, -1, -1)])
    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        w = [(chunk[4 * j] << 24) | (chunk[4 * j + 1] << 16) | (chunk[4 * j + 2] << 8) | chunk[4 * j + 3] for j in range(16)]
        for j in range(16, 64):
            s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            temp1 = (h + S1 + ch + K_const[j] + w[j]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
        H = [(H[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])]
    return ''.join(['{:08x}'.format(h) for h in H])



def construct_genesis_header():
    # Constructs the Genesis Block header as a list of bytes with nonce set to 0
    version = "01000000"  # Version 1 in little endian
    prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # 32 bytes, little endian
    merkle_root = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"  # Correct Merkle Root

    # Convert Merkle Root to little endian
    merkle_root_le = little_endian(merkle_root)

    timestamp = "29ab5f49"  # 1231006505 in little endian
    bits = "ffff001d"       # 486604799 in little endian
    nonce = "00000000"      # Initialize nonce to 0 in little endian

    # Combine all parts to form the Genesis Block Header in little endian
    genesis_header_hex = version + prev_block_hash + merkle_root_le + timestamp + bits + nonce

    # Convert Hexadecimal to Byte List
    genesis_header_bytes = hex_to_byte_list(genesis_header_hex)

    return genesis_header_bytes

def decode_bits(bits_hex):
    """
    Decodes the compact bits format to get the target.

    Args:
        bits_hex (str): 8-character hexadecimal string representing the bits field.

    Returns:
        int: The target value as an integer.
    """
    # First byte is the exponent
    exponent = int(bits_hex[0:2], 16)
    # Next 6 characters represent the coefficient
    coefficient = int(bits_hex[2:], 16)
    target = coefficient * (1 << (8 * (exponent - 3)))
    return target

def run_tests():
    # Runs tests to verify SHA-256 implementation works as intended
    test_cases = {
        "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hello": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "The quick brown fox jumps over the lazy dog":
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "The quick brown fox jumps over the lazy cog":
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
    }

    for msg, expected in test_cases.items():
        # Convert message to byte list
        msg_hex = ''.join(['{:02x}'.format(ord(c)) for c in msg])
        try:
            msg_bytes = hex_to_byte_list(msg_hex)
        except Exception as e:
            print("Error converting message to bytes:", e)
            print("Test Passed: False\n")
            continue

        try:
            computed_hash = sha256(msg_bytes)
            print("Input: '{}'".format(msg))
            print("Expected SHA-256: {}".format(expected))
            print("Computed SHA-256: {}".format(computed_hash))
            print("Test Passed: {}\n".format(computed_hash.lower() == expected.lower()))
            assert computed_hash.lower() == expected.lower()
        except Exception as e:
            print("Input: '{}'".format(msg))
            print("Error during hashing:", e)
            print("Test Passed: False\n")
    print("All tests completed.\n")

def mine_simulated_block(genesis_header_bytes, target_hash_hex, max_nonce=1000000):
    """
    Simulates mining by searching for a nonce that produces a hash less than or equal to the target.

    Args:
        genesis_header_bytes (list): The Genesis Block header as a list of bytes.
        target_hash_hex (str): The target hash in hexadecimal for demonstration.
        max_nonce (int): The maximum nonce value to search.

    Returns:
        tuple: (nonce, final_hash_le, elapsed_time) if found, else (None, None, elapsed_time)
    """
    nonce = 0

    hash_count = 0
    last_time = _time()

    start_time = _time()

    while nonce <= max_nonce:
        # Update the nonce in the block header (last 4 bytes in little endian)
        nonce_hex = '{:08x}'.format(nonce)
        try:
            nonce_hex_le = little_endian(nonce_hex)  # Convert to little endian
            nonce_bytes = hex_to_byte_list(nonce_hex_le)
        except Exception as e:
            print("Error converting nonce to bytes:", e)
            return None, None, (_time() - start_time)

        updated_block = genesis_header_bytes[:-4] + nonce_bytes

        # Ensure updated_block has the correct length
        if len(updated_block) != len(genesis_header_bytes):
            print("Warning: updated_block length mismatch at nonce {}".format(nonce))
            return None, None, (_time() - start_time)

        # Compute double SHA-256
        try:
            hash1 = sha256(updated_block)
            hash1_bytes = hex_to_byte_list(hash1)
            hash2 = sha256(hash1_bytes)
        except Exception as e:
            print("Error during double SHA-256 at nonce {}: {}".format(nonce, e))
            return None, None, (_time() - start_time)

        # Increment hash count
        hash_count += 1

        # Calculate and print the hash rate after each hash
        current_time = _time()
        time_taken = (current_time - last_time)
        if time_taken > 0:
            hash_rate = 1 / time_taken
        else:
            hash_rate = 0
        print("Hash rate: {:.2f} hashes/sec".format(hash_rate))
        last_time = current_time

        # Check if the computed hash is less than or equal to the target hash
        if hash2.lower() <= target_hash_hex.lower():
            end_time = _time()
            elapsed_time = time(end_time - start_time)
            # Reverse the final hash to match Bitcoin's little-endian display
            final_hash_le = reverse_hex(hash2)
            return nonce, final_hash_le, elapsed_time

        nonce += 1

    # After loop, if nonce not found
    end_time = _time()
    elapsed_time = (end_time - start_time)
    return None, None, elapsed_time

def bitcoin():
    # Run Test Cases
    run_tests()

    # Construct Block Header (with nonce initialized to 0)
    genesis_header_bytes = construct_genesis_header()

    # Define a lower difficulty target for demonstration (e.g., leading 4 zeros)
    target_hash_demo = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    # Start simulated mining with a limited nonce range suitable for the demo
    print("Starting mining simulation with lower difficulty...")
    nonce, final_hash_le, elapsed_time = mine_simulated_block(
        genesis_header_bytes,
        target_hash_demo,
        max_nonce=1000000  # Adjust as needed for the demo
    )

    if nonce is not None:
        print("\nNonce found:", nonce)
        print("Hash:", final_hash_le)
        print("Time taken:", elapsed_time, "seconds")
    else:
        print("\nNo valid nonce found within the range.")
        print("Time taken:", elapsed_time, "seconds")

# Execute the simulated mining function
bitcoin()