#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://cryptoproject.gtinfosec.org/GTusername/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your GTusername is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue

def decrypt_block(oracle_url: str, prev_block: bytes, curr_block: bytes) -> bytes:
    BLOCK_SIZE = 16
    intermediate = bytearray(BLOCK_SIZE)
    
    # Decrypt byte by byte, from right to left
    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos
        
        # Build a "fake" previous block
        modified_prev = bytearray(BLOCK_SIZE)
        
        # Set known bytes to create the target padding
        for i in range(byte_pos + 1, BLOCK_SIZE):
            modified_prev[i] = intermediate[i] ^ padding_value
        
        # Try all 256 values for current byte
        candidates = []
        
        for guess in range(256):
            modified_prev[byte_pos] = guess
            
            # Send only these 2 blocks to oracle
            test_ct = bytes(modified_prev) + curr_block
            result = oracle(oracle_url, [test_ct])[0]
            
            # Accept any status that's NOT "invalid_padding"
            if result["status"] != "invalid_padding":
                candidates.append(guess)
        
        # Handle candidates
        if len(candidates) == 0:
            raise Exception(f"Could not find valid padding for byte position {byte_pos}")
        
        # If multiple candidates when looking for 0x01, the real padding is longer
        # Example: real padding is 0x03 0x03 0x03, but we can also create 0x03 0x03 0x01
        # Both give "invalid_mac", not "invalid_padding"
        if len(candidates) > 1 and padding_value == 1:
            # The real padding length equals the plaintext byte value
            # Try each candidate and see which one makes sense
            for guess in candidates:
                intermediate_val = guess ^ padding_value  # guess ^ 0x01
                real_plaintext = intermediate_val ^ prev_block[byte_pos]
                
                # The real plaintext byte should equal the actual padding length
                # Check if this candidate is consistent with multi-byte padding
                if 2 <= real_plaintext <= 16:
                    # This suggests real padding length is real_plaintext
                    # Use this candidate
                    intermediate[byte_pos] = intermediate_val
                    break
            else:
                # No multi-byte padding detected, use first candidate
                intermediate[byte_pos] = candidates[0] ^ padding_value
        else:
            # Single candidate or not looking for 0x01
            intermediate[byte_pos] = candidates[0] ^ padding_value
    
    # Compute plaintext by XORing intermediate with real previous block
    # This method was talked about in class
    plaintext = bytes([intermediate[i] ^ prev_block[i] for i in range(BLOCK_SIZE)])
    return plaintext

def decrypt_message(oracle_url: str, ciphertext: bytes) -> bytes:
    
    # The primer says to decrypt the full message by working backwards through blocks.

    BLOCK_SIZE = 16
    
    if len(ciphertext) < 2 * BLOCK_SIZE:
        raise ValueError("Ciphertext too short")
    
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    
    # Split into blocks
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    
    plaintext_blocks = []
    
    # Work backwards: decrypt last block first, then second-to-last, etc.
    for i in range(len(blocks) - 1, 0, -1):
        prev_block = blocks[i - 1]
        curr_block = blocks[i]
        
        # sys.stderr.write(f"Decrypting block {i}/{len(blocks)-1}...\n")
        plaintext_block = decrypt_block(oracle_url, prev_block, curr_block)
        plaintext_blocks.insert(0, plaintext_block)
    
    # Concatenate all plaintext blocks
    full_plaintext = b''.join(plaintext_blocks)
    
    # Remove PKCS#7 padding
    padding_length = full_plaintext[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise ValueError(f"Invalid padding length: {padding_length}")
    
    # Verify padding
    for i in range(padding_length):
        if full_plaintext[-(i+1)] != padding_length:
            raise ValueError("Invalid padding")
    
    plaintext_without_padding = full_plaintext[:-padding_length]
    
    # Remove HMAC (last 32 bytes)
    if len(plaintext_without_padding) < 32:
        raise ValueError("Plaintext too short to contain HMAC")
    
    message = plaintext_without_padding[:-32]
    
    return message

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    #
    # TODO: Decrypt the message
    #

    #Decrypt message
    decrypted = decrypt_message(oracle_url, message)

    #Output as human-readable text
    print(decrypted.decode('utf-8', errors='replace'))

if __name__ == '__main__':
    main()