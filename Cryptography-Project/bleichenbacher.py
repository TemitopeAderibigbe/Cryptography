#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py from_username+to_username+100.00
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys


def forge_signature(message: str) -> int:

    # Constraints for 2048-bit RSA key
    KEY_SIZE_BITS = 2048
    KEY_SIZE_BYTES = KEY_SIZE_BITS // 8 #256 Bytes

    #SHA-256 has of the function
    message_bytes = message.encode('utf-8')
    hash_bytes = hashlib.sha256(message_bytes).digest() #32 bytes

    # ASN.1 DigestInfo for SHA-256 (19 bytes):
    ASN1_SHA256 = bytes.fromhex('3031300d060960864801650304020105000420')

    #Build the forged block with minimal padding
    forged_block = bytearray()
    forged_block.append(0x00) # Leading byte
    forged_block.append(0x01) # Block Type
    forged_block.append(0xFF) # Just one FF byte
    forged_block.append(0x00) # Separator
    forged_block.extend(ASN1_SHA256) #ASN.1 DigestInfo
    forged_block.extend(hash_bytes)   

    # 55 bytes so far, pad the rest with 0's
    garbage_len = KEY_SIZE_BYTES - len(forged_block)
    forged_block.extend(bytes(garbage_len))

    # Convert to integer
    forged_int = bytes_to_integer(bytes(forged_block))

    # Since e = 3, take the cube root
    # Want to find s s.t. s^3 = forged_int
    signature, exact = integer_nthroot(forged_int, 3)

    # if not exact, round up to ensure s^3 >= forged_int
    if not exact:
        signature += 1
    
    return signature


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    # TODO: Forge a signature

    forged_signature = forge_signature(message)

    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))


if __name__ == '__main__':
    main()
