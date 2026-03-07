# Cryptographic Attack Implementation

A practical exploration of real-world cryptographic vulnerabilities through implementation of four classic attacks: length extension, hash collisions, padding oracle, and RSA signature forgery.

**Educational Purpose**: These implementations demonstrate why certain cryptographic practices are dangerous and should be avoided in production systems.

---

## Attack Implementations

### Length Extension Attack
Exploited SHA-256's Merkle-Damgård construction to forge authentication tokens without knowing the secret key.

**Vulnerability**: Using `SHA256(secret || message)` instead of HMAC for authentication allows attackers to append data by resuming the hash computation from its final state.

**Technique**:
- Extracted token (hash output) from authorized URL
- Calculated SHA-256 padding for known message length
- Restored hash state and extended with malicious command
- Constructed forged URL with embedded padding

**Result**: Successfully appended `&command=UnlockSafes` to authorized requests without knowing the 8-byte secret.

---

### MD5 Hash Collision Generation
Generated two Python programs with identical MD5 hashes but different runtime behavior using collision attacks.

**Vulnerability**: MD5's broken collision resistance allows creating different inputs with the same hash in under one second.

**Technique**:
- Used `fastcoll` to generate collision blocks with identical MD5
- Embedded collision blocks in Python triple-quoted strings
- Added conditional logic based on SHA-256 of the blob
- Both files hash to same MD5 but execute different code paths

**Result**: Created `good.py` and `evil.py` with identical MD5 (`c720ad86...`) but different outputs.

---

### Padding Oracle Attack
Decrypted AES-CBC ciphertext without knowing the encryption key by exploiting padding validation timing.

**Vulnerability**: Server reveals whether padding is valid before checking MAC, leaking one bit of information per query.

**Technique**:
- Sent modified ciphertext blocks to oracle
- Observed `invalid_padding` vs `invalid_mac` responses
- Tried all 256 byte values for each position
- Derived intermediate values when padding validated
- Computed plaintext: `plaintext = intermediate XOR ciphertext[prev_block]`
- Worked backwards through blocks to avoid MAC errors

**Challenge**: Handled false positives when real padding was multi-byte (e.g., `0x03 0x03 0x03`) but oracle also accepted `0x03 0x03 0x01`.

**Result**: Successfully decrypted 9-block ciphertext through ~36,000 oracle queries in several minutes.

---

### Bleichenbacher RSA Signature Forgery
Forged RSA signatures with e=3 by exploiting weak PKCS#1 v1.5 validation.

**Vulnerability**: Server only checks signature prefix (`00 01 FF ... 00 <ASN.1> <hash>`) without verifying FF padding length or hash position.

**Technique**:
- Constructed malformed PKCS#1 block with only ONE FF byte (should be 202)
- Format: `00 01 FF 00 <ASN.1> <SHA256(message)> <zeros...>`
- Computed cube root since block is much smaller than proper signature
- Server validated prefix and accepted signature

**Mathematical Basis**: With minimal padding, `signature³` doesn't wrap around modulus, so we compute regular cube root instead of modular arithmetic.

**Result**: Forged signature for money transfer without possessing private key.

---

## Technical Implementation

**Language**: Python 3.9  
**Libraries**: `hashlib`, `requests`, custom `pysha256` module, `roots` (arbitrary-precision arithmetic)  
**Cryptography**: SHA-256, MD5, AES-128-CBC, RSA-2048  
**Environment**: Docker development container

---

## Key Findings

### Why These Attacks Matter

**Length Extension**: Demonstrates why HMAC-SHA256 should always be used instead of `hash(secret || message)` for authentication. Production systems using plain hash functions for MAC are vulnerable.

**Hash Collisions**: Shows MD5 is completely broken for integrity verification. Any system still using MD5 for security purposes can be attacked in real-time.

**Padding Oracle**: Reveals how timing side-channels and error messages leak information. Implementations must check MAC before decryption and use constant-time comparisons.

**Bleichenbacher**: Illustrates dangers of implementing cryptographic standards incorrectly. Even with strong primitives (RSA-2048), improper validation enables forgery.

---

## Defense Recommendations

1. **Use HMAC-SHA256** for message authentication, never plain hash functions
2. **Deprecate MD5/SHA-1** completely - use SHA-256 minimum
3. **Validate MAC before decryption** to prevent padding oracle attacks
4. **Use modern RSA padding** (PSS) with full validation, not PKCS#1 v1.5
5. **Implement constant-time operations** to avoid timing side-channels

---

## Testing Results

All attacks successfully exploited their target vulnerabilities:
- **Length Extension**: Forged valid authentication tokens
- **Hash Collisions**: Identical MD5 with different behavior
- **Padding Oracle**: Complete plaintext recovery (3/3 test cases)
- **Bleichenbacher**: Signature forgery accepted by server

---

## Repository Structure

├── len_ext_attack.py      # Length extension implementation  
├── good.py                # Hash collision (benign version)  
├── evil.py                # Hash collision (malicious version)  
├── padding_oracle.py      # Padding oracle attack  
├── bleichenbacher.py      # RSA signature forgery  
├── pysha256.py           # Custom SHA-256 with state control  
└── roots.py              # Arbitrary-precision arithmetic  

[Link to full write-up](https://docs.google.com/document/d/1hCx_eHPBH-sYVY0Ym51iir7rRGGr1V1UKNZgAFXsmHM/edit?usp=sharing)
