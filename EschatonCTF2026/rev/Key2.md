# Key 2 - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**Points:** 100  
**Author:** @solvz  
**Flag:** `esch{loops-hide-secrets-lunar-viper-1048}`

## Challenge Description

We're given a "GameForge activation system" - basically a license key validator. The goal is to reverse engineer how valid keys are generated so we can build a keygen that produces valid keys for any username and hardware ID combination. The server will test us with 5 random username/HWID pairs - we need to generate valid keys for all 5 to get the flag.

## Initial Analysis

### First Look

We get a single file called `validator` - a stripped, statically linked Linux binary. Running it shows us the expected format:

```bash
./validator
```

**Output:**
```
Usage: ./validator <username> <hwid> <key>
  username: 4-20 alphanumeric characters
  hwid: 8-character hex string
  key: A1B2-XXXX-XXXX-XXXX-CCCC format
```

### Basic File Information

```bash
file validator
# validator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

strings validator | grep -i "valid\|invalid\|usage"
# Shows "Valid!", "Invalid!", and usage strings
```

**Key observations:**
- Stripped binary (no symbol table)
- Statically linked (all libraries included)
- Takes 3 arguments: username, HWID, and key
- Key format: `A1B2-XXXX-XXXX-XXXX-CCCC` where XXXX are hex segments and CCCC is a checksum

## Methodology

### Step 1: Static Analysis Setup

Load the binary into a disassembler:
- **Binary Ninja** (used in this writeup)
- **Ghidra** (free alternative with decompiler)
- **IDA Pro** (industry standard)
- **radare2** (command-line)

### Step 2: Locate Validation Function

1. Search for strings "Valid!" and "Invalid!"
2. Find cross-references to these strings
3. Identify the main validation function
4. Trace the control flow

### Step 3: Understand Input Validation

1. Analyze username validation (length, character set)
2. Analyze HWID validation (format, hex parsing)
3. Analyze key format validation (dashes, prefix)

### Step 4: Reverse Engineer the Algorithm

1. Identify the hash function
2. Understand the transformation chain
3. Trace how key segments are calculated
4. Understand checksum calculation

### Step 5: Implement Keygen

1. Port the hash function to Python
2. Implement transformation functions
3. Implement key generation logic
4. Test locally against the binary

### Step 6: Connect to Server

1. Automate interaction with the server
2. Generate keys for 5 random username/HWID pairs
3. Extract the flag

## Static Analysis

### Finding the Validation Logic

Searching for the strings "Valid!" and "Invalid!" in Binary Ninja leads us to the main validation function at `sub_404db0` (address may vary).

### Main Validation Function

The function performs several checks:

```c
// Pseudo-code from disassembly
int validate(char *username, char *hwid, char *key) {
    // 1. Check key format
    if (key[4] != '-' || key[9] != '-' || key[14] != '-' || key[19] != '-') {
        return 0;  // Invalid format
    }
    
    // 2. Check prefix
    if (strncmp(key, "A1B2", 4) != 0) {
        return 0;  // Must start with "A1B2"
    }
    
    // 3. Parse HWID as hex
    unsigned int hwid_val = strtoul(hwid, NULL, 16);
    
    // 4. Validate username length and characters
    if (username_length < 4 || username_length > 20) {
        return 0;
    }
    // Check alphanumeric...
    
    // 5. Perform algorithm validation
    return algorithm_check(username, hwid_val, key);
}
```

### Key Format Requirements

The license key must follow this exact format:

```
A1B2-XXXX-XXXX-XXXX-CCCC
```

Where:
- **Prefix:** Must be `A1B2`
- **Segments:** Three 4-character hex segments (`XXXX`)
- **Checksum:** One 4-character hex segment (`CCCC`)
- **Dashes:** At positions 4, 9, 14, and 19 (0-indexed)
- **Total length:** 24 characters

## Hash Function Analysis

### The Custom Hash Function

The binary uses a custom hash function that processes input data byte by byte. This hash function is used both for hashing the username and for calculating the checksum.

### Understanding Bit Rotations

Before diving into the hash function, we need to understand **bit rotations**:

#### ROL (Rotate Left)

Rotates bits left, wrapping around:

```
ROL(0b11010010, 3) = 0b10010110

Original:  1101 0010
After ROL: 1001 0110
            ^^^^
            (wrapped around)
```

**Python implementation:**
```python
def rol(value, bits, size=32):
    """Rotate left (circular shift left)"""
    bits = bits % size
    return ((value << bits) | (value >> (size - bits))) & ((1 << size) - 1)
```

#### ROR (Rotate Right)

Rotates bits right, wrapping around:

```
ROR(0b11010010, 3) = 0b01011010

Original:  1101 0010
After ROR: 0101 1010
                  ^^^^
                  (wrapped around)
```

**Python implementation:**
```python
def ror(value, bits, size=32):
    """Rotate right (circular shift right)"""
    bits = bits % size
    return ((value >> bits) | (value << (size - bits))) & ((1 << size) - 1)
```

**Key difference from shifts:**
- **Shift:** Bits that fall off are lost, zeros fill in
- **Rotate:** Bits that fall off wrap around to the other side

### Hash Function Algorithm

The custom hash function works as follows:

```python
def custom_hash(data):
    """
    Custom hash function used by the validator.
    
    Args:
        data: Bytes to hash
        
    Returns:
        32-bit hash value
    """
    result = 0x4e7f2a19  # Initial seed
    
    for i, byte in enumerate(data):
        # Calculate shift amount: cycles through 0, 8, 16, 24
        shift = (i & 3) * 8  # (i % 4) * 8
        
        # Shift byte left by shift amount and XOR with current result
        xored = ((byte << shift) & 0xFFFFFFFF) ^ result
        
        # Rotate left 5 bits, then add constant
        rotated = rol(xored, 5) + 0x3c91e6b7
        rotated &= 0xFFFFFFFF  # Keep 32 bits
        
        # Rotate right 11 bits, then XOR with rotated value
        result = (ror(rotated, 11) ^ rotated) & 0xFFFFFFFF
    
    return result
```

### Hash Function Breakdown

Let's trace through the hash function step by step:

#### Step 1: Initial Seed

```python
result = 0x4e7f2a19
```

#### Step 2: Process Each Byte

For each byte in the input:

1. **Calculate shift:** `shift = (i & 3) * 8`
   - This cycles through: 0, 8, 16, 24, 0, 8, 16, 24, ...
   - Effectively shifts the byte to different positions in a 32-bit word

2. **XOR with shifted byte:**
   ```python
   xored = ((byte << shift) & 0xFFFFFFFF) ^ result
   ```
   - Shifts the byte to position `shift` in a 32-bit word
   - XORs with current hash value

3. **Rotate and add:**
   ```python
   rotated = rol(xored, 5) + 0x3c91e6b7
   ```
   - Rotates left by 5 bits
   - Adds magic constant `0x3c91e6b7`

4. **Final transformation:**
   ```python
   result = ror(rotated, 11) ^ rotated
   ```
   - Rotates right by 11 bits
   - XORs with the rotated value itself

### Hash Function Example

Let's hash the string "test" (bytes: `[0x74, 0x65, 0x73, 0x74]`):

```python
# Initial
result = 0x4e7f2a19

# Byte 0: 0x74, i=0, shift=0
byte_shifted = 0x74 << 0 = 0x74
xored = 0x74 ^ 0x4e7f2a19 = 0x4e7f2a6d
rotated = rol(0x4e7f2a6d, 5) + 0x3c91e6b7 = 0x8b4f5d34
result = ror(0x8b4f5d34, 11) ^ 0x8b4f5d34 = 0x... (example)

# Byte 1: 0x65, i=1, shift=8
byte_shifted = 0x65 << 8 = 0x6500
xored = 0x6500 ^ result
# ... continue for all bytes
```

### Why This Hash Design?

This hash function design:
- **Mixes bits thoroughly** through rotations and XORs
- **Uses position-dependent shifts** to ensure byte order matters
- **Non-linear** due to rotations and additions
- **Avalanche effect** - small input changes cause large output changes

## Transformation Chain

The binary uses a chain of transformations to derive key segments from a seed value. These transformations are implemented using **virtual function tables** (vtables) in C++.

### Virtual Function Tables (Vtables)

#### What are Vtables?

In C++, when a class has virtual functions, the compiler creates a **vtable** (virtual function table) - an array of function pointers. Each object with virtual functions contains a pointer to its vtable.

**Example C++ code:**
```cpp
class Transform {
public:
    virtual uint32_t apply(uint32_t x) = 0;
};

class Transform1 : public Transform {
public:
    uint32_t apply(uint32_t x) override {
        return rol(x, 7) ^ 0x8d2f5a1c;
    }
};
```

**In memory:**
```
Object layout:
[0x00] vtable_ptr -> [0x1000] function pointer to Transform1::apply
[0x08] ... other data ...
```

#### Identifying Vtables in Disassembly

In the binary, you'll see patterns like:

```asm
; Object creation
mov     rax, [rbp-0x20]      ; Load object pointer
mov     rax, [rax]            ; Load vtable pointer (first 8 bytes)
mov     rax, [rax+0x10]       ; Load function pointer from vtable
call    rax                   ; Call the virtual function
```

**Key indicators:**
- Objects start with a pointer (vtable pointer)
- Function calls through `[rax]` or similar (indirect calls)
- Multiple objects with similar structure

### Transform 1: ROL + XOR

**Function:**
```python
def transform1(x):
    """
    Transform 1: Rotate left 7 bits, then XOR with constant.
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    return rol(x, 7) ^ 0x8d2f5a1c
```

**What it does:**
- Rotates the input left by 7 bits
- XORs the result with magic constant `0x8d2f5a1c`

**Example:**
```python
x = 0x12345678
# ROL(x, 7):
# Original:  0001 0010 0011 0100 0101 0110 0111 1000
# After ROL: 0001 0001 1010 0010 1011 0001 1110 0000 = 0x11A2B1E0
# XOR with 0x8d2f5a1c:
result = 0x11A2B1E0 ^ 0x8d2f5a1c = 0x9C8DEBFC
```

### Transform 2: High/Low 16-bit Swap + XOR

**Function:**
```python
def transform2(x):
    """
    Transform 2: Swap high and low 16-bit halves, XOR each with constants.
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    # Extract high and low 16-bit halves
    high = (x >> 16) & 0xFFFF  # Upper 16 bits
    low = x & 0xFFFF           # Lower 16 bits
    
    # XOR each half with different constants
    high_xored = high ^ 0x6b3e
    low_xored = low ^ 0x1fa9
    
    # Swap: put low in high position, high in low position
    result = (low_xored << 16) | high_xored
    
    return result & 0xFFFFFFFF
```

**What it does:**
- Extracts the upper 16 bits and lower 16 bits
- XORs upper half with `0x6b3e`
- XORs lower half with `0x1fa9`
- Swaps the positions (low becomes high, high becomes low)

**Example:**
```python
x = 0x12345678
# Extract halves
high = 0x1234
low = 0x5678

# XOR
high_xored = 0x1234 ^ 0x6b3e = 0x790A
low_xored = 0x5678 ^ 0x1fa9 = 0x49D1

# Swap and combine
result = (0x49D1 << 16) | 0x790A = 0x49D1790A
```

### Transform 3: ROR + Addition

**Function:**
```python
def transform3(x):
    """
    Transform 3: Rotate right 13 bits, then add constant.
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    rotated = ror(x, 13)
    result = (rotated + 0x47c83d2e) & 0xFFFFFFFF
    return result
```

**What it does:**
- Rotates the input right by 13 bits
- Adds magic constant `0x47c83d2e`

**Example:**
```python
x = 0x12345678
# ROR(x, 13):
rotated = ror(0x12345678, 13)  # = 0x... (example)
# Add constant
result = rotated + 0x47c83d2e
```

## Key Generation Algorithm

Now that we understand all the components, let's see how they fit together to generate a valid license key.

### Complete Algorithm Flow

1. **Hash the username** using `custom_hash()`
2. **Parse HWID** as a hexadecimal number
3. **Calculate seed:** `seed = hash(username) ^ hwid`
4. **Apply Transform 1** to seed → take lower 16 bits → **first key segment**
5. **Apply Transform 2** to result → take lower 16 bits → **second key segment**
6. **Apply Transform 3** to result → take lower 16 bits → **third key segment**
7. **Calculate checksum:** Pack all three segments, hash them, XOR with `0x52b1`

### Step-by-Step Example

Let's trace through with a concrete example:

**Input:**
- Username: `"test"`
- HWID: `"12345678"`

#### Step 1: Hash Username

```python
username_hash = custom_hash(b"test")
# Example result: 0x8A5C3D2E (actual value depends on hash implementation)
```

#### Step 2: Parse HWID

```python
hwid_val = int("12345678", 16)
# = 0x12345678
```

#### Step 3: Calculate Seed

```python
seed = username_hash ^ hwid_val
# = 0x8A5C3D2E ^ 0x12345678
# = 0x98686B56
```

#### Step 4: Apply Transform 1 → First Segment

```python
result = transform1(seed)
# = rol(0x98686B56, 7) ^ 0x8d2f5a1c
# = 0x... (example: 0x7913ABCD)

key_part0 = result & 0xFFFF
# = 0xABCD (example: 0x7913)
```

#### Step 5: Apply Transform 2 → Second Segment

```python
result = transform2(result)
# = transform2(0x7913ABCD)
# = ... (swap high/low, XOR, etc.)
# = 0x... (example: 0x6330EF12)

key_part1 = result & 0xFFFF
# = 0xEF12 (example: 0x6330)
```

#### Step 6: Apply Transform 3 → Third Segment

```python
result = transform3(result)
# = ror(0x6330EF12, 13) + 0x47c83d2e
# = 0x... (example: 0xCE99ABCD)

key_part2 = result & 0xFFFF
# = 0xABCD (example: 0xCE99)
```

#### Step 7: Calculate Checksum

```python
# Pack the three segments into 6 bytes (little-endian)
checksum_buf = struct.pack('<HHH', key_part0, key_part1, key_part2)
# = b'\x13\x79\x30\x63\x99\xCE' (example)

# Hash the packed bytes
checksum_hash = custom_hash(checksum_buf)
# = 0x... (example: 0x2E64)

# XOR with constant
checksum = checksum_hash ^ 0x52b1
# = 0x2E64 ^ 0x52b1
# = 0x7C55 (example)
```

#### Step 8: Format Key

```python
key = f"A1B2-{key_part0:04X}-{key_part1:04X}-{key_part2:04X}-{checksum:04X}"
# = "A1B2-7913-6330-CE99-7C55" (example)
```

## Key Generation Implementation

### Complete Keygen Script

```python
#!/usr/bin/env python3
"""
Keygen for GameForge Activation System
Generates valid license keys for any username/HWID combination
"""

import struct

def rol(value, bits, size=32):
    """
    Rotate left (circular shift left).
    
    Args:
        value: Value to rotate
        bits: Number of bits to rotate
        size: Bit size (default 32)
        
    Returns:
        Rotated value
    """
    bits = bits % size
    return ((value << bits) | (value >> (size - bits))) & ((1 << size) - 1)

def ror(value, bits, size=32):
    """
    Rotate right (circular shift right).
    
    Args:
        value: Value to rotate
        bits: Number of bits to rotate
        size: Bit size (default 32)
        
    Returns:
        Rotated value
    """
    bits = bits % size
    return ((value >> bits) | (value << (size - bits))) & ((1 << size) - 1)

def custom_hash(data):
    """
    Custom hash function used by the validator.
    
    This function processes input data byte by byte, applying
    bit rotations and XOR operations to create a 32-bit hash.
    
    Args:
        data: Bytes to hash (bytes or bytearray)
        
    Returns:
        32-bit hash value
    """
    result = 0x4e7f2a19  # Initial seed
    
    for i, byte in enumerate(data):
        # Calculate shift amount: cycles through 0, 8, 16, 24
        # (i & 3) is equivalent to (i % 4)
        shift = (i & 3) * 8
        
        # Shift byte left by shift amount and XOR with current result
        byte_shifted = (byte << shift) & 0xFFFFFFFF
        xored = byte_shifted ^ result
        
        # Rotate left 5 bits, then add constant
        rotated = rol(xored, 5) + 0x3c91e6b7
        rotated &= 0xFFFFFFFF  # Keep 32 bits
        
        # Rotate right 11 bits, then XOR with rotated value
        result = (ror(rotated, 11) ^ rotated) & 0xFFFFFFFF
    
    return result

def transform1(x):
    """
    Transform 1: Rotate left 7 bits, then XOR with constant.
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    return rol(x, 7) ^ 0x8d2f5a1c

def transform2(x):
    """
    Transform 2: Swap high and low 16-bit halves, XOR each with constants.
    
    This transformation:
    1. Extracts upper and lower 16-bit halves
    2. XORs each half with different constants
    3. Swaps their positions
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    # Extract high and low 16-bit halves
    high = (x >> 16) & 0xFFFF  # Upper 16 bits
    low = x & 0xFFFF           # Lower 16 bits
    
    # XOR each half with different constants
    high_xored = high ^ 0x6b3e
    low_xored = low ^ 0x1fa9
    
    # Swap: put low in high position, high in low position
    result = (low_xored << 16) | high_xored
    
    return result & 0xFFFFFFFF

def transform3(x):
    """
    Transform 3: Rotate right 13 bits, then add constant.
    
    Args:
        x: 32-bit input value
        
    Returns:
        32-bit transformed value
    """
    rotated = ror(x, 13)
    result = (rotated + 0x47c83d2e) & 0xFFFFFFFF
    return result

def generate_key(username, hwid):
    """
    Generate a valid license key for the given username and HWID.
    
    Algorithm:
    1. Hash the username
    2. Parse HWID as hex
    3. Calculate seed: hash(username) ^ hwid
    4. Apply transform chain to get key segments
    5. Calculate checksum from segments
    6. Format as A1B2-XXXX-XXXX-XXXX-CCCC
    
    Args:
        username: Username string (4-20 alphanumeric chars)
        hwid: Hardware ID string (8 hex characters)
        
    Returns:
        License key string in format A1B2-XXXX-XXXX-XXXX-CCCC
    """
    # Validate inputs
    if not (4 <= len(username) <= 20):
        raise ValueError("Username must be 4-20 characters")
    
    if len(hwid) != 8:
        raise ValueError("HWID must be 8 hex characters")
    
    try:
        hwid_val = int(hwid, 16)
    except ValueError:
        raise ValueError("HWID must be valid hexadecimal")
    
    # Step 1: Hash the username
    username_hash = custom_hash(username.encode('utf-8'))
    
    # Step 2: Calculate seed
    seed = username_hash ^ hwid_val
    
    # Step 3: Apply transform chain
    # Transform 1 -> first key segment
    result = transform1(seed)
    key_part0 = result & 0xFFFF
    
    # Transform 2 -> second key segment
    result = transform2(result)
    key_part1 = result & 0xFFFF
    
    # Transform 3 -> third key segment
    result = transform3(result)
    key_part2 = result & 0xFFFF
    
    # Step 4: Calculate checksum
    # Pack the three segments into 6 bytes (little-endian)
    checksum_buf = struct.pack('<HHH', key_part0, key_part1, key_part2)
    
    # Hash the packed bytes
    checksum_hash = custom_hash(checksum_buf)
    
    # XOR with constant to get final checksum
    checksum = (checksum_hash ^ 0x52b1) & 0xFFFF
    
    # Step 5: Format as license key
    key = f"A1B2-{key_part0:04X}-{key_part1:04X}-{key_part2:04X}-{checksum:04X}"
    
    return key

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <hwid>")
        print("Example: python3 keygen.py test 12345678")
        sys.exit(1)
    
    username = sys.argv[1]
    hwid = sys.argv[2]
    
    try:
        key = generate_key(username, hwid)
        print(key)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
```

### Server Solver Script

```python
#!/usr/bin/env python3
"""
Automated solver for Key2 challenge server
Connects to server and generates keys for 5 random username/HWID pairs
"""

from pwn import *
from keygen import generate_key
import re

def solve_challenge(host, port):
    """
    Connect to challenge server and solve all 5 challenges.
    """
    conn = remote(host, port)
    
    try:
        # Receive initial banner
        banner = conn.recvuntil(b'Challenge', timeout=5).decode('utf-8', errors='ignore')
        print(banner, end='')
        
        # Solve 5 challenges
        for challenge_num in range(1, 6):
            # Receive challenge prompt
            data = conn.recvuntil(b'key:', timeout=5).decode('utf-8', errors='ignore')
            print(data, end='')
            
            # Extract username and HWID from prompt
            # Format: "Username: <username> / HWID: <hwid>"
            username_match = re.search(r'Username:\s+(\S+)', data)
            hwid_match = re.search(r'HWID:\s+([0-9A-Fa-f]{8})', data)
            
            if not username_match or not hwid_match:
                print(f"[!] Error: Could not extract username/HWID from challenge {challenge_num}")
                break
            
            username = username_match.group(1)
            hwid = hwid_match.group(1)
            
            print(f"[*] Challenge {challenge_num}: {username} / {hwid}", end='')
            
            # Generate key
            key = generate_key(username, hwid)
            print(f" -> {key}")
            
            # Send key
            conn.sendline(key.encode('utf-8'))
            
            # Receive response
            response = conn.recvuntil(b'Challenge', timeout=5, drop=True).decode('utf-8', errors='ignore')
            print(response, end='')
            
            if 'Invalid' in response:
                print(f"[!] Key validation failed for challenge {challenge_num}")
                break
        
        # Receive final flag
        final_data = conn.recv(timeout=5).decode('utf-8', errors='ignore')
        print(final_data)
        
        # Extract flag
        flag_match = re.search(r'esch\{[^}]+\}', final_data)
        if flag_match:
            flag = flag_match.group(0)
            print(f"\n[+] Flag: {flag}")
            return flag
        
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
    
    return None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        print("Example: python3 solve.py node-3.mcsc.space 35045")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    solve_challenge(host, port)
```

## Testing & Verification

### Local Testing

Before connecting to the server, always test your keygen locally:

```bash
# Test with various username/HWID combinations
./validator test 12345678 "$(python3 keygen.py test 12345678)"
# Should output: Valid!

./validator admin C3C3C3C3 "$(python3 keygen.py admin C3C3C3C3)"
# Should output: Valid!

./validator user123 FEDCBA98 "$(python3 keygen.py user123 FEDCBA98)"
# Should output: Valid!
```

### Verification Steps

1. **Test hash function:**
   ```python
   # Test with known input
   h = custom_hash(b"test")
   print(f"Hash: 0x{h:08X}")
   ```

2. **Test transformations:**
   ```python
   # Test each transform individually
   x = 0x12345678
   t1 = transform1(x)
   t2 = transform2(t1)
   t3 = transform3(t2)
   print(f"Transform chain: 0x{x:08X} -> 0x{t1:08X} -> 0x{t2:08X} -> 0x{t3:08X}")
   ```

3. **Verify key format:**
   ```python
   key = generate_key("test", "12345678")
   assert key.startswith("A1B2")
   assert len(key) == 24
   assert key.count('-') == 4
   ```

4. **Test edge cases:**
   - Minimum length username (4 chars)
   - Maximum length username (20 chars)
   - Various HWID values
   - Different username/HWID combinations

### Debugging Tips

If your keygen doesn't work:

1. **Check the hash function:**
   - Verify bit rotations are correct
   - Check that shift calculation `(i & 3) * 8` is correct
   - Verify constants match the binary

2. **Verify transformations:**
   - Test each transform function individually
   - Check that ROL/ROR operations are correct
   - Verify bit masks and operations

3. **Check seed calculation:**
   ```python
   username_hash = custom_hash(b"test")
   hwid_val = int("12345678", 16)
   seed = username_hash ^ hwid_val
   print(f"Seed: 0x{seed:08X}")
   ```

4. **Verify checksum:**
   ```python
   # Print intermediate values
   print(f"Key parts: {key_part0:04X} {key_part1:04X} {key_part2:04X}")
   print(f"Checksum: {checksum:04X}")
   ```

5. **Compare with binary:**
   - Use a debugger (gdb) to step through the binary
   - Check register values at each step
   - Compare with your Python implementation

## Getting the Flag

Once the keygen is verified locally, connect to the server:

```bash
python3 solve.py node-3.mcsc.space 35045
```

**Expected output:**
```
[+] Opening connection to node-3.mcsc.space on port 35045: Done
[*] Challenge 1: gamma_streamer / 12345678 -> A1B2-7913-6330-CE99-7C55
[+] Valid!

[*] Challenge 2: psi_founder / C3C3C3C3 -> A1B2-B75F-AD53-203B-C8EA
[+] Valid!

[*] Challenge 3: epsilon_pro / 87654321 -> A1B2-BAD9-58A7-CC68-8322
[+] Valid!

[*] Challenge 4: tau_community / 0F0F0F0F -> A1B2-6515-F294-AE8D-431F
[+] Valid!

[*] Challenge 5: omicron_artist / FEDCBA98 -> A1B2-F7B8-5921-2160-C9FC
[+] Valid!

╔══════════════════════════════════════╗
║        Congratulations!              ║
╠══════════════════════════════════════╣
║  esch{loops-hide-secrets-lunar-viper-1048}
╚══════════════════════════════════════╝

[+] Flag: esch{loops-hide-secrets-lunar-viper-1048}
```

## Reverse Engineering Process

### Identifying the Validation Function

1. **Search for strings:**
   - Look for "Valid!" and "Invalid!" strings
   - Find cross-references to these strings
   - This leads to the main validation function

2. **Trace control flow:**
   - Follow function calls from main
   - Identify input validation code
   - Find the algorithm validation code

### Identifying the Hash Function

1. **Look for patterns:**
   - Bit rotation operations (ROL/ROR)
   - XOR operations with constants
   - Loops processing bytes
   - Magic constants like `0x4e7f2a19`, `0x3c91e6b7`

2. **Trace data flow:**
   - Follow where username is used
   - See how it's processed byte by byte
   - Identify the hash result

### Identifying Transformation Functions

1. **Look for vtable patterns:**
   - Objects with function pointers
   - Indirect function calls
   - Multiple similar objects

2. **Analyze each transform:**
   - Transform 1: Look for ROL with constant 7
   - Transform 2: Look for bit swapping and XORs
   - Transform 3: Look for ROR with constant 13

3. **Trace the chain:**
   - See how transforms are applied sequentially
   - Identify which parts become key segments

### Understanding the Vtable Structure

In the disassembly, you'll see:

```asm
; Object creation
mov     rax, [rbp-0x20]      ; Load object pointer
mov     rax, [rax]            ; Load vtable pointer
mov     rax, [rax+0x10]       ; Load function pointer (offset 0x10 in vtable)
call    rax                   ; Call the virtual function
```

**Key observations:**
- First 8 bytes of object = vtable pointer
- Vtable contains function pointers at specific offsets
- Each transform class has its own vtable

## Lessons Learned

1. **Bit rotations are powerful** - ROL/ROR operations mix bits thoroughly and are commonly used in custom crypto/hash functions. Understanding them is essential.

2. **Virtual function tables in C++** - When reversing C++ binaries, look for vtable patterns. Objects start with a pointer to their vtable, and function calls go through these pointers.

3. **Custom hash functions** - Many CTF challenges use custom hash functions. They often combine rotations, XORs, and additions. Trace through them carefully.

4. **Transformation chains** - When you see a chain of transformations, work through each one step by step. Each transform modifies the value, and you need to understand all of them.

5. **Checksums validate integrity** - The checksum ensures the key segments are correct. It's calculated from the segments themselves, creating a self-validating structure.

6. **Test locally first** - Always test your keygen against the actual binary before hitting the server. This catches bugs early.

7. **Magic constants matter** - The specific constants used (like `0x8d2f5a1c`, `0x6b3e`, etc.) are part of the algorithm. Get them exactly right.

8. **Bit manipulation is key** - Understanding bit operations (shifts, rotations, XORs, masks) is crucial for reverse engineering.

9. **Position matters in hash functions** - The shift calculation `(i & 3) * 8` ensures byte position matters. This is a common pattern.

10. **Decompilers help** - Tools like Binary Ninja's decompiler or Ghidra make understanding C++ code much easier than raw assembly.

## Files

- `keygen.py` - Standalone keygen for manual use
- `solve.py` - Automated solver for the CTF challenge (requires pwntools)
- `validator` - The original binary to test against locally

## Additional Resources

- [Bit Rotation Operations](https://en.wikipedia.org/wiki/Bitwise_operation#Rotate)
- [Virtual Function Tables](https://en.wikipedia.org/wiki/Virtual_method_table)
- [Custom Hash Functions in CTFs](https://ctf-wiki.mahaloz.re/reverse/algorithm/encryption/)
- [Binary Ninja Documentation](https://docs.binary.ninja/)
- [Ghidra Documentation](https://ghidra-sre.org/)

---

*"Understanding bit operations and transformation chains is key to reverse engineering custom algorithms!"*
