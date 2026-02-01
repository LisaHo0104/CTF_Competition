# Key 3 - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**Points:** 480  
**Author:** @solvz  
**Flag:** `esch{conditions-drive-paths-shadow-shadow-8997}`

## Challenge Description

EnterpriseCore's premium licensing system uses a complex method for key generation. Reverse engineer the binary to build a keygen that works for any parameters. The server will test us with 5 random username/HWID/timestamp/tier combinations - we need to generate valid keys for all 5 to get the flag.

## TL;DR

Stripped Rust binary that validates license keys. The key derivation is: SHA-256 a blob of inputs, pull four 32-bit words out of the hash (little-endian!), CRC32 the hardware ID, then run everything through an 8-round Feistel-like mixing network. One endianness gotcha is the entire challenge.

## Initial Analysis

### First Look

We get a single binary (`validator`) and a remote service that asks us to generate 5 valid keys in a row.

```bash
file validator
# validator: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

./validator
# Usage: ./validator <username> <hwid> <timestamp> <tier> <key>
```

**Key observations:**
- **Stripped binary** - No symbol table
- **PIE (Position Independent Executable)** - Addresses are randomized
- **Dynamically linked** - Uses system libraries
- **Compiled from Rust** - Visible in embedded strings and panic paths referencing `src/validator.rs`

### Basic File Information

```bash
strings validator | grep -i "valid\|invalid\|usage\|KGIII"
# Shows "Valid!", "Invalid!", usage strings, and "KGIII" prefix
```

The key format is visible in the strings:

```
KGIII-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-YYYY
```

Where:
- **Prefix:** `KGIII-`
- **Segments:** Four 8-character hex groups (`XXXXXXXX`)
- **Tier suffix:** `YYYY` - one of:
  - `BRNZ` (tier 1 - Bronze)
  - `SLVR` (tier 2 - Silver)
  - `GOLD` (tier 3 - Gold)

## Methodology

### Step 1: Static Analysis Setup

Load the binary into a disassembler:
- **Binary Ninja** (used in this writeup)
- **Ghidra** (free alternative with decompiler)
- **IDA Pro** (industry standard)
- **radare2** (command-line)

### Step 2: Identify Rust Binary Characteristics

Rust binaries have distinctive characteristics:
- Panic messages referencing source files (`src/validator.rs`)
- String formatting functions (`core::fmt`)
- Memory safety checks
- Standard library functions

### Step 3: Locate Validation Function

1. Search for strings "Valid!" and "Invalid!"
2. Find cross-references to these strings
3. Identify the main validation function
4. Trace the control flow

### Step 4: Understand Input Validation

1. Analyze username validation (length, character set)
2. Analyze HWID validation (format, hex parsing)
3. Analyze timestamp validation (time range)
4. Analyze tier validation (1, 2, or 3)
5. Analyze key format validation

### Step 5: Reverse Engineer the Algorithm

1. Identify the hash function (SHA-256)
2. Understand how the input buffer is constructed
3. Understand hash word extraction
4. Identify CRC32 calculation
5. Understand the mixing network (Feistel-like structure)
6. Trace through all 8 rounds

### Step 6: Implement Keygen

1. Port the algorithm to Python
2. Handle endianness correctly
3. Test locally against the binary
4. Verify with multiple inputs

### Step 7: Connect to Server

1. Automate interaction with the server
2. Generate keys for 5 random combinations
3. Extract the flag

## Static Analysis

### Finding the Validation Logic

Searching for the strings "Valid!" and "Invalid!" in Binary Ninja leads us to the main validation function. In a stripped binary, this might be at an address like `0x402480` (addresses vary due to PIE).

### Identifying Rust Binaries

Rust binaries have several telltale signs:

1. **Panic messages:**
   ```
   thread 'main' panicked at '...', src/validator.rs:XX:XX
   ```

2. **String formatting:**
   - References to `core::fmt`
   - Format string handling

3. **Memory safety:**
   - Bounds checking
   - Option/Result handling

4. **Standard library:**
   - `std::` namespace functions
   - Rust-specific calling conventions

## Input Validation

The main validation function performs several sanity checks before running the algorithm:

### Username Validation

```c
// Pseudo-code from disassembly
if (username_length < 4 || username_length > 32) {
    return 0;  // Invalid
}

for (each character in username) {
    if (!isprint(c)) {  // Not printable ASCII
        return 0;  // Invalid
    }
}
```

**Rules:**
- Length: 4-32 characters
- Characters: Printable ASCII only

### HWID Validation

```c
// Pseudo-code
if (hwid_length != 16) {
    return 0;  // Invalid - must be exactly 16 hex characters
}

// Uppercase the HWID
hwid_upper = toupper(hwid);

// Parse as hex to 8 raw bytes
hwid_bytes = parse_hex(hwid_upper);
```

**Rules:**
- Length: Exactly 16 hexadecimal characters
- Case: Converted to uppercase internally
- Parsing: Converted to 8 raw bytes (not kept as hex string)

**Example:**
```
HWID: "ABCDEF0123456789"
Parsed: [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]
```

### Timestamp Validation

```c
// Pseudo-code
current_time = time(NULL);
timestamp = parse_int(timestamp_str);

if (abs(timestamp - current_time) > 86400) {
    return 0;  // Invalid - must be within 24 hours
}
```

**Rules:**
- Must be a valid integer
- Must be within 86400 seconds (~24 hours) of current system time
- This prevents using old keys indefinitely

### Tier Validation

```c
// Pseudo-code
tier = parse_int(tier_str);

if (tier < 1 || tier > 3) {
    return 0;  // Invalid
}
```

**Rules:**
- Must be 1, 2, or 3
- Corresponds to tier suffixes: BRNZ, SLVR, GOLD

### Key Format Validation

```c
// Pseudo-code
if (key_length != 46) {
    return 0;  // Invalid
}

if (strncmp(key, "KGIII-", 6) != 0) {
    return 0;  // Invalid - must start with "KGIII-"
}

// Check dashes at positions 6, 15, 24, 33
if (key[6] != '-' || key[15] != '-' || key[33] != '-' || key[42] != '-') {
    return 0;  // Invalid format
}

// Check tier suffix
tier_suffix = key + 43;  // Last 4 characters
if (tier == 1 && strcmp(tier_suffix, "BRNZ") != 0) return 0;
if (tier == 2 && strcmp(tier_suffix, "SLVR") != 0) return 0;
if (tier == 3 && strcmp(tier_suffix, "GOLD") != 0) return 0;

// Parse four hex groups as 32-bit integers
key1 = parse_hex_u32(key + 6);   // First 8 hex chars
key2 = parse_hex_u32(key + 15);  // Second 8 hex chars
key3 = parse_hex_u32(key + 24);  // Third 8 hex chars
key4 = parse_hex_u32(key + 33);   // Fourth 8 hex chars
```

**Format:**
```
KGIII-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-YYYY
       ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^
       key1    key2     key3     key4     tier
```

## Hash Function Analysis

### SHA-256 Hash Construction

The binary constructs an input buffer and computes its SHA-256 hash. This hash is the foundation of the key generation algorithm.

### Input Buffer Construction

The input buffer is constructed by concatenating:

```
SHA-256( username_bytes || hwid_parsed_bytes || le64(timestamp) || u8(tier) )
```

**Where:**
- `username_bytes` - The username as raw bytes (UTF-8)
- `hwid_parsed_bytes` - The 8 raw bytes from parsing the hex HWID string (NOT the ASCII hex string itself!)
- `le64(timestamp)` - The timestamp packed as a little-endian 64-bit integer
- `u8(tier)` - The tier as a single byte (1, 2, or 3)

**Important notes:**
1. **HWID is parsed, not used as string** - The hex string "ABCDEF0123456789" becomes 8 bytes: `[0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]`
2. **Timestamp is little-endian** - On x86, this is native byte order
3. **Tier is a single byte** - Not a string, not a 32-bit integer

### Example Input Buffer

Let's construct an example:

**Inputs:**
- Username: `"testuser"` → `[0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72]`
- HWID: `"ABCDEF0123456789"` → `[0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]`
- Timestamp: `1769889821` → `[0x9D, 0x7A, 0x8C, 0x69, 0x00, 0x00, 0x00, 0x00]` (little-endian)
- Tier: `1` → `[0x01]`

**Complete buffer:**
```
[0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72,  # "testuser"
 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,  # HWID bytes
 0x9D, 0x7A, 0x8C, 0x69, 0x00, 0x00, 0x00, 0x00,  # timestamp (le64)
 0x01]                                              # tier
```

**Python code:**
```python
import hashlib
import struct

username = b"testuser"
hwid_hex = "ABCDEF0123456789"
hwid_bytes = bytes.fromhex(hwid_hex)  # Parse hex to bytes
timestamp = 1769889821
tier = 1

# Construct input buffer
input_buffer = (
    username +
    hwid_bytes +
    struct.pack('<Q', timestamp) +  # Little-endian 64-bit
    struct.pack('B', tier)            # Single byte
)

# Compute SHA-256
sha256_hash = hashlib.sha256(input_buffer).digest()
```

### Hash Word Extraction

From the first 16 bytes of the SHA-256 output, four 32-bit words are extracted:

```python
# Extract four 32-bit words (LITTLE-ENDIAN!)
h0 = struct.unpack('<I', sha256_hash[0:4])[0]   # Bytes 0-3
h1 = struct.unpack('<I', sha256_hash[4:8])[0]   # Bytes 4-7
h2 = struct.unpack('<I', sha256_hash[8:12])[0]  # Bytes 8-11
h3 = struct.unpack('<I', sha256_hash[12:16])[0] # Bytes 12-15
```

**Critical:** The words are read as **little-endian** (native x86 byte order), not big-endian!

**Visual example:**
```
SHA-256 output (first 16 bytes):
[0x04, 0x2D, 0xEF, 0xC2, 0x67, 0x8C, 0x57, 0x19, 0x36, 0x79, 0x91, 0x86, 0x9C, 0x20, 0x2F, 0x2B]

Reading as little-endian 32-bit words:
h0 = 0xC2EF2D04  (bytes 0-3: [0x04, 0x2D, 0xEF, 0xC2] read as <I)
h1 = 0x19578C67  (bytes 4-7: [0x67, 0x8C, 0x57, 0x19] read as <I)
h2 = 0x86917936  (bytes 8-11: [0x36, 0x79, 0x91, 0x86] read as <I)
h3 = 0x2B2F209C  (bytes 12-15: [0x9C, 0x20, 0x2F, 0x2B] read as <I)
```

**If you read as big-endian (WRONG):**
```python
h0 = struct.unpack('>I', sha256_hash[0:4])[0]  # WRONG!
# Would give: 0x042DEFC2 (different value!)
```

## CRC32 Analysis

### What is CRC32?

**CRC (Cyclic Redundancy Check)** is an error-detecting code commonly used in digital networks and storage devices. CRC32 uses a 32-bit polynomial to compute a checksum.

### IEEE 802.3 Polynomial

The binary uses the **IEEE 802.3 polynomial** (also known as CRC-32-IEEE):

```
Polynomial: 0x04C11DB7
```

This is the standard polynomial used in Ethernet, ZIP files, and many other applications.

### CRC32 Calculation

The binary computes CRC32 over the **8 parsed HWID bytes** (not the hex string):

```python
import zlib

hwid_hex = "ABCDEF0123456789"
hwid_bytes = bytes.fromhex(hwid_hex)  # [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]

crc = zlib.crc32(hwid_bytes) & 0xFFFFFFFF
# Result: 0x9fb3d300 (example)
```

**Important:**
- CRC32 is computed over the **raw bytes**, not the hex string
- The result is a 32-bit value
- Python's `zlib.crc32` uses the IEEE 802.3 polynomial by default

### PCLMULQDQ Acceleration

The binary may use `PCLMULQDQ` (carry-less multiplication) CPU instructions for faster CRC32 computation on supported hardware. This is an optimization but doesn't change the result - the algorithm is the same.

**For our keygen:**
- We can use Python's `zlib.crc32` which produces the same result
- No need to worry about hardware acceleration

## Feistel Network Analysis

### What is a Feistel Network?

A **Feistel network** is a symmetric structure used in block ciphers. It splits the input into two halves and processes them through multiple rounds, with each round using a "round function" that operates on one half and is XORed with the other half.

**Basic Feistel structure:**
```
Round i:
  L_i = R_{i-1}
  R_i = L_{i-1} XOR F(R_{i-1}, K_i)
```

Where `F` is the round function and `K_i` is the round key.

### Why "Feistel-like"?

This challenge's mixing network is **Feistel-like** but not a pure Feistel network because:
- It doesn't strictly split into two halves that swap
- It uses more complex operations (rotations, additions, subtractions)
- It has more than two state variables
- The round function is more complex

However, it shares the Feistel characteristic of:
- Multiple rounds
- Each round builds on the previous
- Complex mixing of values

### The 8-Round Mixing Network

The algorithm mixes the hash words (`h0`, `h1`, `h2`, `h3`) and CRC32 value (`c`) through 8 rounds using:
- `rol32()` - Rotate left by N bits
- XOR with magic constant `0x5f8c2e7a`
- Additions and subtractions mod 2^32

### Magic Constant

The constant `0x5f8c2e7a` is XORed at specific points in the algorithm. This is a common technique in cryptographic algorithms to add non-linearity and break patterns.

### Round-Dependent CRC Rotations

The CRC value `c` gets rotated by incrementing multiples of 3 throughout the rounds:
- Round 1: `rol32(c, 3)`
- Round 2: `rol32(c, 6)`
- Round 3: `rol32(c, 9)`
- Round 4: `rol32(c, 12)`
- Round 5: `rol32(c, 15)`
- Round 6: `rol32(c, 18)`
- Round 7: `rol32(c, 21)`

This creates round-dependent "tweaks" that ensure each round is different.

### Complete Algorithm

Here's the full algorithm, round by round:

```python
MAGIC = 0x5f8c2e7a

# Setup: Extract hash words and compute CRC
h0, h1, h2, h3 = extract_hash_words(sha256_hash)
c = crc32(hwid_bytes)

# Initial setup
a = h0 ^ c
b = h1 + a

# Round 1
b4 = rol32(b, 4) ^ h2
x1 = b4 ^ MAGIC
c3 = rol32(c, 3)
y1 = x1 ^ c3
d = ((h3 - x1) ^ a) + y1
d4 = rol32(d, 4) ^ a

# Round 2
x2 = d4 ^ MAGIC
c6 = rol32(c, 6)
y2 = x2 ^ c6
e = ((rol32(b, 25) - x2) ^ y1) + y2

# Round 3
f1 = c3 ^ b4 ^ rol32(e, 4)
c9 = rol32(c, 9)
g1 = c9 ^ f1
h_val = ((rol32(d, 25) - f1) ^ y2) + g1

# Round 4
f2 = c6 ^ d4 ^ rol32(h_val, 4)
c12 = rol32(c, 12)
g2 = c12 ^ f2
j = ((rol32(e, 25) - f2) ^ g1) + g2

# Round 5
j4 = rol32(j, 4) ^ g1
x5 = j4 ^ MAGIC
c15 = rol32(c, 15)
y5 = x5 ^ c15
k = ((rol32(h_val, 25) - x5) ^ g2) + y5

# Round 6
k4 = rol32(k, 4) ^ g2
x6 = k4 ^ MAGIC
c18 = rol32(c, 18)
y6 = x6 ^ c18
m = ((rol32(j, 25) - x6) ^ y5) + y6

# Round 7
f7 = c15 ^ j4 ^ rol32(m, 4)
c21 = rol32(c, 21)
n = c21 ^ f7
p = ((rol32(k, 25) - f7) ^ y6) + n

# Round 8
r_val = c18 ^ k4 ^ rol32(p, 4)

# Final key parts
key1 = r_val
key2 = (rol32(m, 25) - r_val) ^ n
key3 = n
key4 = rol32(p, 25)
```

### Step-by-Step Example

Let's trace through with concrete values (simplified for clarity):

**Inputs:**
- Username: `"testuser"`
- HWID: `"ABCDEF0123456789"`
- Timestamp: `1769889821`
- Tier: `1`

**Step 1: Compute SHA-256**
```python
input_buffer = b"testuser" + bytes.fromhex("ABCDEF0123456789") + struct.pack('<Q', 1769889821) + b'\x01'
sha256_hash = hashlib.sha256(input_buffer).digest()

# Extract words (little-endian!)
h0 = struct.unpack('<I', sha256_hash[0:4])[0]   # Example: 0xC2EF2D04
h1 = struct.unpack('<I', sha256_hash[4:8])[0]   # Example: 0x19578C67
h2 = struct.unpack('<I', sha256_hash[8:12])[0]  # Example: 0x86917936
h3 = struct.unpack('<I', sha256_hash[12:16])[0] # Example: 0x2B2F209C
```

**Step 2: Compute CRC32**
```python
hwid_bytes = bytes.fromhex("ABCDEF0123456789")
c = zlib.crc32(hwid_bytes) & 0xFFFFFFFF  # Example: 0x9fb3d300
```

**Step 3: Initial Setup**
```python
a = h0 ^ c  # 0xC2EF2D04 ^ 0x9fb3d300 = 0x5D5CFE04
b = h1 + a  # 0x19578C67 + 0x5D5CFE04 = 0x76B48A6B
```

**Step 4: Round 1**
```python
b4 = rol32(b, 4) ^ h2      # rol32(0x76B48A6B, 4) ^ 0x86917936 = ...
x1 = b4 ^ MAGIC            # ... ^ 0x5f8c2e7a = ...
c3 = rol32(c, 3)           # rol32(0x9fb3d300, 3) = ...
y1 = x1 ^ c3               # ...
d = ((h3 - x1) ^ a) + y1   # ...
d4 = rol32(d, 4) ^ a       # ...
```

Continue through all 8 rounds...

**Step 5: Final Key Parts**
```python
key1 = r_val
key2 = (rol32(m, 25) - r_val) ^ n
key3 = n
key4 = rol32(p, 25)
```

**Step 6: Format Key**
```python
tier_suffix = ["BRNZ", "SLVR", "GOLD"][tier - 1]
key = f"KGIII-{key1:08X}-{key2:08X}-{key3:08X}-{key4:08X}-{tier_suffix}"
```

## Endianness Deep Dive

### What is Endianness?

**Endianness** refers to the byte order used to store multi-byte values in memory:

- **Little-endian:** Least significant byte first (used by x86/x64)
- **Big-endian:** Most significant byte first (used by some network protocols, older architectures)

**Example:**
```
Value: 0x12345678

Little-endian (x86): [0x78, 0x56, 0x34, 0x12]
Big-endian:           [0x12, 0x34, 0x56, 0x78]
```

### Why x86 is Little-Endian

x86 and x86-64 architectures use **little-endian** byte order. This means:
- When you read a 32-bit integer from memory, the bytes are read in little-endian order
- `struct.unpack('<I', ...)` matches native x86 behavior
- `struct.unpack('>I', ...)` would give wrong results on x86

### The Endianness Bug

The critical bug in the initial keygen was reading the SHA-256 hash words as **big-endian** instead of **little-endian**.

**Wrong (big-endian):**
```python
h0 = struct.unpack('>I', sha256_hash[0:4])[0]  # WRONG!
```

**Correct (little-endian):**
```python
h0 = struct.unpack('<I', sha256_hash[0:4])[0]  # CORRECT!
```

### Debugging Table

Here's the comparison that revealed the bug:

| Word | Python (big-endian) | Binary (little-endian) | Bytes (for reference) |
|------|---------------------|------------------------|----------------------|
| h0   | `0x042DEFC2`       | `0xC2EF2D04`          | `[0x04, 0x2D, 0xEF, 0xC2]` |
| h1   | `0x678C5719`       | `0x19578C67`          | `[0x67, 0x8C, 0x57, 0x19]` |
| h2   | `0x36799186`       | `0x86917936`          | `[0x36, 0x79, 0x91, 0x86]` |
| h3   | `0x9C202F2B`       | `0x2B2F209C`          | `[0x9C, 0x20, 0x2F, 0x2B]` |

**Observation:**
- Same bytes, opposite read order
- The CRC32 result matched perfectly (confirmed HWID parsing was correct)
- Pure endianness issue

### How to Identify Endianness Issues

1. **Check platform:** x86/x64 = little-endian
2. **Compare values:** If your values are byte-reversed, it's likely endianness
3. **Use GDB:** Set breakpoints and compare register values
4. **Test with known input:** Use a simple test case and trace through

### Verifying with GDB

```bash
# Set breakpoint before CRC32 call
gdb ./validator
(gdb) break *0x402480  # Address of validation function
(gdb) run testuser ABCDEF0123456789 1769889821 1 KGIII-00000000-00000000-00000000-00000000-BRNZ

# When breakpoint hits, inspect registers
(gdb) x/4x $rax  # First 16 bytes of SHA-256 (if in register)
(gdb) print/x $eax  # First 32-bit word (h0)
```

Compare with your Python output to identify endianness issues.

## Key Generation Implementation

### Complete Keygen Script

```python
#!/usr/bin/env python3
"""
Keygen for EnterpriseCore Premium Licensing System
Generates valid license keys for any username/HWID/timestamp/tier combination
"""

import hashlib
import struct
import zlib

def rol32(value, bits):
    """
    Rotate left 32-bit value.
    
    Args:
        value: 32-bit value to rotate
        bits: Number of bits to rotate left
        
    Returns:
        Rotated 32-bit value
    """
    bits = bits % 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

def extract_hash_words(sha256_hash):
    """
    Extract four 32-bit words from SHA-256 hash (LITTLE-ENDIAN!).
    
    Args:
        sha256_hash: 16 bytes from SHA-256 output
        
    Returns:
        Tuple of (h0, h1, h2, h3) as 32-bit integers
    """
    h0 = struct.unpack('<I', sha256_hash[0:4])[0]   # Bytes 0-3
    h1 = struct.unpack('<I', sha256_hash[4:8])[0]   # Bytes 4-7
    h2 = struct.unpack('<I', sha256_hash[8:12])[0]  # Bytes 8-11
    h3 = struct.unpack('<I', sha256_hash[12:16])[0] # Bytes 12-15
    return h0, h1, h2, h3

def generate_key(username, hwid, timestamp, tier):
    """
    Generate a valid license key.
    
    Algorithm:
    1. Construct input buffer: username || hwid_bytes || timestamp_le64 || tier_u8
    2. SHA-256 hash the buffer
    3. Extract 4 words from hash (little-endian)
    4. CRC32 the HWID bytes
    5. Run through 8-round Feistel-like mixing network
    6. Format as KGIII-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-YYYY
    
    Args:
        username: Username string (4-32 printable ASCII)
        hwid: Hardware ID string (16 hex characters)
        timestamp: Unix timestamp (integer)
        tier: Tier number (1, 2, or 3)
        
    Returns:
        License key string
    """
    # Validate inputs
    if not (4 <= len(username) <= 32):
        raise ValueError("Username must be 4-32 characters")
    
    if len(hwid) != 16:
        raise ValueError("HWID must be 16 hex characters")
    
    if tier not in [1, 2, 3]:
        raise ValueError("Tier must be 1, 2, or 3")
    
    # Parse HWID to bytes (uppercase first)
    hwid_upper = hwid.upper()
    try:
        hwid_bytes = bytes.fromhex(hwid_upper)
    except ValueError:
        raise ValueError("HWID must be valid hexadecimal")
    
    # Step 1: Construct input buffer
    username_bytes = username.encode('utf-8')
    timestamp_le64 = struct.pack('<Q', timestamp)  # Little-endian 64-bit
    tier_u8 = struct.pack('B', tier)                # Single byte
    
    input_buffer = username_bytes + hwid_bytes + timestamp_le64 + tier_u8
    
    # Step 2: SHA-256 hash
    sha256_hash = hashlib.sha256(input_buffer).digest()
    
    # Step 3: Extract hash words (LITTLE-ENDIAN!)
    h0, h1, h2, h3 = extract_hash_words(sha256_hash[:16])
    
    # Step 4: CRC32 of HWID bytes
    c = zlib.crc32(hwid_bytes) & 0xFFFFFFFF
    
    # Step 5: 8-round Feistel-like mixing network
    MAGIC = 0x5f8c2e7a
    
    # Setup
    a = h0 ^ c
    b = h1 + a
    b &= 0xFFFFFFFF  # Keep 32 bits
    
    # Round 1
    b4 = rol32(b, 4) ^ h2
    x1 = b4 ^ MAGIC
    c3 = rol32(c, 3)
    y1 = x1 ^ c3
    d = ((h3 - x1) ^ a) + y1
    d &= 0xFFFFFFFF
    d4 = rol32(d, 4) ^ a
    
    # Round 2
    x2 = d4 ^ MAGIC
    c6 = rol32(c, 6)
    y2 = x2 ^ c6
    e = ((rol32(b, 25) - x2) ^ y1) + y2
    e &= 0xFFFFFFFF
    
    # Round 3
    f1 = c3 ^ b4 ^ rol32(e, 4)
    c9 = rol32(c, 9)
    g1 = c9 ^ f1
    h_val = ((rol32(d, 25) - f1) ^ y2) + g1
    h_val &= 0xFFFFFFFF
    
    # Round 4
    f2 = c6 ^ d4 ^ rol32(h_val, 4)
    c12 = rol32(c, 12)
    g2 = c12 ^ f2
    j = ((rol32(e, 25) - f2) ^ g1) + g2
    j &= 0xFFFFFFFF
    
    # Round 5
    j4 = rol32(j, 4) ^ g1
    x5 = j4 ^ MAGIC
    c15 = rol32(c, 15)
    y5 = x5 ^ c15
    k = ((rol32(h_val, 25) - x5) ^ g2) + y5
    k &= 0xFFFFFFFF
    
    # Round 6
    k4 = rol32(k, 4) ^ g2
    x6 = k4 ^ MAGIC
    c18 = rol32(c, 18)
    y6 = x6 ^ c18
    m = ((rol32(j, 25) - x6) ^ y5) + y6
    m &= 0xFFFFFFFF
    
    # Round 7
    f7 = c15 ^ j4 ^ rol32(m, 4)
    c21 = rol32(c, 21)
    n = c21 ^ f7
    p = ((rol32(k, 25) - f7) ^ y6) + n
    p &= 0xFFFFFFFF
    
    # Round 8
    r_val = c18 ^ k4 ^ rol32(p, 4)
    r_val &= 0xFFFFFFFF
    
    # Final key parts
    key1 = r_val
    key2 = ((rol32(m, 25) - r_val) ^ n) & 0xFFFFFFFF
    key3 = n
    key4 = rol32(p, 25)
    
    # Step 6: Format key
    tier_suffixes = ["BRNZ", "SLVR", "GOLD"]
    tier_suffix = tier_suffixes[tier - 1]
    
    key = f"KGIII-{key1:08X}-{key2:08X}-{key3:08X}-{key4:08X}-{tier_suffix}"
    
    return key

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <username> <hwid> <timestamp> <tier>")
        print("Example: python3 keygen.py testuser ABCDEF0123456789 1769889821 1")
        sys.exit(1)
    
    username = sys.argv[1]
    hwid = sys.argv[2]
    timestamp = int(sys.argv[3])
    tier = int(sys.argv[4])
    
    try:
        key = generate_key(username, hwid, timestamp, tier)
        print(f"Username:  {username}")
        print(f"HWID:      {hwid}")
        print(f"Timestamp: {timestamp}")
        print(f"Tier:      {tier}")
        print(f"Key:       {key}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
```

### Server Solver Script

```python
#!/usr/bin/env python3
"""
Automated solver for Key3 challenge server
Connects to server and generates keys for 5 random username/HWID/timestamp/tier combinations
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
            
            # Extract username, HWID, timestamp, and tier from prompt
            # Format: "Username: <username>\nHWID: <hwid>\nTimestamp: <timestamp>\nTier: <tier>"
            username_match = re.search(r'Username:\s+(\S+)', data)
            hwid_match = re.search(r'HWID:\s+([0-9A-Fa-f]{16})', data)
            timestamp_match = re.search(r'Timestamp:\s+(\d+)', data)
            tier_match = re.search(r'Tier:\s+(\d+)', data)
            
            if not all([username_match, hwid_match, timestamp_match, tier_match]):
                print(f"[!] Error: Could not extract all parameters from challenge {challenge_num}")
                break
            
            username = username_match.group(1)
            hwid = hwid_match.group(1)
            timestamp = int(timestamp_match.group(1))
            tier = int(tier_match.group(1))
            
            print(f"[*] Challenge {challenge_num}: {username} / {hwid} / {timestamp} / {tier}", end='')
            
            # Generate key
            key = generate_key(username, hwid, timestamp, tier)
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
# Test with various combinations
./validator testuser ABCDEF0123456789 1769889821 1 "$(python3 keygen.py testuser ABCDEF0123456789 1769889821 1)"
# Should output: Valid!

./validator admin 1234567890ABCDEF 1769889821 2 "$(python3 keygen.py admin 1234567890ABCDEF 1769889821 2)"
# Should output: Valid!
```

### Verification Steps

1. **Test hash construction:**
   ```python
   # Verify input buffer construction
   input_buffer = username_bytes + hwid_bytes + timestamp_le64 + tier_u8
   print(f"Input buffer length: {len(input_buffer)}")
   print(f"Input buffer: {input_buffer.hex()}")
   ```

2. **Verify hash word extraction:**
   ```python
   # Check endianness
   h0_le = struct.unpack('<I', sha256_hash[0:4])[0]
   h0_be = struct.unpack('>I', sha256_hash[0:4])[0]
   print(f"Little-endian h0: 0x{h0_le:08X}")
   print(f"Big-endian h0:    0x{h0_be:08X}")
   ```

3. **Verify CRC32:**
   ```python
   crc = zlib.crc32(hwid_bytes) & 0xFFFFFFFF
   print(f"CRC32: 0x{crc:08X}")
   ```

4. **Test edge cases:**
   - Minimum length username (4 chars)
   - Maximum length username (32 chars)
   - Various HWID values
   - Different timestamps
   - All three tiers

### Debugging Tips

If your keygen doesn't work:

1. **Check endianness:**
   - Verify you're using `<I` (little-endian) for hash word extraction
   - Compare with GDB register values

2. **Verify input buffer:**
   - Check that HWID is parsed to bytes, not kept as hex string
   - Verify timestamp is little-endian 64-bit
   - Verify tier is a single byte

3. **Check CRC32:**
   - Verify CRC32 is computed over parsed HWID bytes
   - Compare with binary's CRC32 result

4. **Trace through mixing network:**
   - Print intermediate values at each round
   - Compare with binary's intermediate values (if possible with GDB)

5. **Verify key format:**
   - Check prefix is "KGIII-"
   - Check dashes are at correct positions
   - Check tier suffix matches tier number

## Getting the Flag

Once the keygen is verified locally, connect to the server:

```bash
python3 solve.py node-3.mcsc.space 35045
```

**Expected output:**
```
[+] Opening connection to node-3.mcsc.space on port 35045: Done
╔══════════════════════════════════════╗
║     key-3 Enterprise Licensing       ║
╠══════════════════════════════════════╣
║  Generate 5 valid keys to proceed   ║
╚══════════════════════════════════════╝

Challenge 1/5:
Username: subscriber_silver
HWID: DEAD5678FACE1234
Timestamp: 1769889863
Tier: 2 (SLVR)
[*] Challenge 1: subscriber_silver / DEAD5678FACE1234 / 1769889863 / 2 -> KGIII-...
Enter key: 
[+] Valid!

Challenge 2/5:
...
[+] Valid!

...

Challenge 5/5:
...
[+] Valid!

╔══════════════════════════════════════╗
║        Congratulations!              ║
╠══════════════════════════════════════╣
║  esch{conditions-drive-paths-shadow-shadow-8997}
╚══════════════════════════════════════╝

[+] Flag: esch{conditions-drive-paths-shadow-shadow-8997}
```

## Lessons Learned

1. **Endianness matters!** - Always check the byte order when reading multi-byte values. x86 is little-endian, so use `<I` not `>I` for 32-bit integers.

2. **Rust binaries have telltale signs** - Panic messages, string formatting, and standard library functions help identify Rust binaries.

3. **SHA-256 input construction is critical** - The exact byte layout matters. HWID must be parsed to bytes, not used as hex string.

4. **Feistel networks mix values thoroughly** - Each round builds on the previous, creating complex dependencies. Trace through carefully.

5. **Round-dependent tweaks add complexity** - The CRC rotations by multiples of 3 ensure each round is different.

6. **Magic constants are common** - XORing with constants like `0x5f8c2e7a` adds non-linearity.

7. **Test locally first** - Always verify your keygen against the actual binary before hitting the server.

8. **Use GDB for debugging** - Setting breakpoints and comparing register values helps identify issues like endianness bugs.

9. **Timestamp validation prevents replay** - Keys must be generated with current timestamps (within 24 hours).

10. **Tier affects suffix only** - The tier doesn't affect the algorithm, only the final suffix (BRNZ/SLVR/GOLD).

## Tools Used

- **Binary Ninja** - Decompilation and disassembly of the stripped Rust binary
- **GDB** - Tracing intermediate values to find the endianness bug
- **Python 3** - Keygen + socket solve script (using pwntools)

## Files

- `keygen.py` - Standalone keygen for manual use
- `solve.py` - Automated solver for the CTF challenge (requires pwntools)
- `validator` - The original binary to test against locally

## Additional Resources

- [Endianness Explained](https://en.wikipedia.org/wiki/Endianness)
- [SHA-256 Algorithm](https://en.wikipedia.org/wiki/SHA-2)
- [CRC32 Calculation](https://en.wikipedia.org/wiki/Cyclic_redundancy_check)
- [Feistel Networks](https://en.wikipedia.org/wiki/Feistel_cipher)
- [Rust Binary Analysis](https://github.com/m4b/bingrep)
- [Binary Ninja Documentation](https://docs.binary.ninja/)
- [GDB Tutorial](https://sourceware.org/gdb/current/onlinedocs/gdb/)

---

*"Endianness bugs are the bane of reverse engineers. Always verify byte order!"*
