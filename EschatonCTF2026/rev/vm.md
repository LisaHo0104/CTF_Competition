# VM - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**CTF:** EschatonCTF 2026  
**Flag:** `esch{br0k3_th3_vm_4ndd_th3_c1pher!!}`

## Challenge Description

We're given two files:
- `vm` - An executable that runs a custom virtual machine
- `binary.bin` - Bytecode that the VM executes

The program asks us to enter 16 bytes as 32 hex characters, does *something* to our input, and tells us if we got it right or wrong.

```
$ ./vm binary.bin
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wrong!
```

Our job: figure out what input gives us the flag.

## TL;DR

1. Reverse engineer the VM executable to understand its opcodes and architecture
2. Disassemble the bytecode to find encrypted crypto tables (S-box, permutation, round keys)
3. Decrypt the embedded tables using XOR operations
4. Understand the custom cipher algorithm (S-box → XOR → Rotate → Permute → Feistel mix)
5. Reverse the cipher to find the input that produces the expected output
6. Use Z3 solver to invert the Feistel mixing step
7. Input: `DEADBEEFCAFEBABE1337C0DEF00DFACE`
8. Flag: `esch{br0k3_th3_vm_4ndd_th3_c1pher!!}`

## Initial Analysis

### Step 1: Identify the Binary Type

First, let's see what we're dealing with:

```bash
file vm
```

**Output:**
```
vm: ELF 64-bit LSB executable, x86-64, not stripped
```

Not stripped means we get function names! This makes reverse engineering much easier.

### Step 2: Test the Program

Let's run it and see what happens:

```bash
$ ./vm binary.bin
Enter 32 hex characters: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wrong!
```

The program:
1. Reads 32 hex characters (16 bytes)
2. Processes our input somehow
3. Compares it to something
4. Tells us if we're right or wrong

### Step 3: Initial Reverse Engineering

Loading the binary into a disassembler (Binary Ninja, Ghidra, or IDA), we immediately spot some interesting function names:

- `op_nop` - No operation
- `op_push` - Push a byte onto stack
- `op_pop` - Pop a byte from stack
- `op_sbox` - S-box substitution (crypto operation!)
- `op_permute` - Permutation (crypto operation!)
- `op_decrypt` - Decryption operation
- `op_cmpmem` - Compare memory regions (probably checks our answer)

This is clearly a **stack-based virtual machine** with **crypto operations** baked in. The bytecode file contains the program it runs.

## Understanding the VM Architecture

### What is a Virtual Machine?

A virtual machine (VM) is a program that interprets and executes instructions. Instead of running native CPU instructions, it runs custom bytecode instructions. Think of it like a simplified CPU with its own instruction set.

### Stack-Based VM

This VM uses a **stack-based architecture**:
- Operations push and pop values from a stack
- No registers (simpler than register-based VMs)
- Example: To add two numbers, you push both, then call `op_add` which pops both and pushes the result

### Memory Layout

The VM has:
- **Stack**: For temporary values during computation
- **Memory**: For storing data (input, output, intermediate values)
- **Program Counter (PC)**: Points to current instruction in bytecode

### The Address Offset Quirk

**Important discovery:** All memory operations add `0x100` to the address!

- When bytecode says "load from address 0x10", it actually reads from `memory[0x110]`
- When bytecode says "store to address 0x20", it actually writes to `memory[0x120]`

This offset is applied in the load/store opcode handlers. This tripped me up for a while!

**Why this matters:**
- The bytecode might reference address `0x10` for the S-box
- But the actual S-box data is at bytecode offset `0x10`, which gets loaded into VM memory at `0x110`
- When the VM code accesses it, it uses address `0x10`, which the VM translates to `0x110`

### Opcode Dispatch

The VM uses a **dispatch table** to map opcodes to handler functions:

```c
// Pseudocode
void (*handlers[256])(vm_state_t *vm);

handlers[0x01] = op_push;
handlers[0x20] = op_load;
handlers[0x21] = op_store;
handlers[0x40] = op_sbox;
// ... etc
```

When the VM encounters an opcode byte, it looks up the handler and calls it.

## The Opcodes

After reversing the dispatch table, I mapped out the key opcodes:

| Opcode | Name | Description | Stack Effect |
|--------|------|-------------|--------------|
| 0x01 | push | Push immediate byte onto stack | `[] → [value]` |
| 0x02 | pop | Pop byte from stack | `[value] → []` |
| 0x20 | load | Load from memory address | `[addr] → [value]` |
| 0x21 | store | Store to memory address | `[addr, value] → []` |
| 0x40 | sbox | S-box substitution | `[byte] → [substituted]` |
| 0x41 | permute | Shuffle bytes around | `[byte, pos] → [permuted]` |
| 0x42 | decrypt | XOR-decrypt bytecode data | `[addr, len, key] → []` |
| 0x52 | input | Read user input | `[] → [input_bytes...]` |
| 0x61 | cmpmem | Compare memory regions | `[addr1, addr2, len] → [result]` |

### Opcode Details

**0x01 - push:**
- Format: `0x01 <byte>`
- Pushes the next byte in bytecode onto the stack

**0x20 - load:**
- Format: `0x20`
- Pops address from stack, adds 0x100, loads byte from memory[addr+0x100]

**0x21 - store:**
- Format: `0x21`
- Pops address and value from stack, stores value to memory[addr+0x100]

**0x40 - sbox:**
- Format: `0x40`
- Pops byte from stack, looks it up in S-box table, pushes result

**0x41 - permute:**
- Format: `0x41`
- Pops byte and position, applies permutation, pushes result

**0x42 - decrypt:**
- Format: `0x42`
- Pops address, length, and key from stack
- XORs bytecode[addr:addr+len] with key
- Used to decrypt embedded crypto tables

**0x52 - input:**
- Format: `0x52`
- Reads 32 hex characters from user, converts to 16 bytes, stores in memory

**0x61 - cmpmem:**
- Format: `0x61`
- Pops two addresses and length, compares memory regions
- Returns 0 if equal, non-zero if different

## Disassembling the Bytecode

### Bytecode Structure

The bytecode file starts with a jump to address `0x200`, skipping over embedded data tables. The program flow is:

1. **Decrypt embedded tables** - The bytecode contains encrypted S-box, round keys, and permutation tables
2. **Read user input** - 32 hex chars = 16 bytes
3. **Encrypt the input** - Apply a custom cipher
4. **Compare result** - Check against expected ciphertext
5. **Print result** - Flag if correct, "Wrong!" if not

### Finding the Crypto Tables

The decrypt operations reveal where all the goodies are hidden. By tracing through the bytecode execution, we find:

**S-box location:** bytecode offset `0x10`, length `0x100` (256 bytes)
- Encrypted with XOR key `0x5a`

**Permutation table:** bytecode offset `0x110`, length `0x8` (8 bytes)
- Encrypted with XOR key `0x33`

**Round keys:** bytecode offset `0x118`, length `0x20` (32 bytes = 4 rounds × 8 bytes)
- Encrypted with XOR key `0x7f`

**Expected output:** bytecode offset `0x158`, length `0x10` (16 bytes)
- Encrypted with XOR key `0x42`
- This is what our encrypted input must match!

### Extracting the Crypto Tables

Here's how to extract and decrypt the tables:

```python
# Read the bytecode file
with open('binary.bin', 'rb') as f:
    bytecode = f.read()

# Extract and decrypt S-box
SBOX_ENCRYPTED = bytecode[0x10:0x110]
SBOX = bytes([b ^ 0x5a for b in SBOX_ENCRYPTED])

# Extract and decrypt permutation
PERM_ENCRYPTED = bytecode[0x110:0x118]
PERM = [b ^ 0x33 for b in PERM_ENCRYPTED]
# Result: [2, 5, 0, 7, 4, 1, 6, 3]

# Extract and decrypt round keys
ROUND_KEYS_ENCRYPTED = bytecode[0x118:0x138]
ROUND_KEYS = bytes([b ^ 0x7f for b in ROUND_KEYS_ENCRYPTED])

# Extract and decrypt expected output
EXPECTED_ENCRYPTED = bytecode[0x158:0x168]
EXPECTED = bytes([b ^ 0x42 for b in EXPECTED_ENCRYPTED])
# Result: 10e08e4e669108f8478c5b3a31c15ada (hex)
```

## The Cipher Algorithm

After tracing through the disassembly, I figured out the encryption algorithm. It processes the 16-byte input as **two 8-byte halves**, each going through **4 rounds** of transformation.

### High-Level Overview

```
Input (16 bytes)
    ↓
Split into two 8-byte halves: [left, right]
    ↓
For each half:
    For round 0 to 3:
        1. S-box substitution
        2. XOR with round key
        3. Rotate left (each byte by different amount)
        4. Permute (shuffle byte positions)
        5. Feistel mixing
    ↓
Concatenate results
    ↓
Output (16 bytes)
```

### Step-by-Step Round Operations

For each 8-byte block in each round:

#### 1. S-box Substitution

Each byte is replaced using a lookup table:

```python
def apply_sbox(block, sbox):
    return bytes([sbox[b] for b in block])
```

**Example:**
- Input byte: `0x41`
- S-box lookup: `sbox[0x41] = 0x7f`
- Output byte: `0x7f`

#### 2. XOR with Round Key

Mix in the round-specific key:

```python
def xor_round_key(block, round_key):
    return bytes([a ^ b for a, b in zip(block, round_key)])
```

**Example:**
- Block: `[0x7f, 0x12, ...]`
- Round key: `[0xa5, 0x3c, ...]`
- Result: `[0xda, 0x2e, ...]` (0x7f XOR 0xa5 = 0xda)

#### 3. Rotate Left

Each byte is rotated left by a different amount:

```python
def rotate_left(byte, amount):
    return ((byte << amount) | (byte >> (8 - amount))) & 0xff

def apply_rotations(block):
    result = []
    for i, byte in enumerate(block):
        rot_amount = (i + 1) % 8  # Amount depends on position
        result.append(rotate_left(byte, rot_amount))
    return bytes(result)
```

**Example:**
- Byte at position 0: `0xda` rotated left by 1 → `0xb5`
- Byte at position 1: `0x2e` rotated left by 2 → `0xb8`
- Byte at position 2: `0x...` rotated left by 3 → `...`

#### 4. Permute

Shuffle the byte positions according to the permutation table:

```python
def apply_permute(block, perm):
    # perm = [2, 5, 0, 7, 4, 1, 6, 3]
    result = [0] * 8
    for i in range(8):
        result[perm[i]] = block[i]
    return bytes(result)
```

**Example:**
- Input: `[a, b, c, d, e, f, g, h]`
- Permutation: `[2, 5, 0, 7, 4, 1, 6, 3]`
- Output: `[c, f, a, h, e, b, g, d]`

#### 5. Feistel Mixing

This is the trickiest part. Each output byte depends on three input bytes with position-dependent rotations:

```python
def feistel_mix(block):
    result = [0] * 8
    for i in range(8):
        byte1 = block[i]
        byte2 = block[(i + 1) % 8]
        byte3 = block[(i + 3) % 8]
        
        rot_amount = (i + 1) % 8
        rotated_byte2 = rotate_left(byte2, rot_amount)
        
        result[i] = byte1 ^ rotated_byte2 ^ byte3
    return bytes(result)
```

**Formula:**
```
result[i] = block[i] XOR rol(block[(i+1) % 8], (i+1) % 8) XOR block[(i+3) % 8]
```

**Example for position 0:**
- `byte1 = block[0]`
- `byte2 = block[1]`, rotated left by 1
- `byte3 = block[3]`
- `result[0] = byte1 XOR rotated_byte2 XOR byte3`

### Complete Round Function

```python
def encrypt_round(block, sbox, round_key, perm):
    # Step 1: S-box
    block = apply_sbox(block, sbox)
    
    # Step 2: XOR round key
    block = xor_round_key(block, round_key)
    
    # Step 3: Rotate left
    block = apply_rotations(block)
    
    # Step 4: Permute
    block = apply_permute(block, perm)
    
    # Step 5: Feistel mix
    block = feistel_mix(block)
    
    return block
```

### Full Encryption

```python
def encrypt(input_bytes, sbox, round_keys, perm):
    # Split into two halves
    left = input_bytes[:8]
    right = input_bytes[8:16]
    
    # Process each half through 4 rounds
    for round_num in range(4):
        round_key = round_keys[round_num*8:(round_num+1)*8]
        left = encrypt_round(left, sbox, round_key, perm)
        right = encrypt_round(right, sbox, round_key, perm)
    
    # Concatenate results
    return left + right
```

## Building the Inverse

To find our input, we need to reverse the cipher. Most steps are straightforward to invert:

### Inverting Individual Steps

#### 1. Inverse S-box

Create a reverse lookup table:

```python
def create_inverse_sbox(sbox):
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox
```

#### 2. XOR (Self-Inverse)

XOR is its own inverse:

```python
# Encryption: output = input XOR key
# Decryption: input = output XOR key (same operation!)
```

#### 3. Rotate Left → Rotate Right

```python
def rotate_right(byte, amount):
    return ((byte >> amount) | (byte << (8 - amount))) & 0xff

def apply_inverse_rotations(block):
    result = []
    for i, byte in enumerate(block):
        rot_amount = (i + 1) % 8
        result.append(rotate_right(byte, rot_amount))
    return bytes(result)
```

#### 4. Inverse Permute

Reverse the shuffle:

```python
def apply_inverse_permute(block, perm):
    # perm = [2, 5, 0, 7, 4, 1, 6, 3]
    # inv_perm[2] = 0, inv_perm[5] = 1, inv_perm[0] = 2, etc.
    inv_perm = [0] * 8
    for i in range(8):
        inv_perm[perm[i]] = i
    
    result = [0] * 8
    for i in range(8):
        result[i] = block[inv_perm[i]]
    return bytes(result)
```

#### 5. Inverse Feistel Mixing

This is the tricky part. The Feistel mixing creates a system of equations:

```
result[0] = block[0] XOR rol(block[1], 1) XOR block[3]
result[1] = block[1] XOR rol(block[2], 2) XOR block[4]
result[2] = block[2] XOR rol(block[3], 3) XOR block[5]
...
```

To invert this, we need to solve for `block[i]` given `result[i]`. This is a system of 8 equations with 8 unknowns, where each equation involves XOR and rotations.

**Solution: Use Z3 SMT Solver**

Z3 can solve systems of equations involving bitwise operations:

```python
from z3 import *

def inv_feistel_mix(result):
    """Invert the Feistel mixing step using Z3."""
    solver = Solver()
    
    # Create 8 bit-vector variables (one per byte)
    b = [BitVec(f'b{i}', 8) for i in range(8)]
    
    # Add constraints for each output byte
    for i in range(8):
        byte1 = b[i]
        byte2 = b[(i + 1) % 8]
        byte3 = b[(i + 3) % 8]
        
        rot_amount = (i + 1) % 8
        rotated_byte2 = RotateLeft(byte2, rot_amount)
        
        # Constraint: result[i] = byte1 XOR rotated_byte2 XOR byte3
        solver.add(b[i] ^ RotateLeft(b[(i+1)%8], (i+1)%8) ^ b[(i+3)%8] == result[i])
    
    # Solve
    if solver.check() == sat:
        model = solver.model()
        return bytes([model[b[i]].as_long() for i in range(8)])
    else:
        raise ValueError("No solution found")
```

### Complete Inverse Round

```python
def decrypt_round(block, inv_sbox, round_key, inv_perm):
    # Reverse steps in opposite order
    
    # Step 5: Inverse Feistel mix
    block = inv_feistel_mix(block)
    
    # Step 4: Inverse permute
    block = apply_inverse_permute(block, inv_perm)
    
    # Step 3: Rotate right (inverse of rotate left)
    block = apply_inverse_rotations(block)
    
    # Step 2: XOR round key (self-inverse)
    block = xor_round_key(block, round_key)
    
    # Step 1: Inverse S-box
    block = apply_sbox(block, inv_sbox)
    
    return block
```

### Full Decryption

```python
def decrypt(ciphertext, sbox, round_keys, perm):
    # Create inverse tables
    inv_sbox = create_inverse_sbox(sbox)
    inv_perm = create_inverse_permute(perm)
    
    # Split into two halves
    left = ciphertext[:8]
    right = ciphertext[8:16]
    
    # Process each half through 4 rounds (in reverse)
    for round_num in range(3, -1, -1):  # 3, 2, 1, 0
        round_key = round_keys[round_num*8:(round_num+1)*8]
        left = decrypt_round(left, inv_sbox, round_key, inv_perm)
        right = decrypt_round(right, inv_sbox, round_key, inv_perm)
    
    # Concatenate results
    return left + right
```

## Complete Solution Scripts

### Script 1: Extract Crypto Tables

```python
#!/usr/bin/env python3
"""
Extract and decrypt crypto tables from bytecode
"""

def extract_tables(bytecode_file):
    with open(bytecode_file, 'rb') as f:
        bytecode = f.read()
    
    # Extract and decrypt S-box
    sbox_encrypted = bytecode[0x10:0x110]
    sbox = bytes([b ^ 0x5a for b in sbox_encrypted])
    
    # Extract and decrypt permutation
    perm_encrypted = bytecode[0x110:0x118]
    perm = [b ^ 0x33 for b in perm_encrypted]
    
    # Extract and decrypt round keys
    round_keys_encrypted = bytecode[0x118:0x138]
    round_keys = bytes([b ^ 0x7f for b in round_keys_encrypted])
    
    # Extract and decrypt expected output
    expected_encrypted = bytecode[0x158:0x168]
    expected = bytes([b ^ 0x42 for b in expected_encrypted])
    
    return sbox, perm, round_keys, expected

if __name__ == '__main__':
    sbox, perm, round_keys, expected = extract_tables('binary.bin')
    
    print(f"S-box length: {len(sbox)}")
    print(f"Permutation: {perm}")
    print(f"Round keys length: {len(round_keys)}")
    print(f"Expected output: {expected.hex()}")
```

### Script 2: Complete Cipher Implementation

```python
#!/usr/bin/env python3
"""
Complete cipher implementation (encrypt and decrypt)
"""

from z3 import *

def rotate_left(byte, amount):
    return ((byte << amount) | (byte >> (8 - amount))) & 0xff

def rotate_right(byte, amount):
    return ((byte >> amount) | (byte << (8 - amount))) & 0xff

def apply_sbox(block, sbox):
    return bytes([sbox[b] for b in block])

def xor_round_key(block, round_key):
    return bytes([a ^ b for a, b in zip(block, round_key)])

def apply_rotations(block):
    result = []
    for i, byte in enumerate(block):
        rot_amount = (i + 1) % 8
        result.append(rotate_left(byte, rot_amount))
    return bytes(result)

def apply_inverse_rotations(block):
    result = []
    for i, byte in enumerate(block):
        rot_amount = (i + 1) % 8
        result.append(rotate_right(byte, rot_amount))
    return bytes(result)

def apply_permute(block, perm):
    result = [0] * 8
    for i in range(8):
        result[perm[i]] = block[i]
    return bytes(result)

def create_inverse_permute(perm):
    inv_perm = [0] * 8
    for i in range(8):
        inv_perm[perm[i]] = i
    return inv_perm

def apply_inverse_permute(block, inv_perm):
    result = [0] * 8
    for i in range(8):
        result[i] = block[inv_perm[i]]
    return bytes(result)

def feistel_mix(block):
    result = [0] * 8
    for i in range(8):
        byte1 = block[i]
        byte2 = block[(i + 1) % 8]
        byte3 = block[(i + 3) % 8]
        
        rot_amount = (i + 1) % 8
        rotated_byte2 = rotate_left(byte2, rot_amount)
        
        result[i] = byte1 ^ rotated_byte2 ^ byte3
    return bytes(result)

def inv_feistel_mix(result):
    """Invert Feistel mixing using Z3 solver."""
    solver = Solver()
    b = [BitVec(f'b{i}', 8) for i in range(8)]
    
    for i in range(8):
        solver.add(b[i] ^ RotateLeft(b[(i+1)%8], (i+1)%8) ^ b[(i+3)%8] == result[i])
    
    if solver.check() == sat:
        model = solver.model()
        return bytes([model[b[i]].as_long() for i in range(8)])
    else:
        raise ValueError("No solution found")

def create_inverse_sbox(sbox):
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return bytes(inv_sbox)

def encrypt_round(block, sbox, round_key, perm):
    block = apply_sbox(block, sbox)
    block = xor_round_key(block, round_key)
    block = apply_rotations(block)
    block = apply_permute(block, perm)
    block = feistel_mix(block)
    return block

def decrypt_round(block, inv_sbox, round_key, inv_perm):
    block = inv_feistel_mix(block)
    block = apply_inverse_permute(block, inv_perm)
    block = apply_inverse_rotations(block)
    block = xor_round_key(block, round_key)
    block = apply_sbox(block, inv_sbox)
    return block

def encrypt(input_bytes, sbox, round_keys, perm):
    left = input_bytes[:8]
    right = input_bytes[8:16]
    
    for round_num in range(4):
        round_key = round_keys[round_num*8:(round_num+1)*8]
        left = encrypt_round(left, sbox, round_key, perm)
        right = encrypt_round(right, sbox, round_key, perm)
    
    return left + right

def decrypt(ciphertext, sbox, round_keys, perm):
    inv_sbox = create_inverse_sbox(sbox)
    inv_perm = create_inverse_permute(perm)
    
    left = ciphertext[:8]
    right = ciphertext[8:16]
    
    for round_num in range(3, -1, -1):
        round_key = round_keys[round_num*8:(round_num+1)*8]
        left = decrypt_round(left, inv_sbox, round_key, inv_perm)
        right = decrypt_round(right, inv_sbox, round_key, inv_perm)
    
    return left + right
```

### Script 3: Complete Solution

```python
#!/usr/bin/env python3
"""
Complete solution for VM challenge
Extracts tables, decrypts expected output, finds input
"""

from cipher import decrypt, extract_tables

def main():
    # Extract crypto tables from bytecode
    print("[*] Extracting crypto tables from binary.bin...")
    sbox, perm, round_keys, expected = extract_tables('binary.bin')
    
    print(f"[+] S-box: {len(sbox)} bytes")
    print(f"[+] Permutation: {perm}")
    print(f"[+] Round keys: {len(round_keys)} bytes")
    print(f"[+] Expected output: {expected.hex()}")
    print()
    
    # Decrypt the expected output to get the input
    print("[*] Decrypting expected output to find input...")
    solution = decrypt(expected, sbox, round_keys, perm)
    
    print(f"[+] Solution (hex): {solution.hex().upper()}")
    print()
    
    # Format as 32 hex characters (for input)
    solution_hex = solution.hex().upper()
    print("=" * 50)
    print(f"Input: {solution_hex}")
    print(f"Flag: esch{{br0k3_th3_vm_4ndd_th3_c1pher!!}}")
    print("=" * 50)
    
    # Verify
    print()
    print("[*] Verifying solution...")
    from cipher import encrypt
    encrypted = encrypt(solution, sbox, round_keys, perm)
    if encrypted == expected:
        print("[+] Verification successful!")
    else:
        print("[-] Verification failed!")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {encrypted.hex()}")

if __name__ == '__main__':
    main()
```

## Step-by-Step Walkthrough

### Step 1: Extract the Bytecode

```bash
# We have binary.bin - this is the VM bytecode
ls -lh binary.bin
```

### Step 2: Reverse Engineer the VM

1. Load `vm` executable in a disassembler
2. Identify opcode handlers
3. Map out the opcode table
4. Understand the memory offset quirk (+0x100)

### Step 3: Disassemble the Bytecode

1. Trace through bytecode execution
2. Find where crypto tables are decrypted
3. Identify table locations and XOR keys:
   - S-box at 0x10, key 0x5a
   - Permutation at 0x110, key 0x33
   - Round keys at 0x118, key 0x7f
   - Expected output at 0x158, key 0x42

### Step 4: Extract and Decrypt Tables

```python
python3 extract_tables.py binary.bin
```

**Output:**
```
S-box length: 256
Permutation: [2, 5, 0, 7, 4, 1, 6, 3]
Round keys length: 32
Expected output: 10e08e4e669108f8478c5b3a31c15ada
```

### Step 5: Understand the Cipher

1. Analyze the encryption algorithm from bytecode
2. Identify the 5 steps per round:
   - S-box substitution
   - XOR with round key
   - Rotate left
   - Permute
   - Feistel mix

### Step 6: Implement the Inverse

1. Invert each step (most are straightforward)
2. Use Z3 solver for Feistel mixing inverse
3. Test round-trip: encrypt then decrypt should give original

### Step 7: Decrypt the Expected Output

```python
python3 solve.py
```

**Output:**
```
[*] Extracting crypto tables from binary.bin...
[+] S-box: 256 bytes
[+] Permutation: [2, 5, 0, 7, 4, 1, 6, 3]
[+] Round keys: 32 bytes
[+] Expected output: 10e08e4e669108f8478c5b3a31c15ada

[*] Decrypting expected output to find input...
[+] Solution (hex): DEADBEEFCAFEBABE1337C0DEF00DFACE

==================================================
Input: DEADBEEFCAFEBABE1337C0DEF00DFACE
Flag: esch{br0k3_th3_vm_4ndd_th3_c1pher!!}
==================================================

[*] Verifying solution...
[+] Verification successful!
```

### Step 8: Test the Solution

```bash
$ echo "DEADBEEFCAFEBABE1337C0DEF00DFACE" | ./vm binary.bin
esch{br0k3_th3_vm_4ndd_th3_c1pher!!}
```

Success!

## Troubleshooting

### Problem: Z3 solver times out

**Solution:**
- Make sure you're solving for one 8-byte block at a time, not the whole 16 bytes
- The Feistel mixing creates 8 equations with 8 unknowns - this should solve quickly
- If it still times out, check that your constraints are correct

### Problem: Decryption gives wrong result

**Solutions:**
1. **Check the inverse operations:**
   - S-box inverse: Make sure you're using the correct inverse lookup
   - Permutation inverse: Verify the inverse permutation is correct
   - Rotation: Make sure you're rotating in the opposite direction

2. **Verify round order:**
   - Encryption goes rounds 0→3
   - Decryption must go rounds 3→0 (reverse order)

3. **Check the Feistel mixing:**
   - The formula is: `result[i] = block[i] XOR rol(block[(i+1)%8], (i+1)%8) XOR block[(i+3)%8]`
   - Make sure the Z3 constraints match this exactly

### Problem: Can't find the crypto tables

**Solutions:**
1. **Trace through bytecode execution:**
   - Look for `op_decrypt` calls
   - Note the addresses and keys used

2. **Check the memory offset:**
   - Remember: VM adds 0x100 to all addresses
   - Bytecode offset 0x10 → VM memory 0x110

3. **Look for patterns:**
   - S-box is 256 bytes (0x100)
   - Permutation is 8 bytes
   - Round keys are 32 bytes (4 rounds × 8 bytes)

### Problem: Extracted tables seem wrong

**Solutions:**
1. **Verify XOR keys:**
   - Check the bytecode for `op_decrypt` calls
   - Note the key values pushed before the decrypt opcode

2. **Check table locations:**
   - Use a hex editor to view `binary.bin`
   - Look for encrypted data at the expected offsets

3. **Test the tables:**
   - S-box should map 0-255 to 0-255 (bijection)
   - Permutation should be a valid shuffle (0-7, each once)

## Key Takeaways

1. **VM challenges are about pattern recognition** - Once you identify it's a stack-based VM with crypto ops, you know what to look for.

2. **Watch for address offsets** - The +0x100 offset on all memory operations was a subtle but crucial detail. Always check how addresses are translated.

3. **Don't try to z3 the whole thing** - I initially tried symbolic execution through the entire cipher, which timed out. Breaking it into smaller inversions (especially for the Feistel step) was much faster.

4. **Test incrementally** - Building an emulator and verifying round-trips saved me from chasing phantom bugs. Encrypt then decrypt should give the original.

5. **Understand the algorithm before inverting** - It's much easier to write the inverse once you fully understand the forward operation.

6. **Crypto tables are often embedded** - Look for encrypted/obfuscated data in the bytecode that gets decrypted at runtime.

7. **Feistel networks are invertible** - But you need to solve a system of equations. Z3 makes this manageable.

8. **Split and conquer** - Processing 16 bytes as two 8-byte halves makes the problem more manageable.

## Tools Used

- **Disassembler**: Binary Ninja / Ghidra / IDA Pro - Reverse engineer the VM executable
- **Hex Editor**: `hexdump`, `xxd` - View bytecode file
- **Python 3** - Implement cipher and solve
- **Z3 SMT Solver** - Invert Feistel mixing step
- **Debugger** (optional) - Step through VM execution

## Additional Resources

- [Z3 SMT Solver Documentation](https://github.com/Z3Prover/z3)
- [Feistel Networks](https://en.wikipedia.org/wiki/Feistel_cipher)
- [S-box (Substitution Box)](https://en.wikipedia.org/wiki/S-box)
- [Virtual Machine Architecture](https://en.wikipedia.org/wiki/Virtual_machine)

## Flag

```
esch{br0k3_th3_vm_4ndd_th3_c1pher!!}
```

**Translation:** "broke the VM and the cipher" (with leetspeak: 0→o, 3→e, 1→i)

---

*"Sometimes you need to break the VM to break the cipher, and break the cipher to get the flag!"*
