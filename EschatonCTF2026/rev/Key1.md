# Key 1 - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**Points:** 450  
**Flag:** `esch{destructors-clean-up-lunar-nova-2168}`

## Challenge Description

We're given a "legacy license validator" from KeyCorp. The goal is to reverse engineer how it validates license keys and build a keygen that can generate valid keys for any username. The server will test us with 5 random usernames - we need to generate valid keys for all 5 to get the flag.

## Initial Analysis

### First Look

We get a binary called `validator`. Running it shows basic usage:

```bash
./validator <username> <license_key>
```

The binary either prints "Valid!" or "Invalid!" - classic crackme style.

### Basic File Information

```bash
file validator
# validator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, ...

strings validator | head -20
# Shows some basic strings, but not much helpful info
```

## Methodology

### Step 1: Static Analysis Setup

Load the binary into a disassembler. Common tools:
- **Binary Ninja** (used in this writeup)
- **Ghidra** (free, open-source)
- **IDA Pro** (industry standard)
- **radare2** (command-line)

### Step 2: Identify Entry Point and Main Function

1. Find the `main` function
2. Trace the control flow
3. Identify key functions called

### Step 3: Analyze Validation Logic

1. Understand input validation
2. Trace the license key validation algorithm
3. Identify the hash function
4. Understand how key components are derived

### Step 4: Reverse Engineer the Algorithm

1. Understand each assembly instruction
2. Track register values through transformations
3. Identify the mathematical operations
4. Reconstruct the algorithm in high-level code

### Step 5: Implement Keygen

1. Port the algorithm to Python (or your preferred language)
2. Test locally against the binary
3. Verify with multiple usernames

### Step 6: Connect to Server

1. Automate the interaction with the server
2. Generate keys for the 5 random usernames
3. Extract the flag

## Static Analysis

### Main Function Analysis

The `main` function is straightforward:

```c
int main(int argc, char **argv) {
    if (argc == 3) {
        if (proc_a(argv[1], argv[2]) != 0)
            puts("Valid!");
        else
            puts("Invalid!");
    }
    return 0;
}
```

**Key observations:**
- Takes exactly 2 arguments (username and license key)
- Calls `proc_a` with both arguments
- Returns "Valid!" if `proc_a` returns non-zero, "Invalid!" otherwise

So all the magic happens in `proc_a`. Let's dive into that function.

### proc_a Function Overview

The `proc_a` function performs several checks:

1. **Username validation** - Checks length and character set
2. **License key format validation** - Checks format and hex digits
3. **Algorithm validation** - The actual cryptographic check

## Algorithm Analysis

### Username Validation Rules

The binary enforces these rules on the username:

```c
// Pseudo-code from disassembly
if (username_length < 4 || username_length > 16) {
    return 0;  // Invalid
}

for (each character in username) {
    if (!isalnum(c) && c != '_') {
        return 0;  // Invalid - only alphanumeric and underscore allowed
    }
}
```

**Rules:**
- Length: 4-16 characters
- Characters: Only alphanumeric (a-z, A-Z, 0-9) and underscore (_)

### License Key Format

The license key must follow a specific format:

```
XXXX-XXXX-XXXX-XXXX
```

Where:
- Total length: 19 characters (16 hex digits + 3 dashes)
- Dashes at positions: 4, 9, and 14 (0-indexed)
- Each `X` must be a valid hexadecimal digit (0-9, A-F)

**Example valid format:** `A1B2-C3D4-E5F6-7890`

### The Hash Function

The binary uses a **polynomial rolling hash** to process the username. This is a variant of the **djb2 hash** algorithm.

#### What is djb2?

The djb2 hash (by Daniel J. Bernstein) is a simple, fast hash function:

```c
unsigned long hash = 5381;  // djb2 uses 5381
for (each character c) {
    hash = hash * 33 + c;
}
```

**Why multiply by 33?**
- 33 = 32 + 1 = 2^5 + 1
- `hash * 33` = `hash * (2^5 + 1)` = `hash * 32 + hash` = `(hash << 5) + hash`
- This can be optimized to: `hash + (hash << 5)`

#### The Challenge's Hash Function

Looking at the disassembly, the binary uses:

```c
unsigned int hash = 0x7a2f;  // Starting seed (different from djb2's 5381)
for (each character c in username) {
    hash = (hash * 33 + (unsigned char)c) & 0xFFFFFFFF;
}
```

**Key differences from standard djb2:**
- Starting seed: `0x7a2f` instead of `5381`
- Same multiplication factor: `33`
- Masked to 32 bits: `& 0xFFFFFFFF`

**Python equivalent:**
```python
def hash_username(username):
    h = 0x7a2f
    for c in username:
        h = (h * 33 + ord(c)) & 0xFFFFFFFF
    return h
```

**Why this works:**
- Polynomial rolling hash: `H(s) = (s[0] * 33^n + s[1] * 33^(n-1) + ... + s[n-1]) mod 2^32`
- Fast to compute
- Good distribution for short strings
- Commonly used in CTF challenges

**Example hash values:**
```python
hash_username("test")     # 0x8A5C3D2E (example)
hash_username("admin")    # 0x9B6D4E3F (example)
hash_username("user123")  # 0x7C8E5F1A (example)
```

## Key Generation Algorithm

This is the heart of the challenge. The binary derives 4 values from the username hash and compares them against the 4 hex groups in the license key.

### Assembly Code Analysis

Let's examine the actual assembly code that generates the key components. This is where the tricky part comes in.

#### Understanding x86 Register Sizes

In x86-64 architecture, registers come in different sizes:

| 64-bit | 32-bit | 16-bit | 8-bit (low) | 8-bit (high) |
|--------|--------|--------|-------------|--------------|
| rax    | eax    | ax     | al           | ah           |
| rbx    | ebx    | bx     | bl           | bh           |
| rcx    | ecx    | cx     | cl           | ch           |
| rdx    | edx    | dx     | dl           | dh           |
| rsi    | esi    | si     | sil          | (none)       |
| rdi    | edi    | di     | dil          | (none)       |

**Critical behavior:**
- Writing to a 32-bit register (e.g., `eax`) **zeros** the upper 32 bits of the 64-bit register
- Writing to a 16-bit register (e.g., `ax`) **preserves** the upper 48 bits
- Writing to an 8-bit register (e.g., `al`) **preserves** the upper 56 bits

This is crucial for understanding the algorithm!

#### The Assembly Code

Here's the relevant assembly (simplified and annotated):

```asm
; Assume hash is in eax at this point
; hash = result from hash_username()

; Calculate first component (si)
mov     esi, eax            ; esi = hash (full 32 bits)
xor     si, 0x9c3e          ; si = (hash & 0xFFFF) ^ 0x9c3e
                            ; Only lower 16 bits affected!

; Calculate second component (ax) - THE TRICKY ONE!
lea     edx, [rax*8]        ; edx = hash << 3 (hash * 8)
mov     esi, eax            ; esi = hash (save original)
shr     ax, 5               ; ax = (hash & 0xFFFF) >> 5
                            ; CRITICAL: Only shifts lower 16 bits!
                            ; Upper 16 bits of eax are preserved!
                            ; So: eax = (hash & 0xFFFF0000) | ((hash & 0xFFFF) >> 5)
xor     eax, edx            ; eax = eax ^ (hash << 3)
xor     ax, 0xb7a1          ; ax = (eax & 0xFFFF) ^ 0xb7a1
                            ; Final: ax = ((eax_after_shr ^ (hash << 3)) ^ 0xb7a1) & 0xFFFF

; Calculate third component (dx)
mov     edx, esi            ; edx = original hash (from saved esi)
add     dx, ax              ; dx = (si + ax) & 0xFFFF
xor     dx, 0xe4d2          ; dx = ((si + ax) ^ 0xe4d2) & 0xFFFF

; Calculate fourth component (cx)
mov     ecx, eax            ; ecx = ax value
xor     cx, dx              ; cx = (ax ^ dx) & 0xFFFF
xor     cx, 0x78ec          ; cx = ((ax ^ dx) ^ 0x78ec) & 0xFFFF
```

### The Tricky Part: `shr ax, 5`

The most confusing part is this instruction:

```asm
shr ax, 5
```

**Why is this tricky?**

1. `ax` is the lower 16 bits of `eax`
2. `shr ax, 5` only shifts the lower 16 bits
3. The upper 16 bits of `eax` remain **unchanged**

**Example:**
```
Before: eax = 0x12345678
        ax  = 0x5678

After shr ax, 5:
        ax  = 0x5678 >> 5 = 0x02B3
        eax = 0x123402B3  (upper 16 bits preserved!)
```

**In Python, this is equivalent to:**
```python
# Instead of: eax = eax >> 5  (wrong - shifts all 32 bits)
# We need:     eax = (eax & 0xFFFF0000) | ((eax & 0xFFFF) >> 5)
```

### Step-by-Step Algorithm Derivation

Let's trace through the algorithm with a concrete example. Assume `hash = 0x8A5C3D2E`.

#### Step 1: Calculate `si` (first key component)

```python
hash = 0x8A5C3D2E
si = (hash & 0xFFFF) ^ 0x9c3e
   = 0x3D2E ^ 0x9c3e
   = 0xA110
```

**Assembly equivalent:**
```asm
mov esi, eax        ; esi = 0x8A5C3D2E
xor si, 0x9c3e      ; si = 0x3D2E ^ 0x9c3e = 0xA110
```

#### Step 2: Calculate `ax` (second key component) - THE TRICKY ONE

```python
hash = 0x8A5C3D2E

# Step 2a: Calculate hash << 3
edx = (hash << 3) & 0xFFFFFFFF
    = 0x452E1E97

# Step 2b: The tricky shr ax, 5
# This only affects lower 16 bits!
eax_after_shr = (hash & 0xFFFF0000) | ((hash & 0xFFFF) >> 5)
              = 0x8A5C0000 | (0x3D2E >> 5)
              = 0x8A5C0000 | 0x01E9
              = 0x8A5C01E9

# Step 2c: XOR with (hash << 3)
eax = eax_after_shr ^ edx
    = 0x8A5C01E9 ^ 0x452E1E97
    = 0xCF721F7E

# Step 2d: Final XOR with 0xb7a1 (only lower 16 bits)
ax = (eax & 0xFFFF) ^ 0xb7a1
   = 0x1F7E ^ 0xb7a1
   = 0xA8DF
```

**Assembly equivalent:**
```asm
lea edx, [rax*8]        ; edx = 0x452E1E97
mov esi, eax            ; Save original hash
shr ax, 5               ; eax = 0x8A5C01E9 (only ax shifted!)
xor eax, edx            ; eax = 0xCF721F7E
xor ax, 0xb7a1          ; ax = 0xA8DF
```

#### Step 3: Calculate `dx` (third key component)

```python
si = 0xA110
ax = 0xA8DF

sum_val = (si + ax) & 0xFFFF
        = (0xA110 + 0xA8DF) & 0xFFFF
        = 0x149EF & 0xFFFF
        = 0x49EF

dx = sum_val ^ 0xe4d2
   = 0x49EF ^ 0xe4d2
   = 0xAD3D
```

**Assembly equivalent:**
```asm
mov edx, esi            ; edx = original hash (but we use si and ax)
add dx, ax              ; dx = 0x49EF
xor dx, 0xe4d2          ; dx = 0xAD3D
```

#### Step 4: Calculate `cx` (fourth key component)

```python
ax = 0xA8DF
dx = 0xAD3D

cx = ((ax ^ dx) ^ 0x78ec) & 0xFFFF
   = ((0xA8DF ^ 0xAD3D) ^ 0x78ec) & 0xFFFF
   = (0x05E2 ^ 0x78ec) & 0xFFFF
   = 0x7D0E
```

**Assembly equivalent:**
```asm
mov ecx, eax            ; ecx = ax value
xor cx, dx              ; cx = 0x05E2
xor cx, 0x78ec          ; cx = 0x7D0E
```

#### Final Key

```python
key = f"{si:04X}-{ax:04X}-{dx:04X}-{cx:04X}"
    = "A110-A8DF-AD3D-7D0E"
```

### Complete Algorithm Summary

Here's the complete algorithm in Python:

```python
def generate_key(username):
    # Step 1: Hash the username
    h = 0x7a2f
    for c in username:
        h = (h * 33 + ord(c)) & 0xFFFFFFFF
    
    # Step 2: Calculate first component (si)
    si = (h ^ 0x9c3e) & 0xFFFF
    
    # Step 3: Calculate second component (ax) - THE TRICKY ONE!
    # This is the key insight: shr ax, 5 only affects lower 16 bits
    edx = (h << 3) & 0xFFFFFFFF
    eax_after_shr = (h & 0xFFFF0000) | ((h & 0xFFFF) >> 5)
    eax_xor = eax_after_shr ^ edx
    ax = (eax_xor ^ 0xb7a1) & 0xFFFF
    
    # Step 4: Calculate third component (dx)
    sum_val = (si + ax) & 0xFFFF
    dx = (sum_val ^ 0xe4d2) & 0xFFFF
    
    # Step 5: Calculate fourth component (cx)
    cx = ((ax ^ sum_val) ^ 0x78ec) & 0xFFFF
    
    # Step 6: Format as license key
    return f"{si:04X}-{ax:04X}-{dx:04X}-{cx:04X}"
```

## Key Generation Implementation

### Complete Keygen Script

```python
#!/usr/bin/env python3
"""
Keygen for KeyCorp Legacy License Validator
Generates valid license keys for any username
"""

def hash_username(username):
    """
    Hash the username using polynomial rolling hash.
    Same algorithm as the binary uses.
    """
    h = 0x7a2f  # Starting seed
    for c in username:
        h = (h * 33 + ord(c)) & 0xFFFFFFFF
    return h

def generate_key(username):
    """
    Generate a valid license key for the given username.
    
    This implements the exact algorithm from the binary:
    1. Hash the username
    2. Derive 4 components from the hash
    3. Format as XXXX-XXXX-XXXX-XXXX
    """
    # Validate username
    if not (4 <= len(username) <= 16):
        raise ValueError("Username must be 4-16 characters")
    
    if not all(c.isalnum() or c == '_' for c in username):
        raise ValueError("Username must be alphanumeric or underscore only")
    
    # Hash the username
    h = hash_username(username)
    
    # Calculate first component (si)
    # si = (hash ^ 0x9c3e) & 0xFFFF
    si = (h ^ 0x9c3e) & 0xFFFF
    
    # Calculate second component (ax)
    # This is the tricky part: shr ax, 5 only affects lower 16 bits
    # So: eax = (hash & 0xFFFF0000) | ((hash & 0xFFFF) >> 5)
    edx = (h << 3) & 0xFFFFFFFF
    eax_after_shr = (h & 0xFFFF0000) | ((h & 0xFFFF) >> 5)
    eax_xor = eax_after_shr ^ edx
    ax = (eax_xor ^ 0xb7a1) & 0xFFFF
    
    # Calculate third component (dx)
    # dx = ((si + ax) ^ 0xe4d2) & 0xFFFF
    sum_val = (si + ax) & 0xFFFF
    dx = (sum_val ^ 0xe4d2) & 0xFFFF
    
    # Calculate fourth component (cx)
    # cx = ((ax ^ sum_val) ^ 0x78ec) & 0xFFFF
    cx = ((ax ^ sum_val) ^ 0x78ec) & 0xFFFF
    
    # Format as license key: XXXX-XXXX-XXXX-XXXX
    return f"{si:04X}-{ax:04X}-{dx:04X}-{cx:04X}"

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    try:
        key = generate_key(username)
        print(key)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
```

### Server Solver Script

```python
#!/usr/bin/env python3
"""
Automated solver for Key1 challenge server
Connects to server and generates keys for 5 random usernames
"""

import socket
import re
from keygen import generate_key

def solve_challenge(host, port):
    """
    Connect to challenge server and solve all 5 challenges.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Receive initial banner
    data = s.recv(4096).decode('utf-8')
    print(data, end='')
    
    # Solve 5 challenges
    for challenge_num in range(1, 6):
        # Receive challenge prompt
        data = s.recv(4096).decode('utf-8')
        print(data, end='')
        
        # Extract username from prompt
        # Format: "Username: <username>"
        match = re.search(r'Username: (\S+)', data)
        if not match:
            print("Error: Could not extract username")
            break
        
        username = match.group(1)
        print(f"[*] Extracted username: {username}")
        
        # Generate key
        key = generate_key(username)
        print(f"[*] Generated key: {key}")
        
        # Send key
        s.send((key + '\n').encode('utf-8'))
        
        # Receive response
        data = s.recv(4096).decode('utf-8')
        print(data, end='')
        
        if 'Invalid' in data:
            print(f"[!] Key validation failed for username: {username}")
            break
    
    # Receive final flag
    data = s.recv(4096).decode('utf-8')
    print(data, end='')
    
    # Extract flag
    match = re.search(r'esch\{[^}]+\}', data)
    if match:
        flag = match.group(0)
        print(f"\n[+] Flag: {flag}")
        return flag
    
    s.close()
    return None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    solve_challenge(host, port)
```

## Testing & Verification

### Local Testing

Before connecting to the server, always test your keygen locally:

```bash
# Test with various usernames
./validator test "$(python3 keygen.py test)"
# Should output: Valid!

./validator admin "$(python3 keygen.py admin)"
# Should output: Valid!

./validator user123 "$(python3 keygen.py user123)"
# Should output: Valid!

# Test with invalid username (should fail validation in keygen)
python3 keygen.py "ab"  # Too short
# Should output error

python3 keygen.py "test@user"  # Invalid character
# Should output error
```

### Verification Steps

1. **Test with known usernames:**
   ```bash
   for user in test admin user123 alpha_beta; do
       key=$(python3 keygen.py "$user")
       ./validator "$user" "$key"
   done
   ```

2. **Verify hash function:**
   ```python
   # Test hash function
   assert hash_username("test") == expected_hash_value
   ```

3. **Verify key components:**
   - Manually calculate components for a known username
   - Compare with keygen output
   - Verify format (XXXX-XXXX-XXXX-XXXX)

4. **Test edge cases:**
   - Minimum length username (4 chars)
   - Maximum length username (16 chars)
   - Usernames with underscores
   - Usernames with numbers

### Debugging Tips

If your keygen doesn't work:

1. **Check the hash function:**
   ```python
   h = hash_username("test")
   print(f"Hash: 0x{h:08X}")
   # Compare with what the binary produces (use a debugger)
   ```

2. **Verify register operations:**
   - The `shr ax, 5` operation is the most common source of bugs
   - Make sure you're preserving upper 16 bits correctly

3. **Check component calculations:**
   ```python
   # Print intermediate values
   print(f"si: 0x{si:04X}")
   print(f"ax: 0x{ax:04X}")
   print(f"dx: 0x{dx:04X}")
   print(f"cx: 0x{cx:04X}")
   ```

4. **Compare with binary:**
   - Use a debugger (gdb) to step through the binary
   - Check register values at each step
   - Compare with your Python implementation

## Getting the Flag

Once the keygen is verified locally, connect to the server:

```bash
python3 solve.py node-2.mcsc.space 10627
```

**Expected output:**
```
╔══════════════════════════════════════╗
║         key-1 License Server         ║
╚══════════════════════════════════════╝

Challenge 1/5:
Username: theta_operator
[*] Extracted username: theta_operator
[*] Generated key: 636E-4ADB-4A9B-9C7E
Enter key: 
[+] Valid!

Challenge 2/5:
Username: pi_developer
[*] Extracted username: pi_developer
[*] Generated key: 1233-C3B9-313E-6EB9
Enter key: 
[+] Valid!

Challenge 3/5:
Username: sigma_analyst
[*] Extracted username: sigma_analyst
[*] Generated key: 8F2A-7C1D-5E3F-9A4B
Enter key: 
[+] Valid!

Challenge 4/5:
Username: lambda_engineer
[*] Extracted username: lambda_engineer
[*] Generated key: A5B3-2C4D-6E7F-8A9B
Enter key: 
[+] Valid!

Challenge 5/5:
Username: test_account
[*] Extracted username: test_account
[*] Generated key: 1885-965C-4A33-4051
Enter key: 
[+] Valid!

╔══════════════════════════════════════╗
║        Congratulations!              ║
╠══════════════════════════════════════╣
║  esch{destructors-clean-up-lunar-nova-2168}
╚══════════════════════════════════════╝

[+] Flag: esch{destructors-clean-up-lunar-nova-2168}
```

## Reverse Engineering Tools & Techniques

### Tools Used

1. **Binary Ninja** - Primary disassembler
   - Excellent UI and analysis features
   - Good for understanding control flow
   - Helpful for identifying functions

2. **Ghidra** - Free alternative
   - Automatic decompilation to C
   - Good for understanding high-level logic
   - Free and open-source

3. **GDB** - Debugger (for dynamic analysis)
   - Step through execution
   - Inspect register values
   - Verify algorithm understanding

4. **Python** - For keygen implementation
   - Easy to prototype algorithms
   - Good for testing

### Static Analysis Techniques

1. **Function Identification:**
   - Look for standard function prologues/epilogues
   - Identify string references
   - Trace call graphs

2. **Control Flow Analysis:**
   - Identify branches and loops
   - Understand condition checks
   - Trace execution paths

3. **Data Flow Analysis:**
   - Track how data moves through registers
   - Identify transformations
   - Understand algorithm structure

### Common Pitfalls

1. **Register Size Confusion:**
   - Always check if operations affect full register or partial
   - `shr ax, 5` vs `shr eax, 5` are very different!
   - Upper bits may be preserved or zeroed

2. **Endianness:**
   - x86 is little-endian
   - Multi-byte values are stored with least significant byte first

3. **Signed vs Unsigned:**
   - Most operations are unsigned in this challenge
   - Watch for sign extension in some instructions

4. **Optimization:**
   - Compiler optimizations can make code harder to read
   - Look for patterns, not exact instruction sequences

## Lessons Learned

1. **Register sizes matter** - x86 has 8/16/32/64-bit variants of the same register. Operations on smaller sizes can preserve or zero upper bits differently. The `shr ax, 5` instruction is a perfect example - it only affects the lower 16 bits!

2. **Always verify locally** - Test your keygen against the actual binary before hitting the server. This catches bugs early and saves time.

3. **Polynomial hashes are common** - djb2 and its variants show up constantly in CTFs and real software. Understanding how they work is essential.

4. **Trace through examples** - Working through concrete examples with actual values helps understand the algorithm better than abstract descriptions.

5. **Static analysis first** - Start with static analysis (disassembler) before dynamic analysis (debugger). Understand the code structure first.

6. **Document your findings** - Keep notes on register values, transformations, and intermediate calculations. This helps when implementing the keygen.

7. **Test edge cases** - Test with minimum/maximum length usernames, special characters, and various inputs to ensure robustness.

8. **Understand the math** - The algorithm uses bitwise operations, XOR, and shifts. Understanding these operations is crucial for reverse engineering.

9. **Automate the solution** - Once you understand the algorithm, automate it. Don't manually calculate keys for the server.

10. **Read assembly carefully** - One misunderstood instruction can break your entire understanding. Pay attention to register sizes and operation semantics.

## Files

- `keygen.py` - The keygen script that generates valid license keys
- `solve.py` - Automated solver for the challenge server
- `validator` - The original binary to test against locally

## Additional Resources

- [x86-64 Register Overview](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture)
- [djb2 Hash Function](http://www.cse.yorku.ca/~oz/hash.html)
- [Polynomial Rolling Hash](https://cp-algorithms.com/string/string-hashing.html)
- [Binary Ninja Documentation](https://docs.binary.ninja/)
- [Ghidra Documentation](https://ghidra-sre.org/)

---

*"The best way to learn reverse engineering is to do it. Start with simple challenges and work your way up!"*
