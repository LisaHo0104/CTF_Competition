# Retro - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**Points:** 500  
**CTF:** EschatonCTF 2026  
**Flag:** `esch{g4m3b0y_r3vved_634512}`

## Challenge Description

We're given a Game Boy ROM file called `retro.gb`. The challenge description says the game is "broken" and we need to find the flag. However, the "broken" code is actually intentional - it's the key to decrypting the flag!

## Quick Solution

1. Extract encrypted data from the ROM at offsets 0x508 and 0x515
2. Decrypt both blocks using XOR key 0xA5
3. Map the decrypted tile indices to characters using the font table
4. Combine to get the flag: `esch{g4m3b0y_r3vved_634512}`

## Step-by-Step Solution

### Step 1: Examine the ROM File

First, let's check what we have:

```bash
file retro.gb
# retro.gb: Game Boy ROM image: "RETRO" (Rev.00) [ROM ONLY], ROM: 256Kbit
```

Good! It's a valid Game Boy ROM. Now let's look at the raw data:

```bash
hexdump -C retro.gb | head -20
```

From the hexdump, we can see:
- At offset `0x130`: `52 45 54 52 4f` = "RETRO" (the game title)
- The ROM contains code and data we need to analyze

### Step 2: Find the Encrypted Data

Looking at the hexdump output you provided, we can see encrypted data blocks:

**Block 1** starts at offset `0x508`:
```
00000500  ... ba 88 b8 87 e5 84 9c 82 9d b9 90 96 e7 ...
```

**Block 2** starts at offset `0x515`:
```
00000510  ... 89 9d 95 95 ba bb e7 9e 9d 9c 9f 93 92 e4 ...
```

Let's extract these:

**Block 1 (13 bytes):**
```
ba 88 b8 87 e5 84 9c 82 9d b9 90 96 e7
```

**Block 2 (14 bytes):**
```
89 9d 95 95 ba bb e7 9e 9d 9c 9f 93 92 e4
```

### Step 3: Find the Encryption Key

Looking at the hexdump around offset `0x180`:

```
00000180  ... 3e a5 ea 06 c0 ...
```

This is Game Boy assembly code:
- `3e a5` = `LD A, $A5` (load 0xA5 into register A)
- `ea 06 c0` = `LD [$C006], A` (store A to memory address 0xC006)

So the encryption key is **0xA5** and it's stored at memory address 0xC006.

### Step 4: Understand the "Broken" Code

At offset `0x1A0` in the hexdump:

```
000001a0  ... cd fd 01 ...
```

This is `CALL $01FD` - it calls the function at address 0x01FD.

But if we look at what's at 0x01FD:

```
000001f0  ... c9 ...
```

That's just `RET` (return) - it does nothing!

The actual key toggle function is at 0x01FE:

```
000001f0  ... fa 06 c0 ee ff ea 06 c0 c9
```

This is:
- `fa 06 c0` = `LD A, [$C006]` (load key from memory)
- `ee ff` = `XOR A, $FF` (flip all bits: 0xA5 becomes 0x5A)
- `ea 06 c0` = `LD [$C006], A` (store back)
- `c9` = `RET` (return)

**The "broken" code calls 0x01FD (does nothing) instead of 0x01FE (toggles key).**

This means the key stays at 0xA5 for both blocks, which is what we need!

### Step 5: Decrypt Block 1

Block 1 encrypted data:
```
ba 88 b8 87 e5 84 9c 82 9d b9 90 96 e7
```

Decrypt by XORing each byte with 0xA5:

```python
encrypted1 = [0xba, 0x88, 0xb8, 0x87, 0xe5, 0x84, 0x9c, 0x82, 0x9d, 0xb9, 0x90, 0x96, 0xe7]
key = 0xA5

decrypted1 = [b ^ key for b in encrypted1]
print([hex(b) for b in decrypted1])
```

**Result:**
```
[0x1f, 0x2d, 0x1d, 0x22, 0x40, 0x21, 0x39, 0x27, 0x38, 0x1c, 0x35, 0x33, 0x42]
```

These are tile indices that map to characters.

### Step 6: Decrypt Block 2

Block 2 encrypted data:
```
89 9d 95 95 ba bb e7 9e 9d 9c 9f 93 92 e4
```

Decrypt with the same key (0xA5) because the toggle was skipped:

```python
encrypted2 = [0x89, 0x9d, 0x95, 0x95, 0xba, 0xbb, 0xe7, 0x9e, 0x9d, 0x9c, 0x9f, 0x93, 0x92, 0xe4]
key = 0xA5

decrypted2 = [b ^ key for b in encrypted2]
print([hex(b) for b in decrypted2])
```

**Result:**
```
[0x2c, 0x38, 0x30, 0x30, 0x1f, 0x1e, 0x42, 0x3b, 0x38, 0x39, 0x3a, 0x36, 0x37, 0x41]
```

### Step 7: Map Tile Indices to Characters

Game Boy uses tile indices to display characters. We need to map these indices to ASCII characters.

**Font mapping table:**

| Tile Index | Character | Tile Index | Character | Tile Index | Character |
|------------|-----------|------------|-----------|------------|-----------|
| 0x00 | space | 0x1B | a | 0x35 | 0 |
| 0x01 | A | 0x1C | b | 0x36 | 1 |
| 0x02 | B | 0x1D | c | 0x37 | 2 |
| 0x03 | C | 0x1E | d | 0x38 | 3 |
| 0x04 | D | 0x1F | e | 0x39 | 4 |
| 0x05 | E | 0x20 | f | 0x3A | 5 |
| 0x06 | F | 0x21 | g | 0x3B | 6 |
| 0x07 | G | 0x22 | h | 0x3C | 7 |
| 0x08 | H | 0x23 | i | 0x3D | 8 |
| 0x09 | I | 0x24 | j | 0x3E | 9 |
| 0x0A | J | 0x25 | k | 0x40 | { |
| 0x0B | K | 0x26 | l | 0x41 | } |
| 0x0C | L | 0x27 | m | 0x42 | _ |
| 0x0D | M | 0x28 | n | | |
| 0x0E | N | 0x29 | o | | |
| 0x0F | O | 0x2A | p | | |
| 0x10 | P | 0x2B | q | | |
| 0x11 | Q | 0x2C | r | | |
| 0x12 | R | 0x2D | s | | |
| 0x13 | S | 0x2E | t | | |
| 0x14 | T | 0x2F | u | | |
| 0x15 | U | 0x30 | v | | |
| 0x16 | V | 0x31 | w | | |
| 0x17 | W | 0x32 | x | | |
| 0x18 | X | 0x33 | y | | |
| 0x19 | Y | 0x34 | z | | |
| 0x1A | Z | | | | |

**Decode Block 1:**
```
0x1f = 'e'
0x2d = 's'
0x1d = 'c'
0x22 = 'h'
0x40 = '{'
0x21 = 'g'
0x39 = '4'
0x27 = 'm'
0x38 = '3'
0x1c = 'b'
0x35 = '0'
0x33 = 'y'
0x42 = '_'
```

**Result:** `esch{g4m3b0y_`

**Decode Block 2:**
```
0x2c = 'r'
0x38 = '3'
0x30 = 'v'
0x30 = 'v'
0x1f = 'e'
0x1e = 'd'
0x42 = '_'
0x3b = '6'
0x38 = '3'
0x39 = '4'
0x3a = '5'
0x36 = '1'
0x37 = '2'
0x41 = '}'
```

**Result:** `r3vved_634512}`

### Step 8: Combine the Blocks

**Final flag:**
```
esch{g4m3b0y_r3vved_634512}
```

## Complete Python Script

Here's a complete script that does everything:

```python
#!/usr/bin/env python3
"""
Decrypt Game Boy ROM flag - Complete Solution
"""

# Encrypted data blocks from the ROM
block1_encrypted = bytes.fromhex("ba88b887e5849c829db99096e7")
block2_encrypted = bytes.fromhex("899d9595babbe79e9d9c9f9392e4")

# Encryption key (found at offset 0x180: 3e a5 = LD A, $A5)
key = 0xA5

# Decrypt both blocks
block1_decrypted = bytes(b ^ key for b in block1_encrypted)
block2_decrypted = bytes(b ^ key for b in block2_encrypted)

print("Block 1 decrypted (hex):", block1_decrypted.hex())
print("Block 2 decrypted (hex):", block2_decrypted.hex())
print()

# Font mapping: tile index -> character
font_map = {
    0x00: ' ', 0x01: 'A', 0x02: 'B', 0x03: 'C', 0x04: 'D', 0x05: 'E',
    0x06: 'F', 0x07: 'G', 0x08: 'H', 0x09: 'I', 0x0A: 'J', 0x0B: 'K',
    0x0C: 'L', 0x0D: 'M', 0x0E: 'N', 0x0F: 'O', 0x10: 'P', 0x11: 'Q',
    0x12: 'R', 0x13: 'S', 0x14: 'T', 0x15: 'U', 0x16: 'V', 0x17: 'W',
    0x18: 'X', 0x19: 'Y', 0x1A: 'Z',
    0x1B: 'a', 0x1C: 'b', 0x1D: 'c', 0x1E: 'd', 0x1F: 'e', 0x20: 'f',
    0x21: 'g', 0x22: 'h', 0x23: 'i', 0x24: 'j', 0x25: 'k', 0x26: 'l',
    0x27: 'm', 0x28: 'n', 0x29: 'o', 0x2A: 'p', 0x2B: 'q', 0x2C: 'r',
    0x2D: 's', 0x2E: 't', 0x2F: 'u', 0x30: 'v', 0x31: 'w', 0x32: 'x',
    0x33: 'y', 0x34: 'z',
    0x35: '0', 0x36: '1', 0x37: '2', 0x38: '3', 0x39: '4', 0x3A: '5',
    0x3B: '6', 0x3C: '7', 0x3D: '8', 0x3E: '9',
    0x40: '{', 0x41: '}', 0x42: '_'
}

# Convert tile indices to characters
def tiles_to_string(tile_indices):
    result = []
    for tile_idx in tile_indices:
        char = font_map.get(tile_idx, '?')
        result.append(char)
    return ''.join(result)

# Decode both blocks
flag_part1 = tiles_to_string(block1_decrypted)
flag_part2 = tiles_to_string(block2_decrypted)

# Combine to get full flag
flag = flag_part1 + flag_part2

print("Block 1 as text:", flag_part1)
print("Block 2 as text:", flag_part2)
print()
print("=" * 50)
print("FLAG:", flag)
print("=" * 50)
```

**Run it:**
```bash
python3 decrypt.py
```

**Output:**
```
Block 1 decrypted (hex): 1f2d1d2240213927381c353342
Block 2 decrypted (hex): 2c3830301f1e423b38393a363741

Block 1 as text: esch{g4m3b0y_
Block 2 as text: r3vved_634512}

==================================================
FLAG: esch{g4m3b0y_r3vved_634512}
==================================================
```

## Manual Calculation Example

Let's manually decrypt the first few bytes to show how it works:

**Block 1, first byte:**
```
Encrypted: 0xba
Key:       0xA5
XOR:       0xba XOR 0xA5 = 0x1f
Tile index: 0x1f
Character: 'e' (from font map)
```

**Block 1, second byte:**
```
Encrypted: 0x88
Key:       0xA5
XOR:       0x88 XOR 0xA5 = 0x2d
Tile index: 0x2d
Character: 's' (from font map)
```

Continue for all bytes...

## Why the "Broken" Code is Important

The code at offset 0x1A0 calls `0x01FD` instead of `0x01FE`:

- **0x01FD** = `RET` (does nothing)
- **0x01FE** = Key toggle function (would change key from 0xA5 to 0x5A)

If the code was "fixed" to call 0x01FE:
- Block 1 would decrypt with 0xA5 ✓
- Key would toggle to 0x5A
- Block 2 would decrypt with 0x5A ✗ (wrong key, produces garbage!)

So the "broken" code is actually **correct** - both blocks were encrypted with 0xA5, so both need to decrypt with 0xA5.

## Verification

You can verify the solution by:
1. Running the Python script above
2. Opening the ROM in a Game Boy emulator (mGBA, BGB, etc.)
3. The flag should be visible in the game

## Summary

1. **Extract encrypted data:**
   - Block 1: `ba 88 b8 87 e5 84 9c 82 9d b9 90 96 e7` (offset 0x508)
   - Block 2: `89 9d 95 95 ba bb e7 9e 9d 9c 9f 93 92 e4` (offset 0x515)

2. **Find encryption key:**
   - Key = 0xA5 (found at offset 0x180: `3e a5`)

3. **Decrypt both blocks:**
   - XOR each byte with 0xA5

4. **Map tile indices to characters:**
   - Use the font mapping table
   - 0x1f = 'e', 0x2d = 's', etc.

5. **Combine blocks:**
   - `esch{g4m3b0y_` + `r3vved_634512}` = `esch{g4m3b0y_r3vved_634512}`

## Flag

```
esch{g4m3b0y_r3vved_634512}
```

**Translation:** "GameBoy revved" (reverse engineered) - because that's exactly what we did!

## Tools Used

- `hexdump` - View raw ROM data
- `python3` - Decrypt and decode the flag
- Game Boy emulator (optional) - To run the ROM

---

*The "broken" code is the solution!*
