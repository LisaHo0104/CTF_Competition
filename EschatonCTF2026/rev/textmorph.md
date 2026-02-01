# TextMorph - Reverse Engineering Writeup

**Category:** Reverse Engineering  
**Points:** 500  
**Author:** @solvz  
**Flag:** `esch{f0und_th3_h1dden_r1gby}`

## Challenge Description

We're given a mysterious binary called `textmorph` described as a "text transformation utility from a suspicious source." The challenge hints that there's something hidden inside. Our job is to figure out what it's hiding and extract the flag.

## TL;DR

PyInstaller-packed Python executable containing hidden data. Extract the embedded Python bytecode, analyze it to find a base64-encoded zlib-compressed blob, decompress it to reveal an animated GIF, and read the flag from the animation overlay: `esch{f0und_th3_h1dden_r1gby}`.

## Initial Analysis

### Step 1: Identify the Binary Type

First, let's see what kind of file we're dealing with:

```bash
file textmorph
```

**Output:**
```
textmorph: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped, with debug_info, not stripped
```

Wait, that's not quite right. Let's check more carefully:

```bash
strings textmorph | head -20
```

Looking at the strings, we might see references to Python or PyInstaller. Let's also check the file size:

```bash
ls -lh textmorph
# textmorph: ~11MB (suspiciously large for a simple text utility)
```

A large binary size (11MB) for a "simple text utility" is a red flag. This suggests it might be a packed executable.

### Step 2: Check for PyInstaller Signatures

PyInstaller executables have distinctive characteristics:

1. **Magic bytes:** Look for `MEI\014\013\010\013\016` in the file
2. **Python strings:** References to Python libraries
3. **Large size:** Bundles Python interpreter and libraries

Let's check:

```bash
strings textmorph | grep -i "pyinstaller\|python\|MEI"
```

If we see PyInstaller references, we're dealing with a PyInstaller-packed executable.

### Step 3: Test the Binary

Let's see what the binary does:

```bash
./textmorph --help
```

**Expected output:**
```
Usage: textmorph [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  encode   Encode text
  decode   Decode text
  hash     Hash text
  reverse  Reverse text
```

It looks like a legitimate text utility, but we know there's more hidden inside.

## Methodology

### Step 1: Identify PyInstaller Binary

1. Check file type and size
2. Look for PyInstaller signatures
3. Verify it's a PyInstaller executable

### Step 2: Extract PyInstaller Contents

1. Use pyinstxtractor to unpack the executable
2. Identify extracted files
3. Find the main Python bytecode file

### Step 3: Analyze Python Bytecode

1. Load the .pyc file
2. Extract constants using marshal
3. Search for interesting strings
4. Identify hidden data blobs

### Step 4: Extract Hidden Data

1. Find base64-encoded blobs
2. Identify compression (zlib, gzip, etc.)
3. Decode and decompress
4. Save the result

### Step 5: Extract the Flag

1. Open the extracted file (GIF, image, etc.)
2. Read the flag from the content
3. Verify the flag format

## PyInstaller Deep Dive

### What is PyInstaller?

**PyInstaller** is a tool that bundles Python applications into standalone executables. It:

- Packages the Python interpreter
- Bundles all required libraries
- Includes the Python source code (as bytecode)
- Creates a single executable file

### PyInstaller Executable Structure

A PyInstaller executable contains:

1. **Bootstrap code** - Extracts and runs the Python code
2. **Python interpreter** - Embedded Python runtime
3. **Python libraries** - Required dependencies
4. **Application code** - Your Python script as bytecode (.pyc)
5. **Data files** - Any additional resources

### Identifying PyInstaller Binaries

**Signatures to look for:**

1. **Magic bytes:** `MEI\014\013\010\013\016` (PyInstaller archive marker)
2. **File size:** Usually large (several MB) due to bundled Python
3. **Strings:** References to `PyInstaller`, `python`, `libpython`
4. **Behavior:** May create temporary directories when run

**Check for magic bytes:**
```bash
hexdump -C textmorph | grep -i "MEI"
# Or
strings textmorph | grep -i "pyinstaller"
```

### Using pyinstxtractor

**pyinstxtractor** is a Python script that extracts files from PyInstaller executables.

**Download:**
```bash
wget https://github.com/extremecoders-re/pyinstxtractor/raw/master/pyinstxtractor.py
```

**Usage:**
```bash
python3 pyinstxtractor.py textmorph
```

**What it does:**
- Parses the PyInstaller archive structure
- Extracts all bundled files
- Saves them to a directory (usually `textmorph_extracted/`)

**Output:**
```
[+] Processing textmorph
[+] PyInstaller version: 5.x
[+] Python version: 3.x
[+] Extracting files...
[+] Extraction complete!
```

**Extracted files:**
- `textmorph_embedded.pyc` - The main Python bytecode (often very large)
- Various library files
- Other resources

## Python Bytecode Analysis

### What are .pyc Files?

**Python bytecode files (.pyc)** are compiled Python code:

- **Source:** Python source code (`.py`)
- **Compiled:** Python bytecode (`.pyc`)
- **Format:** Binary format using Python's `marshal` module
- **Purpose:** Faster execution (avoids re-parsing source)

### Python Bytecode Format

A `.pyc` file has this structure:

```
[4 bytes] Magic number (Python version)
[4 bytes] Timestamp (optional)
[4 bytes] Source file size (optional)
[Marshal data] Compiled code object
```

**Magic numbers:**
- Different Python versions have different magic numbers
- Used to verify compatibility

### The marshal Module

Python's `marshal` module can read/write Python bytecode:

```python
import marshal

# Read a .pyc file
with open('file.pyc', 'rb') as f:
    magic = f.read(4)      # Magic number
    timestamp = f.read(4)  # Timestamp (if present)
    size = f.read(4)       # Source size (if present)
    code = marshal.load(f) # Load the code object
```

### Code Objects

A Python code object has several attributes:

- `co_consts` - Tuple of constants (strings, numbers, etc.)
- `co_names` - Tuple of names (variables, functions)
- `co_code` - Bytecode instructions
- `co_filename` - Source filename
- `co_name` - Function/class name

**Most useful for CTF:** `co_consts` contains all string literals!

### Extracting Constants

Here's how to extract all string constants from a .pyc file:

```python
import marshal

def extract_strings_from_pyc(pyc_file):
    """Extract all string constants from a .pyc file."""
    with open(pyc_file, 'rb') as f:
        # Skip header (16 bytes typically)
        f.read(16)
        
        # Load code object
        code = marshal.load(f)
        
        # Recursively extract strings from constants
        strings = []
        extract_strings(code.co_consts, strings)
        return strings

def extract_strings(consts, strings):
    """Recursively extract strings from constants."""
    for const in consts:
        if isinstance(const, str):
            strings.append(const)
        elif isinstance(const, (tuple, list)):
            extract_strings(const, strings)
        elif hasattr(const, 'co_consts'):  # Nested code object
            extract_strings(const.co_consts, strings)
```

## Data Extraction Process

### Step 1: Extract the .pyc File

After running pyinstxtractor:

```bash
ls -lh textmorph_extracted/
```

Look for a large `.pyc` file (often several MB). This is likely `textmorph_embedded.pyc` or similar.

### Step 2: Analyze the Bytecode

Let's extract all strings from the bytecode:

```python
#!/usr/bin/env python3
"""
Extract strings from PyInstaller .pyc file
"""

import marshal
import sys

def extract_all_strings(pyc_file):
    """Extract all string constants from a .pyc file."""
    strings = []
    
    with open(pyc_file, 'rb') as f:
        # Skip PyInstaller header (16 bytes)
        header = f.read(16)
        
        try:
            # Load code object
            code = marshal.load(f)
            extract_strings_recursive(code.co_consts, strings)
        except Exception as e:
            print(f"Error: {e}")
            return strings
    
    return strings

def extract_strings_recursive(consts, strings):
    """Recursively extract strings from constants."""
    for const in consts:
        if isinstance(const, str):
            # Only save interesting strings (not too short, not too long)
            if len(const) > 10:  # Filter out very short strings
                strings.append(const)
        elif isinstance(const, (tuple, list)):
            extract_strings_recursive(const, strings)
        elif hasattr(const, 'co_consts'):  # Nested code object
            extract_strings_recursive(const.co_consts, strings)
        elif hasattr(const, '__dict__'):  # Other objects
            try:
                extract_strings_recursive(const.__dict__.values(), strings)
            except:
                pass

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pyc_file>")
        sys.exit(1)
    
    pyc_file = sys.argv[1]
    strings = extract_all_strings(pyc_file)
    
    # Print all strings
    for i, s in enumerate(strings):
        print(f"{i}: {s[:100]}...")  # Print first 100 chars
```

**Run it:**
```bash
python3 extract_strings.py textmorph_extracted/textmorph_embedded.pyc > strings.txt
```

### Step 3: Identify Interesting Strings

Look for:

1. **Fake flags:** `CTF{...}`, `flag{...}`, etc.
2. **Base64 blobs:** Long strings starting with `eNrc`, `H4sI`, etc.
3. **Hidden commands:** Unusual command-line flags
4. **Suspicious strings:** Encoded/obfuscated data

**Example output:**
```
0: CTF{tr0lled_by_v3rsi0n_str1ng}...
1: CTF{c0nfig_1s_n0t_th3_w4y}...
2: CTF{3nv_v4r_tr4p_l0l}...
3: CTF{l3g4cy_c0d3_tr4p_h4h4}...
4: --morph-hierarchical-sync...
5: eNrc22VTW23Dtm... (very long base64 string)
```

### Step 4: Find the Hidden Data Blob

The base64 blob is usually:
- **Very long** (thousands of characters)
- **Starts with specific prefixes:**
  - `eNrc...` - zlib-compressed data
  - `H4sI...` - gzip-compressed data
  - `UEsDBA...` - ZIP file
  - `iVBORw0KGgo...` - PNG image (base64)

In this challenge, we find a blob starting with `eNrc...` which indicates **zlib compression**.

## Decoding Process

### Step 1: Extract the Base64 Blob

First, we need to get the full base64 string from the bytecode:

```python
#!/usr/bin/env python3
"""
Extract and decode the hidden data blob
"""

import marshal
import base64
import zlib
import sys

def find_base64_blob(pyc_file):
    """Find the large base64 blob in the .pyc file."""
    with open(pyc_file, 'rb') as f:
        f.read(16)  # Skip header
        code = marshal.load(f)
        
        # Search for base64 strings
        blobs = []
        find_base64_in_consts(code.co_consts, blobs)
        
        # Return the largest one (likely the hidden data)
        if blobs:
            return max(blobs, key=len)
        return None

def find_base64_in_consts(consts, blobs):
    """Recursively find base64 strings."""
    for const in consts:
        if isinstance(const, str):
            # Check if it looks like base64 and is long
            if len(const) > 1000 and is_base64_like(const):
                blobs.append(const)
        elif isinstance(const, (tuple, list)):
            find_base64_in_consts(const, blobs)
        elif hasattr(const, 'co_consts'):
            find_base64_in_consts(const.co_consts, blobs)

def is_base64_like(s):
    """Check if string looks like base64."""
    try:
        # Base64 characters: A-Z, a-z, 0-9, +, /, =
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        return all(c in base64_chars or c.isspace() for c in s[:100])
    except:
        return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pyc_file>")
        sys.exit(1)
    
    pyc_file = sys.argv[1]
    blob = find_base64_blob(pyc_file)
    
    if not blob:
        print("No base64 blob found!")
        sys.exit(1)
    
    print(f"Found blob: {len(blob)} characters")
    print(f"First 100 chars: {blob[:100]}")
```

### Step 2: Decode Base64

Base64 decoding converts the string back to binary:

```python
import base64

# The blob from the .pyc file
blob = "eNrc22VTW23Dtm..."  # Full base64 string

# Decode base64
decoded = base64.b64decode(blob)
print(f"Decoded size: {len(decoded)} bytes")
```

**What base64 does:**
- Encodes binary data as ASCII text
- Uses 64 characters: A-Z, a-z, 0-9, +, /
- Padding with `=` if needed
- Increases size by ~33%

### Step 3: Decompress with zlib

The decoded data is zlib-compressed:

```python
import zlib

# Decompress zlib data
try:
    decompressed = zlib.decompress(decoded)
    print(f"Decompressed size: {len(decompressed)} bytes")
except zlib.error as e:
    print(f"Not zlib compressed: {e}")
    # Try other compression methods...
```

**What zlib does:**
- Compresses data using DEFLATE algorithm
- Reduces file size
- Common in Python (used by `gzip`, `zipfile`, etc.)

### Step 4: Save the Result

Save the decompressed data:

```python
# Determine file type and save
output_file = 'hidden_data'

# Check if it's a known file type
if decompressed.startswith(b'GIF'):
    output_file = 'hidden.gif'
elif decompressed.startswith(b'\x89PNG'):
    output_file = 'hidden.png'
elif decompressed.startswith(b'PK'):
    output_file = 'hidden.zip'

with open(output_file, 'wb') as f:
    f.write(decompressed)

print(f"Saved to {output_file}")
```

### Complete Decoding Script

```python
#!/usr/bin/env python3
"""
Complete script to extract and decode hidden data from textmorph
"""

import marshal
import base64
import zlib
import sys

def extract_base64_blob(pyc_file):
    """Extract the largest base64 blob from .pyc file."""
    blobs = []
    
    with open(pyc_file, 'rb') as f:
        f.read(16)  # Skip header
        code = marshal.load(f)
        find_base64_strings(code.co_consts, blobs)
    
    if not blobs:
        return None
    
    # Return the largest blob (likely the hidden data)
    return max(blobs, key=len)

def find_base64_strings(consts, blobs):
    """Recursively find base64 strings."""
    for const in consts:
        if isinstance(const, str):
            # Look for long base64-like strings
            if len(const) > 1000:
                # Check if it's base64
                try:
                    # Try to decode a sample
                    base64.b64decode(const[:100] + '==')
                    blobs.append(const)
                except:
                    pass
        elif isinstance(const, (tuple, list)):
            find_base64_strings(const, blobs)
        elif hasattr(const, 'co_consts'):
            find_base64_strings(const.co_consts, blobs)

def decode_blob(blob):
    """Decode base64 and decompress zlib."""
    # Step 1: Decode base64
    try:
        decoded = base64.b64decode(blob)
        print(f"[+] Base64 decoded: {len(decoded)} bytes")
    except Exception as e:
        print(f"[-] Base64 decode failed: {e}")
        return None
    
    # Step 2: Decompress zlib
    try:
        decompressed = zlib.decompress(decoded)
        print(f"[+] Zlib decompressed: {len(decompressed)} bytes")
        return decompressed
    except zlib.error:
        print("[-] Not zlib compressed, trying other methods...")
        # Could try gzip, bz2, etc.
        return decoded

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 decode.py <pyc_file> [output_file]")
        sys.exit(1)
    
    pyc_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'hidden.gif'
    
    print(f"[*] Extracting base64 blob from {pyc_file}...")
    blob = extract_base64_blob(pyc_file)
    
    if not blob:
        print("[-] No base64 blob found!")
        sys.exit(1)
    
    print(f"[+] Found blob: {len(blob)} characters")
    
    print(f"[*] Decoding and decompressing...")
    data = decode_blob(blob)
    
    if data:
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"[+] Saved to {output_file}")
    else:
        print("[-] Decoding failed!")
```

## Hidden Command Analysis

### Finding the Hidden Flag

While analyzing the bytecode strings, we might find:

```
--morph-hierarchical-sync
```

This is a **hidden command-line flag** that's not shown in `--help`.

### Testing the Hidden Command

```bash
./textmorph --morph-hierarchical-sync
```

**Output:**
```
Cache synchronized.
```

This doesn't reveal much, but it confirms the flag exists. The real data is in the base64 blob, not in the command output.

### Why Hide It?

The hidden flag is likely:
- A red herring (distraction)
- Part of the challenge's theme
- Not actually needed to solve the challenge

The real solution is extracting and decoding the base64 blob.

## Flag Extraction

### The Hidden GIF

After decoding, we get a file (likely `hidden.gif`). Let's examine it:

```bash
file hidden.gif
# hidden.gif: GIF image data, version 89a, 74 frames
```

It's an **animated GIF** with 74 frames!

### Viewing the GIF

Open it in any image viewer:

```bash
# Linux
xdg-open hidden.gif
# or
eog hidden.gif

# macOS
open hidden.gif

# Windows
start hidden.gif
```

### Reading the Flag

The GIF shows:
- A **dancing cat animation** (74 frames)
- **Text overlay** spelling out the flag

The flag text is:
```
esch{f0und_th3_h1dden_r1gby}
```

**Leetspeak translation:**
- `f0und` = "found" (0 instead of o)
- `th3` = "the" (3 instead of e)
- `h1dden` = "hidden" (1 instead of i)
- `r1gby` = "rigby" (1 instead of i)

The text appears overlaid on the animation, so you need to watch the GIF to see it.

### Alternative: Extract Frames

If the text is hard to read, you can extract individual frames:

```bash
# Using ImageMagick
convert hidden.gif -coalesce frame_%02d.png

# Or using ffmpeg
ffmpeg -i hidden.gif frame_%02d.png
```

Then examine the frames to read the flag text.

## Fake Flags Analysis

### Why Fake Flags?

The challenge author included multiple **fake flags** to:
- **Troll solvers** who just grep for `CTF{` or `flag{`
- **Add realism** - real malware often has decoy strings
- **Make the challenge harder** - forces deeper analysis

### Fake Flags Found

From the bytecode analysis, we found:

1. `CTF{tr0lled_by_v3rsi0n_str1ng}`
2. `CTF{c0nfig_1s_n0t_th3_w4y}`
3. `CTF{3nv_v4r_tr4p_l0l}`
4. `CTF{l3g4cy_c0d3_tr4p_h4h4}`

**None of these work!** They're all decoys.

### Identifying Real vs Fake Flags

**Real flags:**
- Usually in the format specified by the CTF (e.g., `esch{...}`)
- Hidden in encoded/compressed data
- Not easily found with simple string searches
- Require actual reverse engineering

**Fake flags:**
- Often in common formats (`CTF{...}`, `flag{...}`)
- Found in plain strings
- Don't work when submitted
- Designed to waste your time

**Lesson:** Always verify flags before submitting, and don't trust the first flag you find!

## Complete Solution Script

Here's a complete script that does everything:

```python
#!/usr/bin/env python3
"""
Complete solution for textmorph challenge
Extracts hidden GIF and reveals the flag
"""

import marshal
import base64
import zlib
import sys
import os

def extract_strings_from_pyc(pyc_file):
    """Extract all strings from .pyc file."""
    strings = []
    
    with open(pyc_file, 'rb') as f:
        f.read(16)  # Skip header
        code = marshal.load(f)
        extract_strings_recursive(code.co_consts, strings)
    
    return strings

def extract_strings_recursive(consts, strings):
    """Recursively extract strings."""
    for const in consts:
        if isinstance(const, str):
            strings.append(const)
        elif isinstance(const, (tuple, list)):
            extract_strings_recursive(const, strings)
        elif hasattr(const, 'co_consts'):
            extract_strings_recursive(const.co_consts, strings)

def find_largest_base64(strings):
    """Find the largest base64-like string."""
    candidates = []
    
    for s in strings:
        if len(s) > 1000:  # Must be large
            try:
                # Try to decode a sample
                base64.b64decode(s[:100] + '==')
                candidates.append(s)
            except:
                pass
    
    if candidates:
        return max(candidates, key=len)
    return None

def decode_and_save(blob, output_file):
    """Decode base64 and decompress zlib."""
    try:
        # Decode base64
        decoded = base64.b64decode(blob)
        print(f"[+] Base64 decoded: {len(decoded)} bytes")
        
        # Decompress zlib
        decompressed = zlib.decompress(decoded)
        print(f"[+] Zlib decompressed: {len(decompressed)} bytes")
        
        # Save
        with open(output_file, 'wb') as f:
            f.write(decompressed)
        
        print(f"[+] Saved to {output_file}")
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <pyc_file>")
        print("Example: python3 solve.py textmorph_extracted/textmorph_embedded.pyc")
        sys.exit(1)
    
    pyc_file = sys.argv[1]
    
    if not os.path.exists(pyc_file):
        print(f"[-] File not found: {pyc_file}")
        sys.exit(1)
    
    print(f"[*] Extracting strings from {pyc_file}...")
    strings = extract_strings_from_pyc(pyc_file)
    print(f"[+] Found {len(strings)} strings")
    
    print(f"[*] Looking for base64 blob...")
    blob = find_largest_base64(strings)
    
    if not blob:
        print("[-] No base64 blob found!")
        sys.exit(1)
    
    print(f"[+] Found blob: {len(blob)} characters")
    print(f"[*] Decoding and decompressing...")
    
    if decode_and_save(blob, 'hidden.gif'):
        print("\n[+] SUCCESS! Open hidden.gif to see the flag!")
        print("[+] Flag: esch{f0und_th3_h1dden_r1gby}")
    else:
        print("[-] Failed to decode!")

if __name__ == '__main__':
    main()
```

## Step-by-Step Walkthrough

### Complete Process

1. **Extract PyInstaller contents:**
   ```bash
   python3 pyinstxtractor.py textmorph
   ```

2. **Find the main .pyc file:**
   ```bash
   ls -lh textmorph_extracted/
   # Look for large .pyc file (several MB)
   ```

3. **Extract and decode:**
   ```bash
   python3 solve.py textmorph_extracted/textmorph_embedded.pyc
   ```

4. **View the GIF:**
   ```bash
   open hidden.gif  # or xdg-open, start, etc.
   ```

5. **Read the flag:**
   - Watch the animation
   - The flag text is overlaid: `esch{f0und_th3_h1dden_r1gby}`

## Troubleshooting

### Problem: pyinstxtractor fails

**Solution:**
- Make sure you have the latest version
- Try different Python versions
- Check if the binary is actually PyInstaller-packed

### Problem: Can't find base64 blob

**Solution:**
- Print all strings and manually search
- Look for very long strings (>1000 chars)
- Check for different encodings (hex, etc.)

### Problem: zlib decompression fails

**Solution:**
- Try other compression methods (gzip, bz2)
- The data might not be compressed
- Check the file signature (GIF, PNG, etc.)

### Problem: Can't read flag from GIF

**Solution:**
- Extract individual frames
- Use image editing software to enhance contrast
- The text might be in specific frames only

## Lessons Learned

1. **PyInstaller executables can be unpacked** - Use pyinstxtractor to extract embedded Python code

2. **Python bytecode contains strings** - Use marshal module to extract constants from .pyc files

3. **Look for encoded data** - Base64 blobs are common hiding places for flags

4. **Compression is common** - zlib, gzip, bz2 are all used to hide data

5. **Fake flags exist** - Don't trust the first flag you find, always verify!

6. **Large files are suspicious** - An 11MB "text utility" is definitely hiding something

7. **Hidden commands might be red herrings** - The real data is often in encoded blobs, not command output

8. **Image files can contain flags** - GIFs, PNGs, and other images are common flag carriers

9. **Leetspeak is common** - Flags often use 0, 1, 3 instead of o, i, e

10. **Complete the full extraction chain** - Base64 → zlib → file → flag

## Tools Used

- `file` - Identify file type
- `strings` - Search for text in binary
- `pyinstxtractor` - Unpack PyInstaller executables
- Python `marshal` - Analyze Python bytecode
- Python `base64` - Decode base64 strings
- Python `zlib` - Decompress zlib data
- Image viewer - View the extracted GIF

## Additional Resources

- [PyInstaller Documentation](https://pyinstaller.org/)
- [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)
- [Python marshal Module](https://docs.python.org/3/library/marshal.html)
- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
- [Zlib Compression](https://en.wikipedia.org/wiki/Zlib)

## Flag

```
esch{f0und_th3_h1dden_r1gby}
```

**Translation:** "found the hidden rigby" (with leetspeak)

---

*"Sometimes the flag is hidden in plain sight... just encoded, compressed, and embedded in an animated GIF!"*
