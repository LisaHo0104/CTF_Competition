# Now You See Me - Web Challenge Writeup

**Category:** Web  
**Points:** 500  
**Author:** @psychoSherlock

## Challenge Description

A web challenge featuring a creepy eyeball animation where dozens of eyes follow your cursor. The challenge title and various hints suggest that something is hidden in plain sight, but you need to look carefully to find it.

## TL;DR

The flag was hidden using invisible Unicode characters embedded in a JavaScript file. A JavaScript Proxy object was used to decode these invisible characters by converting them to binary and then to ASCII. The decoded code revealed the flag: `esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}`.

---

## Initial Analysis

### First Look

Opening the challenge URL, we're greeted with a creepy eyeball animation - dozens of eyes following your cursor around the screen. The visual effect is created using Matter.js physics engine, but where's the flag?

### HTML Source Investigation

The page source contains an interesting HTML comment:

```html
<!--Now you try more to see me, but still you dont-->
```

This is a hint that something is hidden that we're not seeing.

### Challenge Restrictions

The challenge implements several restrictions to prevent easy inspection:

1. **Right-click blocking** - Right-clicking is disabled with JavaScript
2. **Source view blocking** - Pressing `Ctrl+U` (or `Cmd+U` on Mac) triggers an alert and blocks viewing source
3. **The challenge is literally telling us "you can't see me"** - Classic CTF trolling

These restrictions force us to use alternative methods to inspect the page.

## Methodology

### Step 1: Check Common Hiding Spots

When source viewing is blocked, we need to fetch the raw files directly:

```bash
curl http://node-2.mcsc.space:10627/robots.txt
```

**Output:**
```
esch{not_that_easy_bro}
```

This is obviously a **decoy flag** - a common CTF technique to waste your time. Always verify flags before submitting!

### Step 2: Fetch the JavaScript Files

Since we can't view source in the browser, let's fetch the JavaScript files directly:

```bash
curl http://node-2.mcsc.space:10627/index.js > index.js
```

Or use browser DevTools Network tab to download the file.

### Step 3: Examine the JavaScript

Looking at `index.js`, most of it contains physics code for the eyeball animation using Matter.js. However, scrolling to the bottom reveals something suspicious:

```javascript
new Proxy(
  {},
  {
    get: (_, n) =>
      eval(
        [...n].map((n) => +("ﾠ" > n)).join``.replace(/.{8}/g, (n) =>
          String.fromCharCode(+("0b" + n)),
        ),
      ),
  },
)
  .ﾠﾠㅤﾠﾠﾠﾠﾠﾠﾠㅤﾠﾠﾠﾠﾠ...
```

Wait, what's after that dot? It looks empty, but it's not! If you copy-paste that "empty" space, you'll find it's actually thousands of invisible characters!

### Step 4: Identify the Invisible Characters

The code uses two special Unicode characters that look identical (both invisible):

| Character | Unicode Name | Code Point | Decimal Value |
|-----------|-------------|------------|---------------|
| `ﾠ` | HALFWIDTH HANGUL FILLER | U+FFA0 | 65440 |
| `ㅤ` | HANGUL FILLER | U+3164 | 12644 |

These are legitimate Unicode characters used in Korean text processing, but here they're being abused for steganography.

### Step 5: Understand the Decoding Mechanism

The Proxy object intercepts property access. When you access a property with an invisible name, the `get` trap converts those invisible characters into executable JavaScript code.

### Step 6: Decode the Hidden Message

We need to extract all invisible characters and decode them using the same algorithm the Proxy uses.

### Step 7: Extract the Flag

The decoded JavaScript contains the flag in a comment.

## Technical Deep Dive

### JavaScript Proxy Objects

A **Proxy** object in JavaScript allows you to intercept and customize operations performed on objects (like property lookup, assignment, enumeration, function invocation, etc.).

**Basic Proxy Syntax:**
```javascript
const proxy = new Proxy(target, handler);
```

- `target`: The object to wrap
- `handler`: An object containing traps (methods that intercept operations)

**Common Traps:**
- `get`: Intercepts property access
- `set`: Intercepts property assignment
- `has`: Intercepts `in` operator
- And many more...

**Example:**
```javascript
const target = {};
const handler = {
  get: function(target, prop) {
    console.log(`Accessing property: ${prop}`);
    return target[prop];
  }
};
const proxy = new Proxy(target, handler);
proxy.foo; // Logs: "Accessing property: foo"
```

### How This Challenge Uses Proxy

In this challenge, the Proxy is set up like this:

```javascript
new Proxy(
  {},  // Empty target object
  {
    get: (_, n) => { /* decoding logic */ }
  }
)
```

**Breaking it down:**
1. **Empty target `{}`**: The Proxy wraps an empty object
2. **`get` trap**: Intercepts any property access
3. **Parameter `n`**: The property name being accessed (in this case, the long string of invisible characters)
4. **The property name IS the data**: Instead of storing data in property values, the data IS the property name itself!

### The Decoding Algorithm

Let's break down the decoding logic step by step:

```javascript
get: (_, n) =>
  eval(
    [...n]                              // Step 1: Convert property name to array of characters
    .map((n) => +("ﾠ" > n))             // Step 2: Compare each char to ﾠ, convert to 0 or 1
    .join``                             // Step 3: Join into binary string
    .replace(/.{8}/g, (n) =>            // Step 4: Take 8 bits at a time
        String.fromCharCode(+("0b" + n)) // Step 5: Convert binary to ASCII character
    )
  )
```

**Step-by-step explanation:**

1. **`[...n]`** - Spreads the property name string into an array of individual characters
   - Example: `"ﾠㅤﾠ"` → `['ﾠ', 'ㅤ', 'ﾠ']`

2. **`.map((n) => +("ﾠ" > n))`** - Maps each character to 0 or 1
   - `"ﾠ" > n` compares the character `ﾠ` (U+FFA0 = 65440) with character `n`
   - If `n` is `ㅤ` (U+3164 = 12644): `65440 > 12644` = `true` → `+true` = `1`
   - If `n` is `ﾠ` (U+FFA0 = 65440): `65440 > 65440` = `false` → `+false` = `0`
   - The `+` converts boolean to number
   - Example: `['ﾠ', 'ㅤ', 'ﾠ']` → `[0, 1, 0]`

3. **`.join``**** - Joins the array into a binary string
   - Example: `[0, 1, 0, 1, 1, 0, 1, 0]` → `"01011010"`

4. **`.replace(/.{8}/g, (n) => ...)`** - Processes 8 bits at a time (one byte)
   - The regex `/.{8}/g` matches exactly 8 characters
   - Each match represents one ASCII character in binary

5. **`String.fromCharCode(+("0b" + n))`** - Converts binary to character
   - `"0b" + n` creates a binary literal string (e.g., `"0b01011010"`)
   - `+("0b" + n)` converts it to a number (e.g., `90`)
   - `String.fromCharCode(90)` converts to character (e.g., `'Z'`)

6. **`eval(...)`** - Executes the decoded JavaScript code

### Visual Example

Let's trace through a small example:

**Input (invisible characters):** `ﾠㅤﾠㅤㅤﾠㅤﾠ` (8 characters)

**Step 1 - Array:** `['ﾠ', 'ㅤ', 'ﾠ', 'ㅤ', 'ㅤ', 'ﾠ', 'ㅤ', 'ﾠ']`

**Step 2 - Binary mapping:**
- `ﾠ` (65440) > `ﾠ` (65440)? No → `0`
- `ﾠ` (65440) > `ㅤ` (12644)? Yes → `1`
- `ﾠ` (65440) > `ﾠ` (65440)? No → `0`
- `ﾠ` (65440) > `ㅤ` (12644)? Yes → `1`
- `ﾠ` (65440) > `ㅤ` (12644)? Yes → `1`
- `ﾠ` (65440) > `ﾠ` (65440)? No → `0`
- `ﾠ` (65440) > `ㅤ` (12644)? Yes → `1`
- `ﾠ` (65440) > `ﾠ` (65440)? No → `0`

**Result:** `[0, 1, 0, 1, 1, 0, 1, 0]`

**Step 3 - Join:** `"01011010"`

**Step 4 - Convert to char:** `String.fromCharCode(90)` = `'Z'`

So `ﾠㅤﾠㅤㅤﾠㅤﾠ` decodes to the character `'Z'`!

## Unicode Steganography

### Why These Characters Are Invisible

Both `ﾠ` (HALFWIDTH HANGUL FILLER) and `ㅤ` (HANGUL FILLER) are **non-printing characters** in Unicode. They serve specific purposes in Korean text processing:

- **HALFWIDTH HANGUL FILLER (U+FFA0)**: Used in legacy Korean text encoding systems
- **HANGUL FILLER (U+3164)**: Used as a placeholder in Korean input methods

In most fonts and text editors, these characters render as **zero-width** or **invisible**, making them perfect for steganography.

### Detecting Invisible Characters

Different tools and editors handle invisible characters differently:

#### In Text Editors

**VS Code:**
- Enable "Render Whitespace" to see some invisible characters
- Use extensions like "Unicode code point of current character"
- Search for specific Unicode ranges

**Vim:**
```vim
:set list
:set listchars=tab:>-,trail:-,eol:$
```

**Sublime Text:**
- View → Show Unicode

#### Using Command Line

**Python:**
```python
text = "your text here"
for i, char in enumerate(text):
    if ord(char) > 127:  # Non-ASCII
        print(f"Position {i}: U+{ord(char):04X} ({char})")
```

**Hex dump:**
```bash
xxd index.js | grep -E "ffa0|3164"
```

**Unicode inspection:**
```bash
python3 -c "text = open('index.js', 'rb').read().decode('utf-8'); print([hex(ord(c)) for c in text if ord(c) in [0xFFA0, 0x3164]][:10])"
```

#### Online Tools

- **Unicode Character Inspector**: https://unicode.org/cldr/utility/character.jsp
- **Hex Editor Online**: https://hexed.it/
- **Unicode Analyzer**: Various online tools can show hidden characters

### Other Unicode Steganography Tricks

This challenge uses a specific technique, but there are many other Unicode-based steganography methods:

1. **Zero-Width Characters:**
   - Zero-Width Space (U+200B)
   - Zero-Width Non-Joiner (U+200C)
   - Zero-Width Joiner (U+200D)
   - Left-to-Right Mark (U+200E)
   - Right-to-Left Mark (U+200F)

2. **Lookalike Characters:**
   - Cyrillic `а` vs Latin `a` (homoglyph attacks)
   - Various similar-looking characters from different scripts

3. **Combining Characters:**
   - Diacritical marks that modify base characters
   - Can be stacked to encode data

4. **Variation Selectors:**
   - Used to select specific glyph variants
   - Can encode binary data

## Decoding Implementation

### Python Decoder Script

Here's a complete Python script to decode the hidden message:

```python
#!/usr/bin/env python3
"""
Decoder for Now You See Me challenge
Extracts and decodes invisible Unicode characters from JavaScript
"""

def decode_invisible_steganography(file_path):
    """
    Decode invisible Unicode steganography from a JavaScript file.
    
    Uses the same algorithm as the JavaScript Proxy:
    1. Extract invisible characters (ﾠ and ㅤ)
    2. Convert to binary (ﾠ=0, ㅤ=1)
    3. Convert binary to ASCII
    """
    # Unicode code points
    HALFWIDTH_HANGUL_FILLER = '\uffa0'  # ﾠ (U+FFA0) - represents 0
    HANGUL_FILLER = '\u3164'            # ㅤ (U+3164) - represents 1
    
    # Read file with UTF-8 encoding
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract only the invisible characters
    invisible_chars = []
    for char in content:
        if char == HALFWIDTH_HANGUL_FILLER or char == HANGUL_FILLER:
            invisible_chars.append(char)
    
    print(f"Found {len(invisible_chars)} invisible characters")
    
    if len(invisible_chars) == 0:
        print("No invisible characters found!")
        return None
    
    # Convert to binary string
    # ﾠ (U+FFA0 = 65440) > ㅤ (U+3164 = 12644) is True
    # So: ㅤ → 1, ﾠ → 0
    binary_string = ''
    for char in invisible_chars:
        if char == HANGUL_FILLER:  # ㅤ (smaller codepoint)
            binary_string += '1'
        else:  # HALFWIDTH_HANGUL_FILLER ﾠ (larger codepoint)
            binary_string += '0'
    
    print(f"Binary string length: {len(binary_string)} bits")
    print(f"First 80 bits: {binary_string[:80]}...")
    
    # Convert binary to ASCII (8 bits per character)
    decoded = ''
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            char_code = int(byte, 2)
            decoded += chr(char_code)
    
    return decoded

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 decoder.py <javascript_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = decode_invisible_steganography(file_path)
    
    if result:
        print("\n" + "="*60)
        print("DECODED OUTPUT:")
        print("="*60)
        print(result)
        print("="*60)
```

### JavaScript Decoder (Browser Console)

You can also decode it directly in the browser console:

```javascript
// First, get the invisible characters from the file
// (This assumes you've extracted them somehow)

const halfwidth = '\uffa0';  // ﾠ
const hangul = '\u3164';     // ㅤ

function decode(invisibleString) {
    return invisibleString
        .split('')
        .map(c => (halfwidth > c) ? '1' : '0')
        .join('')
        .match(/.{8}/g)
        .map(bin => String.fromCharCode(parseInt(bin, 2)))
        .join('');
}

// Usage:
// const invisible = "ﾠﾠㅤﾠﾠﾠﾠﾠﾠﾠㅤ..."; // (your extracted string)
// console.log(decode(invisible));
```

### Manual Extraction Method

If automated extraction doesn't work, you can manually extract:

1. Open `index.js` in a hex editor or text editor that shows Unicode
2. Find the section after the Proxy code (after the closing parenthesis and dot)
3. Copy all invisible characters
4. Use the decoder script above

## The Decoded Code

When decoded, the invisible characters reveal JavaScript code that:

1. Creates a styled message div
2. Sets the text content to "Do you see me?"
3. Contains the flag in a comment:

```javascript
// Decoded JavaScript (approximate)
const messageDiv = document.createElement('div');
messageDiv.style.cssText = '...'; // Styling
messageDiv.textContent = "Do you see me?";
// esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}
// Said Sherlock Holmes.
```

## Alternative Approaches

### Method 1: Browser DevTools

Even with right-click blocked, you can still use DevTools:

1. **Open DevTools:**
   - `F12` or `Ctrl+Shift+I` (Windows/Linux)
   - `Cmd+Option+I` (Mac)
   - Or right-click → Inspect (if not fully blocked)

2. **Network Tab:**
   - Reload page
   - Find `index.js` in the network requests
   - Right-click → "Copy response" or "Save as"

3. **Sources Tab:**
   - Navigate to the JavaScript file
   - View raw source (may show invisible characters differently)

4. **Console Tab:**
   - You can try to execute parts of the Proxy code
   - Access the property to trigger decoding

### Method 2: Hex Editor

View the raw bytes of the file:

```bash
# Using xxd
xxd index.js | less

# Using hexdump
hexdump -C index.js | less

# Look for bytes corresponding to:
# U+FFA0: EF BE A0 (UTF-8 encoding)
# U+3164: E3 85 A4 (UTF-8 encoding)
```

### Method 3: Online Unicode Analyzers

1. Upload the file to an online Unicode analyzer
2. Search for specific code points (FFA0, 3164)
3. Extract the characters

### Method 4: JavaScript Console Debugging

If you can access the console, you can try to interact with the Proxy:

```javascript
// The Proxy object might be accessible
// Try to access properties and see what happens
// (This is tricky since you need the exact invisible string)
```

### Method 5: Python Script with Regex

Extract invisible characters using regex:

```python
import re

with open('index.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find invisible characters
invisible = re.findall(r'[\u3164\uffa0]+', content)
if invisible:
    print(f"Found {len(invisible)} invisible character sequences")
    print(f"Total characters: {sum(len(s) for s in invisible)}")
```

## Challenge Mechanics Explained

### Why Right-Click is Blocked

The challenge uses JavaScript event handlers to prevent context menu:

```javascript
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    return false;
});
```

**Bypass methods:**
- Use keyboard shortcuts (`F12` for DevTools)
- Disable JavaScript (but then you can't see the page)
- Use browser extensions to override

### Source View Blocking

The challenge intercepts keyboard shortcuts:

```javascript
document.addEventListener('keydown', function(e) {
    // Block Ctrl+U (view source)
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        alert('Nice try!');
        return false;
    }
});
```

**Bypass methods:**
- Use `curl` or `wget` to fetch files directly
- Use browser DevTools Network tab
- Disable JavaScript temporarily

### The Decoy Flag in robots.txt

The `robots.txt` file contained `esch{not_that_easy_bro}` - a classic CTF technique:

- **Purpose:** Waste your time and make you submit wrong flags
- **Lesson:** Always verify flags before submitting
- **Red flag:** If it's too easy, it's probably wrong!

### The Sherlock Holmes Reference

The flag `esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}` is a play on the famous Sherlock Holmes quote:

> "You see, but you do not observe."

This is perfect because:
- The challenge author is **@psychoSherlock**
- The challenge is about looking at something without truly *seeing* what's there
- The invisible Unicode characters are hiding in plain sight
- You need to "observe" (decode/analyze) rather than just "see" (glance at)

## Verification & Testing

### Verifying the Decoded Output

1. **Check for JavaScript syntax:**
   - The decoded output should be valid JavaScript
   - It should create DOM elements or execute code

2. **Look for the flag format:**
   - Should match `esch{...}`
   - Check for the comment containing the flag

3. **Test the flag:**
   - Submit to the CTF platform
   - Verify it's accepted

### Testing the Decoder

You can test your decoder with a known example:

```python
# Test with known input
test_input = "ﾠ" * 4 + "ㅤ" * 4  # Should decode to one character
# ﾠﾠﾠﾠ = 0000, ㅤㅤㅤㅤ = 1111
# Combined: 00001111 = 15 decimal = '\x0f' (form feed character)
```

### Confirming the Hidden Message

The decoded code should:
1. Create a `div` element
2. Apply CSS styling
3. Set text content to "Do you see me?"
4. Contain the flag in a comment

## Troubleshooting

### Problem: No invisible characters found

**Solutions:**
- Check file encoding (must be UTF-8)
- Verify you're looking at the correct file
- Try different extraction methods
- Check if characters are in a different location

### Problem: Decoded output is gibberish

**Solutions:**
- Verify you're using the correct character mapping (ﾠ=0, ㅤ=1)
- Check that you're processing 8 bits at a time
- Ensure you're reading the file with UTF-8 encoding
- Try reversing the mapping (maybe it's the other way around)

### Problem: Can't access the JavaScript file

**Solutions:**
- Use `curl` or `wget` to download directly
- Use browser DevTools Network tab
- Try different URLs (maybe there's a `/static/` or `/js/` path)
- Check if the file is minified/obfuscated

### Problem: Proxy code doesn't execute

**Solutions:**
- The Proxy might need to be assigned to a variable
- Check browser console for errors
- Verify the invisible characters are correctly formatted
- Try executing the Proxy code manually in console

### Problem: Right-click and source view are blocked

**Solutions:**
- Use keyboard shortcuts (`F12` for DevTools)
- Use `curl`/`wget` to fetch files
- Disable JavaScript (but page won't work)
- Use browser extensions to override restrictions

## Flag

```
esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}
```

## Lessons Learned

1. **Invisible characters are everywhere** - Always check for zero-width, non-printing Unicode characters in web challenges
2. **Decoy flags exist** - Don't submit the first flag-looking string you find; verify it first
3. **View raw source when possible** - Browser rendering might hide things; use `curl`, hex editors, or raw file viewers
4. **Unicode is powerful and dangerous** - Thousands of invisible or lookalike characters can be abused for steganography
5. **JavaScript Proxy is versatile** - Can be used for more than just object property access; here it's used for decoding
6. **Property names can be data** - Data doesn't have to be in property values; the property name itself can encode information
7. **Challenge restrictions can be bypassed** - Right-click blocking and source view blocking can be circumvented with the right tools
8. **Read the challenge title carefully** - "Now You See Me" was a hint about invisible/hidden content
9. **Author names matter** - @psychoSherlock's name hinted at the Sherlock Holmes quote in the flag
10. **Point values can be hints** - Though not as obvious here as in other challenges, sometimes point values provide clues

## Tools Used

- **curl** - For fetching raw files when browser access is blocked
- **Python 3** - For decoding invisible Unicode steganography
- **Text editor with Unicode support** - For viewing and editing files with invisible characters
- **Browser DevTools** - For network inspection and file downloading
- **Hex editor** (optional) - For viewing raw bytes and UTF-8 encodings

## Additional Resources

- [MDN: Proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy)
- [Unicode Character Database](https://www.unicode.org/charts/)
- [Zero-Width Characters](https://en.wikipedia.org/wiki/Zero-width_space)
- [Unicode Steganography Techniques](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-attack)

---

*"You see, but you do not observe." - Sherlock Holmes*

*Now you see it. Now you don't... but now you do again!*
