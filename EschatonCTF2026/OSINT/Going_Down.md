# Going Down - OSINT Challenge Writeup

**Category:** OSINT  
**Points:** 100  
**Author:** @andrewcanil

## Challenge Description

> This photo shows you something, but not everything. Find out what lies within.

We're given a single image file: `Going_Down.png`

## Initial Analysis

Opening the image, we see a beautifully carved stone sculpture of what appears to be a Hindu deity. The intricate stonework suggests this is from an ancient Indian temple or monument. The sculpture features detailed carvings typical of medieval Indian architecture, with ornate patterns and religious iconography.

But the challenge says the photo "shows you something, but not everything" and asks us to "find out what lies within." That's a classic hint that there's hidden data in the image! This immediately points to **steganography** - the practice of hiding information within other non-secret text or data.

## Methodology

### Step 1: Recognizing the Steganography Hint

The challenge title "Going Down" combined with the description "find out what lies within" strongly suggests hidden data. When dealing with image files in CTF challenges, especially PNG files, steganography is a common technique.

### Step 2: Choosing the Right Tool

For PNG files, one of the most effective tools is `zsteg` - a tool specifically designed to detect steganography in PNG and BMP files. It analyzes the least significant bits (LSB) of RGB channels to find hidden data.

### Step 3: Extracting Hidden Data

Running `zsteg` on the image file:

```bash
zsteg Going_Down.png
```

**Expected Output:**
```
imagedata           .. text: "You prolly carry an image of this particular statue in your pocket everyday (If you're an Indian). But you might never have seen it. Find out where it's from.\n\nFlag Format: esch{name_of_place}\n\nP.S: use _ as separator, and refer to wikipedia for exact case"
b1,rgb,lsb,xy       .. text: "You prolly carry an image of this particular statue in your pocket everyday (If you're an Indian). But you might never have seen it. Find out where it's from.\n\nFlag Format: esch{name_of_place}\n\nP.S: use _ as separator, and refer to wikipedia for exact case"
```

Perfect! We've extracted the hidden message.

### Step 4: Analyzing the Clue

The hidden message gives us several important clues:

1. **"carry an image in your pocket everyday"** - This strongly suggests currency (banknotes/coins)
2. **"If you're an Indian"** - Points to Indian currency
3. **"But you might never have seen it"** - Suggests it's on the back of a note, not commonly noticed
4. **100 points** - The challenge point value! This is likely a hint pointing to the ₹100 note

### Step 5: Connecting the Dots

The logical progression:
- Challenge is worth **100 points** → Points to **₹100 note**
- The sculpture is on Indian currency
- Need to find which monument/place is featured on the ₹100 note
- The title "Going Down" must relate to the monument somehow

### Step 6: Researching the Answer

A quick search for "what is on the back of 100 rupee note" or "Indian 100 rupee note monument" reveals that the **₹100 note** (introduced in 2018) features **Rani ki Vav** on the reverse side.

**The "Going Down" connection:** A stepwell (vav) is literally a structure you walk DOWN into to reach water - making the challenge title a perfect pun!

### Step 7: Verifying the Answer

To get the exact flag format:
1. Check Wikipedia for the exact capitalization: "Rani ki Vav"
2. Use underscores as separators: `Rani_ki_Vav`
3. Format as: `esch{Rani_ki_Vav}`

## Technical Details

### What is LSB Steganography?

**Least Significant Bit (LSB) steganography** is a technique where the least significant bit of each pixel's color channel is modified to hide data. Since changing the LSB causes minimal visual change (often imperceptible to the human eye), the image looks normal while containing hidden information.

**How it works:**
- Each pixel in an RGB image has 3 color channels (Red, Green, Blue)
- Each channel is typically 8 bits (0-255)
- The LSB is the rightmost bit (bit 0)
- Changing it from 0 to 1 or 1 to 0 changes the color value by only ±1, which is visually undetectable
- By encoding data across multiple pixels, entire messages can be hidden

### Why zsteg Works

`zsteg` is specifically designed for PNG and BMP files because:
- It understands PNG's internal structure (chunks, compression)
- It can extract data from various bit planes (LSB, MSB, etc.)
- It tests multiple channel combinations (RGB, RGBA, individual channels)
- It can detect data in different positions (xy, yx, etc.)

The tool systematically tests different extraction methods:
- Different bit positions (LSB, MSB)
- Different channel combinations (RGB, individual channels)
- Different scan orders (row-by-row, column-by-column)

## Tools & Techniques

### Primary Tool: zsteg

**Installation:**
```bash
gem install zsteg
```

**Usage:**
```bash
zsteg <image_file>
```

**What it does:**
- Analyzes PNG/BMP files for hidden data
- Tests multiple extraction methods automatically
- Outputs readable text when found
- Shows which method successfully extracted the data

### Alternative Approaches

If `zsteg` doesn't work or you want to try other methods:

#### 1. strings
Extract readable strings from the file:
```bash
strings Going_Down.png | grep -i "esch\|flag\|hint"
```
**When to use:** Quick check for plaintext hidden in file metadata or appended data.

#### 2. binwalk
Detect embedded files and hidden data:
```bash
binwalk Going_Down.png
binwalk -e Going_Down.png  # Extract embedded files
```
**When to use:** When data might be embedded as separate files within the image.

#### 3. exiftool
Check metadata for hidden information:
```bash
exiftool Going_Down.png
```
**When to use:** When clues might be in EXIF data, comments, or other metadata fields.

#### 4. stegsolve / stegonline
Visual steganography analysis tools that let you:
- View different bit planes
- Apply color filters
- Analyze LSB patterns visually

**When to use:** When you need visual analysis or zsteg isn't available.

#### 5. Manual LSB Extraction
Using Python with PIL/Pillow:
```python
from PIL import Image
import numpy as np

img = Image.open('Going_Down.png')
pixels = np.array(img)

# Extract LSB from red channel
lsb_data = pixels[:,:,0] & 1
# Convert to bytes and decode
```

**When to use:** When you need custom extraction logic or want to understand the process.

### Troubleshooting

**If zsteg doesn't find anything:**
1. Try different bit planes: `zsteg -a Going_Down.png` (all methods)
2. Check if it's a different file type (maybe it's actually a JPEG?)
3. Try other steganography tools (steghide, outguess for JPEG)
4. Check file metadata with `exiftool`
5. Look for appended data with `binwalk` or `dd`

**If zsteg isn't installed:**
- Install Ruby first: `sudo apt install ruby` (Linux) or `brew install ruby` (macOS)
- Then: `gem install zsteg`
- Alternative: Use online tools like stegonline.com

## About Rani ki Vav

### Historical Context

**Rani ki Vav** (Queen's Stepwell) is an 11th-century stepwell located in Patan, Gujarat, India. It's one of the most magnificent examples of stepwell architecture in India.

**Key Facts:**
- **Built:** Around 1050 AD by Queen Udayamati in memory of her husband King Bhima I of the Chaulukya dynasty
- **Architecture:** An inverted temple highlighting the sanctity of water
- **Dimensions:** Approximately 64 meters long, 20 meters wide, and 27 meters deep
- **Sculptures:** Over 500 principal sculptures and more than 1,000 minor ones
- **UNESCO Status:** Designated a World Heritage Site in 2014
- **Currency:** Featured on the reverse of the Indian ₹100 banknote since July 2018

### Why "Going Down"?

Stepwells (vavs) are unique architectural structures where you literally walk DOWN a series of steps to reach the water level. Unlike regular wells where you pull water up, stepwells allow direct access to the water source by descending. The challenge title "Going Down" is a clever reference to this architectural feature!

### Why This Monument?

Rani ki Vav was chosen for the ₹100 note because:
- It represents India's rich cultural heritage
- It's a UNESCO World Heritage Site, giving it international recognition
- The intricate carvings showcase India's artistic traditions
- It's less commonly known compared to monuments like the Taj Mahal, making it a perfect "hidden in plain sight" reference

## Verification Steps

1. **Check Wikipedia:**
   - Search for "Rani ki Vav"
   - Verify the exact capitalization: "Rani ki Vav" (with lowercase "ki")
   - Confirm it's on the ₹100 note

2. **Verify Flag Format:**
   - Format: `esch{name_of_place}`
   - Use underscores as separators
   - Match Wikipedia capitalization exactly
   - Result: `esch{Rani_ki_Vav}`

3. **Cross-reference:**
   - Check images of the ₹100 note to confirm the monument
   - Verify the sculpture matches what we see in the challenge image

## Flag

```
esch{Rani_ki_Vav}
```

## Lessons Learned

1. **Always check for steganography** - When a challenge mentions "hidden" or "within," steganography is likely involved
2. **Point values can be hints** - The 100 points directly pointed to the ₹100 note
3. **Challenge titles matter** - "Going Down" was a clever hint about stepwells
4. **OSINT + Steganography** - This challenge combined technical skills (steganography extraction) with research skills (identifying monuments on currency)
5. **Cultural knowledge helps** - Understanding Indian currency and monuments made the connection faster
6. **Tool familiarity** - Knowing `zsteg` for PNG files is essential for CTF challenges
7. **Verification is key** - Always check Wikipedia or official sources for exact spellings and capitalization

## Tools Used

- `zsteg` - Primary tool for detecting LSB steganography in PNG files
- Web search - For identifying the monument on Indian currency
- Wikipedia - For verifying exact capitalization and details

## Alternative Solutions

If you didn't have `zsteg` available, you could:
1. Use online steganography tools (stegonline.com)
2. Write a Python script to extract LSB data manually
3. Try other tools like `steghide` (though it's mainly for JPEG)
4. Use `binwalk` to check for embedded files
5. Check metadata with `exiftool` for any clues

## Conclusion

This was an excellent challenge that combined:
- **Steganography detection** (technical skill)
- **Cultural knowledge** (knowing Indian currency)
- **Logical reasoning** (connecting 100 points to ₹100 note)
- **Research skills** (finding the exact monument name)

The clever wordplay in the title "Going Down" referencing the stepwell's architecture, combined with the hidden message pointing to currency, made this a well-crafted OSINT challenge. The 100-point value matching the ₹100 note was a particularly nice touch that helped guide solvers in the right direction!
