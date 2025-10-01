# LSB_encode.py
from PIL import Image

# Open the image and convert to RGB
img = Image.open("image.png").convert("RGB")
data = "secret message"
data = "Hello World!"
data = "abcdefghijklmnopqrstuvwxyz p ABCDEFGHIJKLMNOPQRSTUVWXYZ"
data = "abcdefghijklmnopqrstuvwxyz p\t ABCDEFGHIJKLMNOPQRSTUVWXYZ"
width, height = img.size
pixel_index = 0  # Tracks the pixel position
char_index = 0   # Tracks the character position
bit_index = 0    # Tracks the bit position within the current character
# Convert data to binary (8 bits per character) with a terminator
binary_data = ''.join(format(ord(char), '08b') for char in data) + '00000000'
print("DEBUG: len(data) = " + str(len(data)))
print("DEBUG: len(binary_data) = " + str(len(binary_data)))

for y in range(height):  # Loop through rows
    for x in range(width):  # Loop through columns
        if pixel_index < len(binary_data):  # Continue until all bits are embedded
            print("DEBUG: pixel_index=" + str(pixel_index) + ": bit=" + binary_data[pixel_index])
            pixel = list(img.getpixel((x, y)))
            # Embed the current bit into the red value
            bit = int(binary_data[pixel_index])
            pixel[0] = (pixel[0] & ~1) | bit  # Modify only the least significant bit of red
            img.putpixel((x, y), tuple(pixel))
            pixel_index += 1
        else:
            break
    if pixel_index >= len(binary_data):
        break

img.save("hidden.png")
