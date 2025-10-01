# LSB_decode.py
from PIL import Image

img = Image.open("hidden.png").convert("RGB")
width, height = img.size
binary_data = ""

for y in range(height):
    for x in range(width):
        pixel = list(img.getpixel((x, y)))
        bit = pixel[0] & 1  # Extract the least significant bit of red
        binary_data += str(bit)
        # if len(binary_data) >= 8 and binary_data[-8:] == "00000000":  # Check terminator
        if (len(binary_data) > 0) and (len(binary_data) % 8) == 0 and binary_data[-8:] == "00000000":
            break
    if (len(binary_data) > 0) and (len(binary_data) % 8) == 0 and binary_data[-8:] == "00000000":
        break

# Convert binary to text
message = ""
for i in range(0, len(binary_data) - 8, 8):
    byte = binary_data[i:i+8]
    message += chr(int(byte, 2))
print(message)
