You will need
⚫ 1 Ubuntu 24.04 VM or equivalent
⚫ python3 Pillow library for image manipulation
    ⚫ pip3 install Pillow
⚫ Download from MyCourses
    ⚫ LSB_encode.py
    ⚫ LSB_decode.py
    ⚫ European_shorthair_cat.png (or any other png image file)

Easy Prebuilt Tool
`from pysteganograph import Steganograph`
`stego = Steganograph("image.png", "hidden.png")`
`stego.encode("secret message", password="pass")`
`message = stego.decode(password="pass")`
`print(message)`
