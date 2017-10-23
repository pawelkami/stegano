import time
import random
import os

while True:
    time.sleep(1 + random.randint(0, 5))

    # -p: download website with CSS, images, etc.
    # -H: download resources from external hosts too
    # -e robots=off: ignore robots.txt (sometimes robots.txt doesn't allow downloading full website)
    # -nv: less verbose output
    os.system('wget -P downloads -p -H -e robots=off -nv server')
