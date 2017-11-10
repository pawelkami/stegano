import time
import pycurl
import random

addresses = [
    "server",
    "server/example",
    "server/programming",
    "server/stegano",
    "server/wireshark"
]

while True:
    time.sleep(0.1)
    try:
        c = pycurl.Curl()
        c.setopt(c.URL, random.choice(addresses))
        c.setopt(pycurl.WRITEFUNCTION, lambda x: None)
        c.perform()
    except:
        pass