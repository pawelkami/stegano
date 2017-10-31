import time
import random
import os
import pycurl

while True:
    time.sleep(1)

    c = pycurl.Curl()
    c.setopt(c.URL, "server")
    c.perform()