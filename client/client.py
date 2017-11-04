import time
import pycurl

while True:
    time.sleep(0.1)
    c = pycurl.Curl()
    c.setopt(c.URL, "server")
    c.setopt(pycurl.WRITEFUNCTION, lambda x: None)
    c.perform()
