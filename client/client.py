import time
from urllib.parse import urlencode
import pycurl
import string
import random

addresses = [
    "server",
    "server/example",
    "server/programming",
    "server/stegano",
    "server/wireshark",
    "server/doggos",
    "server/dogs",
    "server/cats",
    "server/doggos/add"
]


def generate_form_data():
    name_length = random.randint(4, 10)
    name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(name_length))
    cuteness_level = str(random.randint(0, 100))
    dog_url = 'http://example.org/' + ''.join(random.choice(string.ascii_lowercase) for _ in range(5))

    return bytes(urlencode({'name': name, 'cuteness_level': cuteness_level, 'url': dog_url}), encoding='ASCII')


while True:
    time.sleep(0.1)
    try:
        address = random.choice(addresses)
        c = pycurl.Curl()
        c.setopt(c.URL, address)
        c.setopt(pycurl.WRITEFUNCTION, lambda x: None)
        if address == "server/doggos/add" and random.randint(0, 1) == 1:
            c.setopt(c.POSTFIELDS, generate_form_data())
        c.perform()
    except Exception as e:
        print(e)

