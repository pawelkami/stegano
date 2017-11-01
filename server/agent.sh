python3 -u /usr/src/app/app.py & python3 -u /usr/src/app/steganoreader.py
tshark -s 0 -w "/pcaps/traffic.pcap"
