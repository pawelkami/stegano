python3 -u /usr/src/app/app.py &
tshark -s 0 -w "/pcaps/traffic.pcap" &
python3 -u /usr/src/app/steganoreader.py
