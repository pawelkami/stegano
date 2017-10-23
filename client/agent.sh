iptables -A OUTPUT -j NFQUEUE
python3 /stegano/steganowriter.py & python3 /stegano/client.py
