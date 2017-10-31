iptables -A OUTPUT -j NFQUEUE -p tcp --destination-port 80
python3 -u /stegano/steganowriter.py & python3 -u /stegano/client.py
