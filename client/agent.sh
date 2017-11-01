iptables -A OUTPUT -j NFQUEUE -p tcp --destination-port 80 -d `getent hosts server | awk '{ print $1 }'`
python3 -u /stegano/steganowriter.py & python3 -u /stegano/client.py
