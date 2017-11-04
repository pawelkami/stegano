sleep 3s
iptables -A OUTPUT -j NFQUEUE -p tcp --destination-port 80 -d `getent hosts server | awk '{ print $1 }'`
python3 -u /stegano/steganowriter.py &
tshark -s 0 -w "/pcaps/traffic.pcap" &
python3 -u /stegano/client.py
