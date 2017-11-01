export SERVER_ADDRESS=`getent hosts server | awk '{ print $1 }'`
iptables -A OUTPUT -j NFQUEUE -p tcp --destination-port 80 -d $SERVER_ADDRESS
python3 -u /stegano/steganowriter.py & python3 -u /stegano/client.py
