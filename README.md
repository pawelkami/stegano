# stegano

## Server:

### Budowanie:
#### docker image build -t best/webapp .

### Uruchamianie:
#### docker run -d -p 8888:80 best/webapp

### Kopiowanie pcap na maszynę:
docker cp <container id>:/pcaps/traffic.pcap <ścieżka pod którą chcemy zapisać>
