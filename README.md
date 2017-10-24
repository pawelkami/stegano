# stegano

## Server:

### Budowanie:
#### docker image build -t best/webapp .

### Uruchamianie:
#### docker run -d -p 8888:80 best/webapp

### Kopiowanie pcap na maszynę:
docker cp [container]:/pcaps/traffic.pcap [ścieżka pod którą chcemy zapisać]

## Klient:

### Budowanie:
#### docker build -t best/client .

### Uruchamianie:
#### docker run -d --rm --add-cap NET_ADMIN best/client

## Całość

### Budowanie:
#### docker-compose build

### Uruchamianie:
#### docker-compose up