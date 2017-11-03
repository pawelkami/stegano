FROM python:3.6-alpine

ENV PYCURL_SSL_LIBRARY openssl

RUN mkdir /stegano
COPY requirements.txt /stegano

# Install dependencies
RUN apk --update add g++ linux-headers python3-dev libnfnetlink-dev libnetfilter_queue-dev iptables curl-dev tshark
RUN pip3 install -r /stegano/requirements.txt
RUN mkdir /pcaps

# Copy files
COPY Antygona.txt /stegano
COPY agent.sh /stegano
COPY client.py /stegano
COPY steganowriter.py /stegano

# Run the client and the steganowriter
CMD /bin/sh /stegano/agent.sh
