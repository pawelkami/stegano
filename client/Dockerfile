FROM python:3.6-alpine

# Copy files
RUN mkdir /stegano
COPY client.py /stegano
COPY steganowriter.py /stegano
COPY requirements.txt /stegano
COPY agent.sh /stegano
COPY Antygona.txt /stegano
ENV PYCURL_SSL_LIBRARY openssl

# Install dependencies
RUN apk --update add wget g++ linux-headers python3-dev libnfnetlink-dev libnetfilter_queue-dev iptables curl-dev tshark
RUN pip3 install -r /stegano/requirements.txt
RUN mkdir /pcaps

# Run the client and the steganowriter
CMD /bin/sh /stegano/agent.sh
