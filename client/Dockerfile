FROM python:3.6-alpine

# Copy files
RUN mkdir /stegano
COPY client.py /stegano
COPY steganowriter.py /stegano
COPY requirements.txt /stegano
COPY agent.sh /stegano
COPY Antygona.txt /stegano

# Install dependencies
RUN apk --update add wget g++ linux-headers python3-dev libnfnetlink-dev libnetfilter_queue-dev iptables
RUN pip3 install -r /stegano/requirements.txt

# Run the client and the steganowriter
CMD /bin/sh /stegano/agent.sh
