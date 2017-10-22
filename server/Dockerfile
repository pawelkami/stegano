# our base image
FROM alpine:latest

# Install python and pip
RUN apk add --update py-pip tcpdump tshark

# install Python modules needed by the Python app
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt

# copy files required for the app to run
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
COPY agent.sh /usr/src/app
COPY steganoreader.py /

# tell the port number the container should expose
EXPOSE 80
RUN mkdir /pcaps

# run the application
CMD /bin/sh /usr/src/app/agent.sh
