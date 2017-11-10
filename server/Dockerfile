# our base image
FROM python:3.6-alpine

# tell the port number the container should expose
EXPOSE 80

# Install python and pip
RUN apk add --update python3-dev tcpdump tshark

RUN mkdir /pcaps

# install Python modules needed by the Python app
COPY requirements.txt /usr/src/app/
RUN pip3 install --no-cache-dir -r /usr/src/app/requirements.txt

# copy files required for the app to run
COPY config.py /usr/src/app
COPY app.py /usr/src/app/
COPY templates/* /usr/src/app/templates/
COPY agent.sh /usr/src/app
COPY steganoreader.py /usr/src/app


# run the application
CMD /bin/sh /usr/src/app/agent.sh
