FROM python:3.8-buster
COPY . /src
WORKDIR /data
RUN apt-get update  && apt-get install -y \
            geoip-bin \
            libemail-outlook-message-perl \
            libemail-sender-perl
RUN pip install -r /src/requirements.txt
CMD ["/bin/bash"]
