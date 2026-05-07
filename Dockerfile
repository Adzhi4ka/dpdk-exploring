FROM ubuntu:latest
COPY . /app

WORKDIR /app

ENV PATH="$PATH:/app"
 
RUN dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install -y libnuma-dev libatomic1 python3