FROM ubuntu:latest
WORKDIR /home/adzhi4ka/dpdkExporing
ENV PATH="$PATH:/home/adzhi4ka/dpdkExporing"
 
RUN dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install -y libnuma-dev libatomic1 python3