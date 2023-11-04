FROM ubuntu:20.04

COPY sources.list /etc/apt/sources.list

COPY ./ /opt/scan_router

RUN apt update && apt install -y proxychains

