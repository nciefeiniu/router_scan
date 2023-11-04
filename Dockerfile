FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

COPY sources.list /etc/apt/sources.list

COPY ./ /opt/scan_router

WORKDIR /opt/scan_router

RUN apt update && apt install -y proxychains python3.8 python3-pip

RUN apt install -y python3-dev default-libmysqlclient-dev build-essential pkg-config

RUN pip3 install -r requirements.txt -i https://mirrors.ustc.edu.cn/pypi/web/simple

RUN python3.8 manage.py migrate

CMD ["python3.8", "manage.py", "runserver", "0.0.0.0:8000"]