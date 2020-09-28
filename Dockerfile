FROM ubuntu:16.04

RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak
ADD https://isrc.iscas.ac.cn/mirror/help/mirror/xlab_ubuntu18.04.list /etc/apt/sources.list.d/xlab_ubuntu18.04.list

RUN apt-get update

RUN apt-get install -y \
    build-essential \
    python3.6 python3.6-dev python3-pip python3-virtualenv \
    wget git screen docker.io default-jdk lrzsz binwalk vim unzip sudo

# install ghidra
ADD ghidra_9.0.4_PUBLIC_20190516.zip /tmp/ghidra.zip
RUN unzip /tmp/ghidra.zip -d /ghidra

# update pip and install python library
RUN python3.6 -m pip install pip --upgrade
COPY requirements /tmp/
RUN python3.6 -m pip install wheel -r /tmp/requirements

RUN git clone https://github.com/radare/radare2.git && ./radare2/sys/install.sh

# RUN echo 'export PATH=$PATH:/fwslap/bin:/ghidra/ghidra_9.0.4/support/' > /entrypoint.sh && chmod +x /entrypoint.sh
COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
VOLUME [ "/data" ]
WORKDIR /data
ENV FWSLAP_BROKER_URL=pyamqp://guest:guest@rabbit//
COPY . /fwslap
RUN cd /fwslap && python3 /fwslap/setup.py install
# export PATH=$PATH:/fwslap/bin:/ghidra/ghidra_9.0.4/support/
RUN echo 'export PATH=/fwslap/bin:/ghidra/ghidra_9.0.4/support:$PATH:/usr/local/bin' >> /etc/profile
ENV PATH=/fwslap/bin:/ghidra/ghidra_9.0.4/support:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN pip install -U scipy
