FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        curl \
        dnsutils \
        iproute2 \
        iputils-ping \
        net-tools \
        nmap \
        openssh-client \
        traceroute \
    && rm -rf /var/lib/apt/lists/* \
    && setcap -r /usr/lib/nmap/nmap \
    && useradd --create-home --shell /bin/bash kali

USER kali
WORKDIR /home/kali

CMD ["sleep", "infinity"]
