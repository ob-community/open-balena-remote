FROM debian:bookworm-slim AS build

# Build ttyd from source
RUN apt-get update && apt-get install -y build-essential cmake git libjson-c-dev libwebsockets-dev && \
  git clone --quiet https://github.com/tsl0922/ttyd.git && \
  mkdir -p ttyd/build && \
  cd ttyd/build && \
  cmake .. && \
  make && \
  make install

FROM node:23-bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
  nano \
  unzip \
  curl \
  git \
  netbase \
  libjson-c-dev \
  libwebsockets-dev \
  net-tools \
  procps \
  cron \
  python3 \
  python3-venv \
  python3-setuptools \
  python3-numpy \
  libaugeas0 && \
  rm -rf /var/lib/apt/lists/*

# Install balena-cli
ENV BALENA_CLI_VERSION=15.2.3
RUN curl -sSL https://github.com/balena-io/balena-cli/releases/download/v$BALENA_CLI_VERSION/balena-cli-v$BALENA_CLI_VERSION-linux-x64-standalone.zip > balena-cli.zip && \
  unzip balena-cli.zip && \
  mv balena-cli/* /usr/bin && \
  rm -rf balena-cli.zip balena-cli

# Install websockify
RUN mkdir -p /usr/share/websockify && \
  git clone --quiet https://github.com/novnc/websockify.git /usr/share/websockify && \
  cd /usr/share/websockify && \
  python3 setup.py install

# Install novnc
RUN mkdir -p /usr/share/novnc_root/novnc && \
  git clone --quiet https://github.com/novnc/noVNC /usr/share/novnc_root/novnc && \
  cd /usr/share/novnc_root/novnc && \
  npm install --silent && \
  sed -i 's/color:yellow;/color:yellow; display: none; /g' /usr/share/novnc_root/novnc/app/styles/base.css && \
  sed -i '/icons\/novnc/d' /usr/share/novnc_root/novnc/vnc.html && \
  sed -i 's/<title>noVNC/<title>Open Balena Remote VNC/g' /usr/share/novnc_root/novnc/vnc.html && \
  sed -i 's/PAGE_TITLE = "noVNC"/PAGE_TITLE = "Open Balena Remote VNC"/g' /usr/share/novnc_root/novnc/app/ui.js && \
  sed -i '/e.detail.name +/d' /usr/share/novnc_root/novnc/app/ui.js

WORKDIR /usr/src/app

# Install ttyd
COPY --from=build /usr/local/bin/ttyd /usr/local/bin
COPY --from=build /usr/local/share/man/man1/ttyd.1 /usr/local/share/man/man1

COPY open-balena-remote.js ./
COPY logger.js ./
COPY package.json ./
COPY package-lock.json ./
COPY html ./html
COPY views ./views

RUN npm ci --silent

COPY scripts ./scripts

RUN chmod +x scripts/*

COPY start.sh ./

CMD ["bash", "start.sh"]
