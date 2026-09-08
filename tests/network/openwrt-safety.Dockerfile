FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
       iproute2 iputils-ping tcpdump socat \
       qemu-system-x86 qemu-utils python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
