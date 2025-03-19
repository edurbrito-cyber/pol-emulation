# Ubuntu based OpenWrt build environment

# build with:
#
# sudo docker build \
# --build-arg OPENWRT_TARGET=22.03.3-x86-64.Linux-x86_64 \
# --build-arg OPENWRT_TARGET_URL=https://downloads.openwrt.org/releases/22.03.3/targets/x86/64/openwrt-imagebuilder-22.03.3-x86-64.Linux-x86_64.tar.xz \
# --build-arg CACHEBUST=$(date +%s) \
# --build-arg OPENWRT_PROFILE=generic \
# --build-arg ADDITIONAL_FILES=files \
# -t openwrt-builder .
#
# for rpi-zero: OPENWRT_TARGET=22.03.3-bcm27xx-bcm2708.Linux-x86_64 , OPENWRT_TARGET_URL=https://downloads.openwrt.org/releases/22.03.3/targets/bcm27xx/bcm2708/openwrt-imagebuilder-22.03.3-bcm27xx-bcm2708.Linux-x86_64.tar.xz , OPENWRT_PROFILE=rpi
# for rpi-4: OPENWRT_TARGET=22.03.3-bcm27xx-bcm2709.Linux-x86_64 , OPENWRT_TARGET_URL=https://downloads.openwrt.org/releases/22.03.3/targets/bcm27xx/bcm2709/openwrt-imagebuilder-22.03.3-bcm27xx-bcm2709.Linux-x86_64.tar.xz , OPENWRT_PROFILE=rpi-2
# for x86_64: OPENWRT_TARGET=22.03.3-x86-64.Linux-x86_64 , OPENWRT_TARGET_URL=https://downloads.openwrt.org/releases/22.03.3/targets/x86/64/openwrt-imagebuilder-22.03.3-x86-64.Linux-x86_64.tar.xz , OPENWRT_PROFILE=generic

# run with:
#
# sudo docker run --rm -v ./output:/tmp/output openwrt-builder

# pull the latest ubuntu image
FROM ubuntu:latest

# install the required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libncurses5-dev \
    libncursesw5-dev \
    zlib1g-dev \
    gawk \
    git \
    gettext \
    libssl-dev \
    xsltproc \
    rsync \
    wget \
    unzip \
    python3 \
    python3-distutils \
    file

# define the ARG OPENWRT_TARGET and OPENWRT_TARGET_URL
ARG OPENWRT_TARGET
ARG OPENWRT_TARGET_URL
# download the OpenWrt imagebuilder
RUN wget ${OPENWRT_TARGET_URL} -O /tmp/openwrt.tar.xz

# extract the OpenWrt imagebuilder
RUN mkdir /tmp/openwrt && tar -J -x -f /tmp/openwrt.tar.xz -C /tmp/openwrt

# enable ext4 journaling
RUN sed -i 's/# CONFIG_TARGET_EXT4_JOURNAL is not set/CONFIG_TARGET_EXT4_JOURNAL=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
# expand the rootfs to 1GB
RUN sed -i 's/CONFIG_TARGET_ROOTFS_PARTSIZE=[0-9]\+/CONFIG_TARGET_ROOTFS_PARTSIZE=1024/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
# uncomment the batman-adv lines in .config
RUN sed -i 's/# CONFIG_PACKAGE_kmod-batman-adv is not set/CONFIG_PACKAGE_kmod-batman-adv=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_BATMAN_V is not set/CONFIG_BATMAN_ADV_BATMAN_V=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_BLA is not set/CONFIG_BATMAN_ADV_BLA=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_DAT is not set/CONFIG_BATMAN_ADV_DAT=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_NC is not set/CONFIG_BATMAN_ADV_NC=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_MCAST is not set/CONFIG_BATMAN_ADV_MCAST=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_DEBUG is not set/CONFIG_BATMAN_ADV_DEBUG=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config
RUN sed -i 's/# CONFIG_BATMAN_ADV_TRACING is not set/CONFIG_BATMAN_ADV_TRACING=y/' /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET}/.config

# define the ARG ADDITIONAL_FILES
ARG ADDITIONAL_FILES
# copy the additional files from the host to the image
ADD --chown=1000:1000 ${ADDITIONAL_FILES} /tmp/files/

# cache busting
ARG CACHEBUST=1
# define the ARG OPENWRT_PROFILE
ARG OPENWRT_PROFILE
# build the image
RUN cd /tmp/openwrt/openwrt-imagebuilder-${OPENWRT_TARGET} && \
    make info && \
    make image PROFILE=${OPENWRT_PROFILE} PACKAGES="kmod-fs-ext4 kmod-batman-adv e2fsprogs batctl-full wpad-openssl geth curl -wpad-basic -wpad-basic-wolfssl -wpad-basic-mbedtls" FILES="/tmp/files" && \ 
    mkdir /tmp/output

# create an env variable for persistence
ENV OPENWRT_TARGET=${OPENWRT_TARGET}

# copy the output to the host
CMD cp -r /tmp/openwrt/openwrt-imagebuilder-$OPENWRT_TARGET/bin/targets/ /tmp/output/ && \
    chown -R 1000:1000 /tmp/output