# OpenWrt Builder Docker Image

This directory contains the Dockerfile and supporting files for building the OpenWrt Builder Docker image. The image is based on the official Ubuntu image and contains all the necessary steps and tools to build OpenWrt.

## Building the Image

To build the image, run the following command:

```bash
$ docker build \
    --build-arg OPENWRT_TARGET=x86-64.Linux-x86_64 \
    --build-arg OPENWRT_TARGET_URL=https://downloads.openwrt.org/snapshots/targets/x86/64/openwrt-imagebuilder-x86-64.Linux-x86_64.tar.xz \
    --build-arg CACHEBUST=$(date +%s) \
    --build-arg OPENWRT_PROFILE=generic \
    --build-arg ADDITIONAL_FILES=files \
    -t openwrt-builder .
```

The `OPENWRT_TARGET` and `OPENWRT_TARGET_URL` arguments are used to specify the target and URL for the OpenWrt image builder. The `CACHEBUST` argument is used to bust the Docker cache when the image builder is updated. The `OPENWRT_PROFILE` argument is used to specify the OpenWrt profile to build. The `ADDITIONAL_FILES` argument is used to specify the directory containing additional [`files`](./files/) to copy into the image. The `--build-arg`  arguments are mandatory.

### The `files` Directory

The [`files`](./files/) directory contains the additional files that will be copied into the image. 
This directory should be structured as the root directory of the OpenWrt image, for the files intended to be copied into the image.

### OpenWrt Targets

The following table lists the available OpenWrt targets and their URLs:

| Target | URL | Profile | Comment |
|--------|-----|---------|---------|
| `x86-64.Linux-x86_64` | https://downloads.openwrt.org/snapshots/targets/x86/64/openwrt-imagebuilder-x86-64.Linux-x86_64.tar.xz | `generic` | |
| `bcm27xx-bcm2708.Linux-x86_64` | https://downloads.openwrt.org/snapshots/targets/bcm27xx/bcm2708/openwrt-imagebuilder-bcm27xx-bcm2708.Linux-x86_64.tar.xz | `rpi` | Ideal for Raspberry Pi Zero |
| `bcm27xx-bcm2709.Linux-x86_64` | https://downloads.openwrt.org/snapshots/targets/bcm27xx/bcm2709/openwrt-imagebuilder-bcm27xx-bcm2709.Linux-x86_64.tar.xz | `rpi-2` | Ideal for Raspberry Pi 2/3/4 |

## Running the Image

To run the image, run the following command:

```bash
$ docker run --rm -v ./output:/tmp/output openwrt-builder
```

The `-v ./output:/tmp/output` argument is used to mount the [`output`](./output/) directory in the host to the `/tmp/output` directory in the container.

The container will copy the newly built OpenWrt image to the [`output`](./output/) directory.