# README

This repository contains the source code of the proof-of-concept implementation of a decentralized proof-of-location protocol. 

## Structure

The repository is structured as follows:

- `openwrt-builder/`: contains the Dockerfile and supporting files for building the `openwrt-builder` Docker image, to generate the OpenWrt images used in the proof-of-concept.
- `src/`: contains the source files for the utility programs used in the proof-of-concept.
- `qemu/`: contains the scripts for setting up a QEMU emulation environment for OpenWrt and BATMAN.