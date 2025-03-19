#! /bin/bash

# This script compiles the geth-utils scripts into the bin folder
# and copies them to the openwrt-builder files folder

mkdir -p bin
# Compile the scripts
CGO_ENABLED=0 go build -o bin/geth-init geth-init.go
CGO_ENABLED=0 go build -o bin/geth-run geth-run.go
CGO_ENABLED=0 go build -o bin/geth-prover geth-prover.go

# Copy the scripts to the openwrt-builder files folder
cp -r bin/. ../../openwrt-builder/files/usr/bin/
