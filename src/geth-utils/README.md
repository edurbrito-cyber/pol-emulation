# geth-utils

This directory contains the source files for the utility programs used to interact with the Ethereum blockchain.

## Compile

To compile the utility programs, run the following command:

```bash
$ ./compile.sh
```

This will compile the utility programs and place the compiled binaries in the `bin` directory.

It will additionally copy the compiled binaries to the `openwrt-builder/files/usr/bin/` directory, so that they can be included in the OpenWrt image.

## Usage

The utility programs can be used to interact with the Ethereum blockchain. The following programs are available:

* `geth-init`: Initialize a new Ethereum blockchain. This will create a new genesis file and initialize the blockchain with it. It may receive a list of additional signers as arguments, which will be added to the genesis file.
* `geth-run`: Run a new Ethereum node. This will start a new Ethereum node and connect it to the blockchain. It may receive a list of additional bootnodes as arguments, which will be used to connect a running blockchain.
* `geth-prover`: Run the proof-of-location prover process. This will simulate a proof-of-location generation process, which will submit a transaction to the blockchain and gather the required signatures. It may receive a list of additional signers as arguments, which will be used to gather the required signatures.
