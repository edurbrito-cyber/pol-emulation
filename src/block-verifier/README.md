# Block Verifier Example Smart Contract

This directory contains the source files for the example smart contract used for the proof of location verification.

## Compile

To compile the smart contract, run the following command:

```bash
$ ./compile.sh
```

This will compile the smart contract and place the compiled ABI and bytecode files in the `output` directory.

Additionally, one may run the `abigen` tool, from the `go-ethereum` repository, to generate a Go wrapper for the smart contract. To do so, run the following command:

```bash
$ mkdir -p ../geth-utils/blockverifier
$ ./abigen \
    --abi output/BlockHashVerifier.abi \
    --bin output/BlockHashVerifier.bin \
    --pkg blockverifier \
    --out ../geth-utils/blockverifier/BlockVerifier.go
```