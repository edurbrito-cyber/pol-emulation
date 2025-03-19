#! /bin/bash

# Compile the contract
# This script is meant to be run from inside the ´src/block-verifier´ directory
# It will create a directory called ´output´ and 
# put the compiled contract abi and bin files there
docker run \
    --rm --user "$(id -u):$(id -g)" \
    -v $(pwd):/sources ethereum/solc:stable \
    -o /sources/output --abi --bin --overwrite \
    /sources/BlockHashVerifier.sol

# # abigen is a tool that generates Go bindings for Ethereum contracts
# # to generate the Go bindings
# mkdir -p ../geth-utils/blockverifier
# ./abigen \
#     --abi output/BlockHashVerifier.abi \
#     --bin output/BlockHashVerifier.bin \
#     --pkg blockverifier \
#     --out ../geth-utils/blockverifier/blockverifier.go