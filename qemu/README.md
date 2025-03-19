# QEMU Emulation Environment

This directory contains the scripts for setting up a QEMU emulation environment for OpenWrt and BATMAN. The setup is based on the [OpenWrt QEMU Emulation Environment](https://www.open-mesh.org/doc/devtools/Emulation_Environment.html). 

## Running the instances

To run the VM instances, first copy the `openwrt-x86-64-generic-ext4-combined-efi.img` image to this directory. You may need to first extract the image from the `openwrt-x86-64-generic-ext4-combined-efi.img.gz` file.

Then, in separate terminals, run the following commands for each instance:

```bash
$ ./run.sh <instance_type> <instance_number>
```

The instance type should be either `witness` or `prover`. The instance number should be a positive integer. The script will create, for each instance, a (copy on write) snapshot of the base image. Then, it will start the instance, and connect it to a virtual network, using the tap device corresponding to the instance type and number. BATMAN is also started on the instance. 

## Starting the witness Ethereum blockchain

To start the Ethereum blockchain for the witnesses, do the following:

```bash
# getting the witness addresses
# run on each witness instance
$ ls -1t /root/.ethereum/keystore/UTC--* | head -1 | awk -F"--" '{printf "0x%s\n", $3}'
# remember all the witness addresses

# initialize the genesis block
# on each witness instance 
# and with the other witness addresses as arguments 
# run the following command
$ geth-init -signers <witness_address_a>,<witness_address_b>,<witness_address_c>

# start the blockchain
# on each witness instance run the following command
# NB:   
#   * the first witness instance does not need bootnodes
#   * the other witness instances need only the enode of the first witness instance
#   * after running `geth-run` on the first witness instance, its enode can be obtained by running the following command
#     $ geth attach
#     > admin.nodeInfo.enode
$ geth-run -bootnodes <witness_enode_1>

# attach to the blockchain
# on each witness instance run the following command
$ geth attach

# check peers
> admin.peers

# check current block number
> eth.blockNumber
```

Example run:

```bash
# on witness 1
$ ls -1t /root/.ethereum/keystore/UTC--* | head -1 | awk -F"--" '{printf "0x%s\n", $3}'
0xf0988f23802b795c8d77cd51d769614faa41cc66

# on witness 2
$ ls -1t /root/.ethereum/keystore/UTC--* | head -1 | awk -F"--" '{printf "0x%s\n", $3}'
0x2b6a91f8c65d2d39fed38f85d374aac747510b57

# on witness 3
$ ls -1t /root/.ethereum/keystore/UTC--* | head -1 | awk -F"--" '{printf "0x%s\n", $3}'
0x0843a0019582837274c4c20b760bb336d9ae19ec

# on witnesses 1,2,3
$ geth-init -signers 0xf0988f23802b795c8d77cd51d769614faa41cc66,0x2b6a91f8c65d2d39fed38f85d374aac747510b57,0x0843a0019582837274c4c20b760bb336d9ae19ec

# on witness 1
$ geth-run
$ geth attach
> admin.nodeInfo.enode
enode://44643c74c538d7dd3d28f46bb33ff29ba20e1722199779e6f1fb5cc35ad4d33fa9f9e2747bd2caa22d1a66c734368a67365b4e3ff8015cc851b545d394dc43de@192.168.0.1:30301

# on witnesses 2,3
$ geth-run -bootnodes enode://44643c74c538d7dd3d28f46bb33ff29ba20e1722199779e6f1fb5cc35ad4d33fa9f9e2747bd2caa22d1a66c734368a67365b4e3ff8015cc851b545d394dc43de@192.168.0.1:30301

# on witnesses 1,2,3
# if not yet attached
$ geth attach
> eth.blockNumber
3

# the witness blockchain is now running
```

## Connect the prover to the witness blockchain

To connect the prover to the witness blockchain, do the following:

```bash
# on the prover instance, get the latest block number
$ curl -s -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true],"id":1}' \
      http://192.168.0.1:8545 \
    | sed -n 's/.*"number":"0x\([0-9a-f]*\)".*/0x\1/p' \
    | xargs printf "%d\n"
9

# on the prover instance, get the latest block hash
$ curl -s -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true],"id":1}' \
      http://192.168.0.1:8545 \
    | sed -n 's/.*"hash":"0x\([0-9a-f]*\)".*/0x\1/p'
0x690ea1859dbe729c83d51c086aafeb0a489549a9b1ace96e928dfccc4bff58ee

# on the prover instance, get the signature of the latest block hash by the witness 1
$ curl -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","method":"eth_sign","params":["0xf0988f23802b795c8d77cd51d769614faa41cc66", "0x690ea1859dbe729c83d51c086aafeb0a489549a9b1ace96e928dfccc4bff58ee"],"id":1}' \
        http://192.168.0.1:8545
{"jsonrpc":"2.0","id":1,"result":"0xe825164f31bf1d993d020203e83be5590f53c7bcff5007be76cbe612ebb69bdb148ea9d1607ef4423fca71656f27fd08b597378ff05d9707e7c957595b5c4bd81b"}

# on the prover instance, get the signature of the latest block hash by the witness 2
$ curl -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","method":"eth_sign","params":["0x2b6a91f8c65d2d39fed38f85d374aac747510b57", "0x690ea1859dbe729c83d51c086aafeb0a489549a9b1ace96e928dfccc4bff58ee"],"id":1}' \
        http://192.168.0.2:8545
{"jsonrpc":"2.0","id":1,"result":"0xdc793792b89dbf01b127a07d04a78e658a0a56ac0626e86c0ffdbd36575dd2e16145acc92e6a19d0d911d2b7e49bc777ee5a47b2bc174f0e074f1c6c44a288391c"}

# on the prover instance, get the signature of the latest block hash by the witness 3
$ curl -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","method":"eth_sign","params":["0x0843a0019582837274c4c20b760bb336d9ae19ec", "0x690ea1859dbe729c83d51c086aafeb0a489549a9b1ace96e928dfccc4bff58ee"],"id":1}' \
        http://192.168.0.3:8545
{"jsonrpc":"2.0","id":1,"result":"0x0d65ede8956794216d7fa243c3c6fcfd70c1f65a763cf4ce67f2eb96acad21f20b807b6b51a2b559e1049b5db6d4bad0c9dd15fa273fa46f882a9d063b14e4be1b"}

# attach the prover instance to the witness blockchain
$ geth attach http://192.168.0.1:8545

# get the latest block number
> eth.blockNumber
```

## Simulate the proof-of-location generation & verification

To simulate the proof-of-location generation & verification, we will use the `geth-prover` tool.
It will create, sign and send a synchronous transaction to the blockchain and will wait for the transaction to be mined.
It will then gather the signatures of the witnesses.

```bash
# on the prover instance
# outside of the geth console, run the geth-prover tool with the witness addresses and endpoints
$ geth-prover -signers 0x2b6a91f8c65d2d39fed38f85d374aac747510b57,0x0843a0019582837274c4c20b760bb336d9ae19ec,0xf0988f23802b795c8d77cd51d769614faa41cc66 -ips http://192.168.0.1:8545,http://192.168.0.2:8545,http://192.168.0.3:8545
```

## (Unstable) Missing steps

To interact with a smart contract, we need to have the ABI of the smart contract, and its bytecode should be deployed on the blockchain, for example, via the genesis file.
The ABI is a JSON file that describes the functions of the smart contract.
Check the `src/block-verifier` folder for more information.

```bash
# Note: this is for testing purposes only
# The following steps are not stable and should be replaced by a more robust solution
# The current version of go-ethereum may fail at executing the smart contract

# on the prover instance
# attach the prover instance to the witness blockchain
$ geth attach http://192.168.0.1:8545

# unlock an account
personal.unlockAccount(eth.coinbase,"")

# load the smart contract ABI
# Note: replace the ABI with the ABI of your smart contract
> var abi = JSON.parse('[{"inputs": [],"name": "greet","outputs": [{"internalType": "int256","name": "","type": "int256"}], "stateMutability":"view","type": "function"}]');

# load the smart contract address
# Note: replace the address with the address of your smart contract
> var address = "0x0000000000000000000000000000000000000011";

# load the smart contract
> var contract = web3.eth.contract(abi).at(address);

# call the smart contract
> contract.verifyLastBlockHashPure.call(eth.getBlockByNumber("latest").hash)
true

# send a transaction to the smart contract
# Note: 
# * In the current version of go-ethereum, it may fail for insufficient gas/funds
# Solve it by allocating funds to the account
# * It may also fail at returning the correct output
> contract.verifyLastBlockHash.sendTransaction(eth.getBlockByNumber("latest").hash, {from: eth.coinbase, gas: 22627})
0xcef5556bf06d49c12c4fd2684e68d142791b4b127f18e4d576c09c4ea60071c5

# get the transaction receipt
> eth.getTransactionReceipt("0x188b9008bf6f777ac2bc9b1008b2358ae1f53305ce1608123460a439c4fa9044")

# get the transaction result
> eth.getTransactionReceipt("0x15889a242c830ad91f606c9026e0d68a3c6f3d5bbcd9628903de69f655f643bc").logs[0].data

# get transaction
> eth.getTransaction("0x188b9008bf6f777ac2bc9b1008b2358ae1f53305ce1608123460a439c4fa9044")

# all other steps...
```
