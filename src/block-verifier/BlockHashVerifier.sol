// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract BlockHashVerifier {

    int public counter = 0;
    
    function verifyLastBlockHashPure(bytes32 hashToCheck) public view returns(bool) {
        bytes32 lastBlockHash = blockhash(block.number - 1);
        return lastBlockHash == hashToCheck;
    }

    function verifyLastBlockHash(bytes32 hashToCheck) public returns(bool) {
        bytes32 lastBlockHash = blockhash(block.number - 1);
        counter++;
        return lastBlockHash == hashToCheck;
    }
}