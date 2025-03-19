// SPDX-License-Identifier: GPL-3.0

// The following code is an example contract that verifies a given signature for a given hash.
// It is used to verify the witnesses signature of the block hash, and the prover signature of the transaction hash.
// The code is based on the following example:
// Reference: https://solidity-by-example.org/signature/

// Note:
// The code is not optimized for gas cost, but for readability.
// It is missing some checks:
// - check if the block struct contains the transaction
// - check if their hashes are correct
// - check if the transaction is valid, i.e. the transaction input contains the parent block hash
// - other checks...

pragma solidity >=0.8.2 <0.9.0;

contract PoLVerifier {

    function verifyBlockSignatures(
        bytes32 blockHash,
        bytes[] memory blockSignatures,
        address[] memory signers
    ) public pure returns(bool) {
        require(blockSignatures.length == signers.length, "Invalid input: signatures and signers arrays have different lengths");
        
        for (uint i = 0; i < blockSignatures.length; i++) {
            require(verifySignature(blockHash, blockSignatures[i], signers[i]), "Invalid signature");
        }
        
        return true;
    }
 
    function verifySignature(
        bytes32 hash,
        bytes memory signature,
        address signer
    ) public pure returns(bool) {
        return recoverSigner(getEthSignedMessageHash(hash), signature) == signer;
    }

    function getEthSignedMessageHash(
        bytes32 _messageHash
    ) public pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
}