package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	hexCharsRegex = "0x[0-9a-fA-F]{40}"
	ipRegex       = "http://[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]{1,5}"
)

func main() {

	signersFlag := flag.String("signers", "", "comma-separated list of signer addresses, ex: 0xf0988f23802b795c8d77cd51d769614faa41cc66,0x2b6a91f8c65d2d39fed38f85d374aac747510b57,0x0843a0019582837274c4c20b760bb336d9ae19ec")
	ipsFlag := flag.String("ips", "", "comma-separated list of corresponding signer ip addresses, ex: http://192.168.0.1:8545,http://192.168.0.2:8545,http://192.168.0.3:8545")

	flag.Parse()

	signers := []string{}

	if *signersFlag != "" {
		signers = append(signers, strings.Split(*signersFlag, ",")...)
		for _, signer := range signers {
			matched, _ := regexp.MatchString(hexCharsRegex, signer)
			if !matched {
				fmt.Printf("Error: invalid signer address '%s'\n", signer)
				os.Exit(1)
			}
		}
	}

	ips := []string{}

	if *ipsFlag != "" {
		ips = append(ips, strings.Split(*ipsFlag, ",")...)
		for _, ip := range ips {
			matched, _ := regexp.MatchString(ipRegex, ip)
			if !matched {
				fmt.Printf("Error: invalid ip address '%s'\n", ip)
				os.Exit(1)
			}
		}
	}

	if len(signers) != len(ips) {
		fmt.Println("Error: number of signers and IPs must be equal")
		os.Exit(1)
	}

	// choose random ip
	clientIp := ips[rand.Intn(len(ips))]

	client, err := ethclient.Dial(clientIp)
	if err != nil {
		fmt.Println("Error connecting to client:", err)
		os.Exit(1)
	}

	// get the account address from the self node
	// list the files in the keystore directory
	files, err := os.ReadDir("/root/.ethereum/keystore")
	if err != nil || len(files) == 0 {
		fmt.Println("Error reading keystore directory:", err)
		os.Exit(1)
	}

	// get the first file in the keystore directory
	privateKeyFileName := files[0].Name()

	jsonBytes, err := ioutil.ReadFile("/root/.ethereum/keystore/" + privateKeyFileName)
	if err != nil {
		fmt.Println("Error reading keystore file:", err)
		os.Exit(1)
	}

	privateKey, err := keystore.DecryptKey(jsonBytes, "")
	if err != nil {
		fmt.Println("Error decrypting private key:", err)
		os.Exit(1)
	}

	publicKey := privateKey.Address

	nonce, err := client.PendingNonceAt(context.Background(), publicKey)
	if err != nil {
		fmt.Println("Error getting nonce:", err)
		os.Exit(1)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		fmt.Println("Error getting chain ID:", err)
		os.Exit(1)
	}

	lastBlockHeader, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		fmt.Println("Error getting last block header:", err)
		os.Exit(1)
	}

	lastBlockHash := lastBlockHeader.Hash().Bytes()

	value := big.NewInt(0)     // in wei (0 eth)
	gasLimit := uint64(100000) // in units
	gasPrice := big.NewInt(0)  // in wei (0 wei)

	// Or to whatever address the prover wants to send to
	toAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, lastBlockHash)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey.PrivateKey)
	if err != nil {
		fmt.Println("Error signing transaction:", err)
		os.Exit(1)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Println("Error sending transaction:", err)
		os.Exit(1)
	}

	fmt.Printf("Transaction Hash: %s\n", signedTx.Hash().Hex())

	var txData *types.Transaction

	// while transaction is pending, wait for it to be mined
	for {
		_txData, isPending, err := client.TransactionByHash(context.Background(), signedTx.Hash())

		if err != nil {
			fmt.Println("Error getting transaction data:", err)
			os.Exit(1)
		}

		if !isPending {
			txData = _txData
			break
		}
	}

	fmt.Printf("Transaction Data: 0x%x\n", txData.Data())

	// get transaction receipt
	receipt, err := client.TransactionReceipt(context.Background(), signedTx.Hash())
	if err != nil {
		fmt.Println("Error getting transaction receipt:", err)
		os.Exit(1)
	}

	fmt.Printf("Transaction Status: %d\n", receipt.Status)

	// get the block data
	block, err := client.BlockByHash(context.Background(), receipt.BlockHash)
	if err != nil {
		fmt.Println("Error getting block data:", err)
		os.Exit(1)
	}

	fmt.Printf("Block Hash: 0x%x\n", block.Hash().Bytes())
	fmt.Printf("Block Parent Hash: 0x%x\n", block.ParentHash().Bytes())
	fmt.Printf("Valid Transaction: %t\n", bytes.Equal(txData.Data(), block.ParentHash().Bytes()))

	// ask the witnesses to sign the block hash
	signatures := []string{}

	// call equivalent of
	// curl -X POST -H "Content-Type: application/json" \
	//   --data '{"jsonrpc":"2.0","method":"eth_sign","params":["0x2b6a91f8c65d2d39fed38f85d374aac747510b57", "0x690ea1859dbe729c83d51c086aafeb0a489549a9b1ace96e928dfccc4bff58ee"],"id":1}' \
	//     http://192.168.0.2:8545

	for i, signer := range signers {
		// Create the JSON-RPC request
		rpcRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "eth_sign",
			"params": []interface{}{
				signer,
				"0x" + hex.EncodeToString(block.Hash().Bytes()),
			},
			"id": 1,
		}

		// Encode the request body as JSON
		requestBody, err := json.Marshal(rpcRequest)
		if err != nil {
			fmt.Println("Error encoding JSON:", err)
			os.Exit(1)
		}

		// Send the HTTP request to the Ethereum node
		response, err := http.Post(ips[i], "application/json", bytes.NewBuffer(requestBody))
		if err != nil {
			fmt.Println("Error sending HTTP request:", err)
			os.Exit(1)
		}
		defer response.Body.Close()

		// Read the response body
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			os.Exit(1)
		}

		// Print the response body
		// fmt.Println("Response body:", string(responseBody))

		// Decode the JSON-RPC response
		var rpcResponse map[string]interface{}
		err = json.Unmarshal(responseBody, &rpcResponse)
		if err != nil {
			fmt.Println("Error decoding JSON:", err)
			os.Exit(1)
		}

		// Print the signed message
		signedMessage := rpcResponse["result"].(string)
		signatures = append(signatures, signedMessage)

		fmt.Printf("Signed message (from %s %s): %s\n", signer, ips[i], signedMessage)
	}
}
