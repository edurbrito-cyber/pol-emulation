package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

const (
	hexCharsRegex = "0x[0-9a-fA-F]{40}"
)

func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		iface    *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if iface, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = iface.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", fmt.Errorf("no ipv4 address found for interface %s", interfaceName)
	}
	return ipv4Addr.String(), nil
}

func main() {
	signersFlag := flag.String("signers", "", "comma-separated list of signer addresses")

	flag.Parse()

	// get the account address from the self node
	// list the files in the keystore directory
	files, err := os.ReadDir("/root/.ethereum/keystore")
	if err != nil || len(files) == 0 {
		fmt.Println("Error reading keystore directory:", err)
		return
	}

	// get the first file in the keystore directory
	fileName := files[0].Name()

	// get the account address from the file name
	// the address comes after the last two dashes in the file name
	// UTC--2023-03-20T08-37-47.753790440Z--0311885597e5eaa5e9b06e70a4e50e663c3d8396
	// 0311885597e5eaa5e9b06e70a4e50e663c3d8396
	accountAddress := strings.Split(fileName, "--")[2]

	// parse the signers addresses and remove duplicates
	signersMap := make(map[string]bool)
	signersMap["0x"+accountAddress] = true

	if *signersFlag != "" {
		for _, signer := range strings.Split(*signersFlag, ",") {
			matched, _ := regexp.MatchString(hexCharsRegex, signer)
			if !matched {
				fmt.Printf("Error: invalid signer address '%s'\n", signer)
				return
			}
			signersMap[signer] = true
		}
	}

	// map keys to slice
	signers := make([]string, 0, len(signersMap))
	for k := range signersMap {
		signers = append(signers, k)
	}

	// sort the signers
	sort.Strings(signers)

	fmt.Println("Success!")
	fmt.Println("Signers:", signers)

	fmt.Println("Writing genesis.json...")

	// write genesis.json with signers in extraData
	// Open the file for writing, creating it if it doesn't exist
	file, err := os.OpenFile("/root/.ethereum/genesis.json", os.O_WRONLY|os.O_CREATE, 0644)

	if err != nil {
		fmt.Println("Error genesis.json opening file:", err)
		return
	}

	defer file.Close()

	// Write a formatted string to the file
	genesis := `{
		"config": {
		  "chainId": 11,
		  "homesteadBlock": 0,
		  "eip150Block": 0,
		  "eip155Block": 0,
		  "eip158Block": 0,
		  "byzantiumBlock": 0,
		  "constantinopleBlock": 0,
		  "petersburgBlock": 0,
		  "istanbulBlock": 0,
		  "muirGlacierBlock": 0,
		  "berlinBlock": 0,
		  "londonBlock": 0,
		  "arrowGlacierBlock": 0,
		  "grayGlacierBlock": 0,
		  "clique": {
			"period": 10,
			"epoch": 30000
		  }
		},
		"difficulty": "1",
		"gasLimit": "800000000",
		"extradata": "0x0000000000000000000000000000000000000000000000000000000000000000%s0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"alloc": {}
	}`

	// remove 0x from signers
	for i, signer := range signers {
		signers[i] = signer[2:]
	}

	// concatenate all signers into one string
	signersString := strings.Join(signers, "")

	// write genesis.json file
	_, err = fmt.Fprintf(file, genesis, signersString)
	if err != nil {
		fmt.Println("Error writing to genesis.json file:", err)
		return
	}

	fmt.Println("Running geth init...")

	// initialize geth with genesis.json
	// running geth --nousb --datadir /root/.ethereum init /root/.ethereum/genesis.json
	cmd := exec.Command("geth", "--nousb", "--datadir", "/root/.ethereum", "init", "/root/.ethereum/genesis.json")
	_, err = cmd.Output()
	if err != nil {
		fmt.Println("Error running command:", err)
		return
	}
}
