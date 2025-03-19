package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	enodeRegex = "^enode://[0-9a-fA-F]{128}@[a-fA-F0-9.:]+:[0-9]+$"
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
	bootnodesFlag := flag.String("bootnodes", "", "comma-separated list of bootnode enode addresses")

	flag.Parse()

	var bootnodes []string

	if *bootnodesFlag != "" {

		bootnodes = strings.Split(*bootnodesFlag, ",")

		fmt.Println("Parsing bootnodes...")

		for _, bootnode := range bootnodes {
			if matched, _ := regexp.MatchString(enodeRegex, bootnode); !matched {
				fmt.Printf("Error: invalid bootnode enode address '%s'\n", bootnode)
				return
			}

			enodeSplit := strings.Split(bootnode, "@")
			enode, ipAndPort := enodeSplit[0], enodeSplit[1]
			// extract enode address
			enode = strings.TrimPrefix(enode, "enode://")
			// verify that the enode address is valid
			if len(enode) != 128 {
				fmt.Printf("Error: invalid enode address in bootnode enode address '%s'\n", bootnode)
				return
			}

			// extract IP address and port from bootnode enode address
			ip, portStr, err := net.SplitHostPort(ipAndPort)
			if err != nil {
				fmt.Printf("Error: invalid bootnode enode address '%s'\n", bootnode)
				return
			}

			// verify that the port is a valid integer
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 0 || port > 65535 {
				fmt.Printf("Error: invalid port in bootnode enode address '%s'\n", bootnode)
				return
			}

			// verify that the IP address is valid
			if net.ParseIP(ip) == nil {
				fmt.Printf("Error: invalid IP address in bootnode enode address '%s'\n", bootnode)
				return
			}
		}
	}

	fmt.Println("Success!")
	fmt.Println("Bootnodes:", bootnodes)

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

	fmt.Println("Running geth...")

	// get ip address of the node for the batman interface
	addr, err := GetInterfaceIpv4Addr("bat0")
	if err != nil {
		fmt.Println("Error getting ip address:", err)
		return
	}

	// run geth with the bootnodes and ip address
	// geth --nousb --datadir /root/.ethereum --networkid 11 \
	// --http --http.addr 192.168.0.1 --http.port 8545 \
	// --http.api "eth,net,web3,personal,clique" \
	// --allow-insecure-unlock --netrestrict 192.168.0.0/24 --nat "extip:192.168.0.1" \
	// --port 30301 --maxpeers 50 --miner.gasprice 0 \
	// --unlock 0xA052112667220935273f2A8220DB5D597CaF13bC --password /root/.password --mine \
	// --bootnodes "enode://2b044e3696c9767eae04a74a9cddaf3dd8028413fc0a8fd903cb6d308af8927f38cca6abc50502ad849689c3ae5adaf63002a829ac62791d5328c6663a69546a@192.168.0.2:30301" \
	// --cache=1024 --snapshot=0 console

	// Create a file to store the logs
	logfile, err := os.Create("/root/.ethereum/geth.log")
	if err != nil {
		fmt.Println("Error creating log file:", err)
		return
	}
	defer logfile.Close()

	bootnodesString := ""
	if len(bootnodes) > 0 {
		bootnodesString = "--bootnodes \"" + strings.Join(bootnodes, ",") + "\" "
	}

	cmdString := "geth --nousb --datadir /root/.ethereum --networkid 11 " +
		"--http --http.addr " + addr + " --http.port 8545 " +
		"--http.api \"eth,net,web3,personal,clique\" " +
		"--allow-insecure-unlock --netrestrict 192.168.0.0/24 --nat \"extip:" + addr + "\" " +
		"--port 30301 --maxpeers 50 --miner.gasprice 0 " +
		"--unlock 0x" + accountAddress + " --password /root/.password --mine " +
		bootnodesString + "--cache=1024 --snapshot=0"

	// Start the command in the background and redirect its output to the log file
	cmd := exec.Command("/bin/sh", "-c", cmdString+" > /root/.ethereum/geth.log 2>&1 &")
	err = cmd.Start()
	if err != nil {
		fmt.Println("Error starting geth:", err)
		return
	}

	fmt.Println("Geth running in background with PID", cmd.Process.Pid)
}
