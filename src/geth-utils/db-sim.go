package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

type Witness struct {
	X, Y   float64
	PrivKey *ecdsa.PrivateKey
	PubKey  *ecdsa.PublicKey
}

const (
	speedOfLight       = 3e8 // m/s
	distance           = 50   // meters
	nRounds            = 128  // Number of rapid exchange rounds
	processingDelayBit = 1e-9 // 1 ns processing delay per bit
)

func generateCommitment() (string, []int) {
	bits := make([]int, nRounds)
	for i := 0; i < nRounds; i++ {
		bits[i] = rand.Intn(2)
	}
	hash := sha256.Sum256([]byte(fmt.Sprint(bits)))
	return hex.EncodeToString(hash[:]), bits
}

func verifyCommitment(commitment string, bits []int) bool {
	hash := sha256.Sum256([]byte(fmt.Sprint(bits)))
	return commitment == hex.EncodeToString(hash[:])
}

func rapidExchange(proverCommit, witnessCommit []int) (float64, []int) {
	responseBits := make([]int, nRounds)
	totalTime := 0.0

	for i := 0; i < nRounds; i++ {
		responseBits[i] = proverCommit[i] ^ witnessCommit[i] // XOR operation
		propDelay := (2 * distance) / speedOfLight           // Light propagation delay
		totalBitTime := propDelay + processingDelayBit       // Total time for one bit exchange
		time.Sleep(time.Duration(totalBitTime * 1e9))        // Simulate delay in ns
		totalTime += totalBitTime
	}
	return totalTime, responseBits
}

func distanceBoundingSimulation() {
	startCommit := time.Now()
	proverCommitHash, proverCommit := generateCommitment()
	witnessCommitHash, witnessCommit := generateCommitment()
	commitTime := time.Since(startCommit).Seconds()

	rapidExchangeTime, _ := rapidExchange(proverCommit, witnessCommit)

	startDecommit := time.Now()
	validProver := verifyCommitment(proverCommitHash, proverCommit)
	validWitness := verifyCommitment(witnessCommitHash, witnessCommit)
	decommitTime := time.Since(startDecommit).Seconds()

	fmt.Printf("Commit Phase (Hash): %.6f ms\n", commitTime*1000)
	fmt.Printf("Rapid Exchange Time: %.6f ms\n", rapidExchangeTime*1000)
	fmt.Printf("Decommit Phase (Hash): %.6f ms\n", decommitTime*1000)
	fmt.Printf("Total Distance Bounding Time: %.6f ms\n", (commitTime+rapidExchangeTime+decommitTime)*1000)
	fmt.Printf("Commitments Valid: Prover=%v, Witness=%v\n", validProver, validWitness)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	distanceBoundingSimulation()
}
