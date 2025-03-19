package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	rand "math/rand"
	"time"
)

type Witness struct {
	X, Y    float64
	DBi     float64
	PrivKey *ecdsa.PrivateKey
	PubKey  *ecdsa.PublicKey
	R, S    string // Signature components
}

// Constants
const (
	speedOfLight       = 3e8 // m/s
	distance           = 50   // meters
	nRounds            = 128  // Number of rapid exchange rounds
	processingDelayBit = 1e-9 // 1 ns processing delay per bit
)

// signMessage signs a message (x, y, DBi) using ECDSA.
func signMessage(privKey *ecdsa.PrivateKey, message string) (string, string) {
	h := sha256.Sum256([]byte(message))
	r, s, _ := ecdsa.Sign(crand.Reader, privKey, h[:])
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	return hex.EncodeToString(rBytes), hex.EncodeToString(sBytes)
}

// verifyMessageSignature verifies the signature (rText, sText) of the message under pubKey.
func verifyMessageSignature(pubKey *ecdsa.PublicKey, message, rText, sText string) bool {
	h := sha256.Sum256([]byte(message))

	rBytes, errR := hex.DecodeString(rText)
	sBytes, errS := hex.DecodeString(sText)
	if errR != nil || errS != nil {
		return false
	}

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	return ecdsa.Verify(pubKey, h[:], r, s)
}

// generateWitnesses places 'num' witnesses in a circle of radius 'distance' around (proverX, proverY),
// simulating small noise in the DBi.
func generateWitnesses(proverX, proverY, distance float64, num int) []Witness {
	witnesses := make([]Witness, num)
	angleStep := 2 * math.Pi / float64(num)

	for i := 0; i < num; i++ {
		angle := float64(i) * angleStep
		x := proverX + distance*math.Cos(angle)
		y := proverY + distance*math.Sin(angle)

		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)

		// Simulate a measured distance bound with small noise.
		dbi := distance + math.Abs(rand.NormFloat64()*5)

		// Sign the (x, y, DBi).
		message := fmt.Sprintf("%f,%f,%f", x, y, dbi)
		r, s := signMessage(privKey, message)

		// Store all info in the Witness struct.
		witnesses[i] = Witness{
			X:      x,
			Y:      y,
			DBi:    dbi,
			PrivKey: privKey,
			PubKey:  &privKey.PublicKey,
			R:       r,
			S:       s,
		}
	}

	return witnesses
}

// distanceError computes the squared error between DBi and the actual distance.
func distanceError(proverX, proverY float64, witness Witness) float64 {
	dist := math.Sqrt(math.Pow(proverX-witness.X, 2) + math.Pow(proverY-witness.Y, 2))
	err := witness.DBi - dist
	return err * err // (DBi - dist)^2
}

// totalDistanceError sums the squared errors for all witnesses.
func totalDistanceError(proverX, proverY float64, witnesses []Witness) float64 {
	total := 0.0
	for _, w := range witnesses {
		total += distanceError(proverX, proverY, w)
	}
	return total
}

// minimizeProverPosition uses gradient descent to minimize sum of squared errors,
// i.e. sum((DBi - dist)^2), w.r.t. (proverX, proverY).
func minimizeProverPosition(witnesses []Witness) (float64, float64) {
	learningRate := 0.01
	threshold := 1e-6
	maxIterations := 1000

	// Start from an initial guess.
	px, py := 50.0, 50.0

	for i := 0; i < maxIterations; i++ {
		gradX, gradY := 0.0, 0.0

		// Compute partial derivatives from sum( (DBi - dist)^2 ).
		// For each witness:
		//   error = (DBi - dist)
		//   partial w.r.t. x = 2 * error * d/dx(error)
		//   d/dx(error) = d/dx(DBi - dist) = - d/dx(dist)
		//   dist = sqrt((px - wx)^2 + (py - wy)^2)
		//   d/dx(dist) = (px - wx)/dist
		// => partial w.r.t. x = 2 * error * ( - (px - wx)/dist )

		for _, w := range witnesses {
			dist := math.Sqrt(math.Pow(px-w.X, 2) + math.Pow(py-w.Y, 2))
			if dist < 1e-9 {
				continue // Avoid division by zero if dist~0.
			}

			errorVal := w.DBi - dist

			// partial derivative wrt x
			gradX += 2 * errorVal * ( - (px - w.X) / dist )

			// partial derivative wrt y
			gradY += 2 * errorVal * ( - (py - w.Y) / dist )
		}

		px -= learningRate * gradX
		py -= learningRate * gradY

		// If gradient is small, we assume convergence.
		if math.Abs(gradX) < threshold && math.Abs(gradY) < threshold {
			fmt.Println("Stopped at", i)
			break
		}
	}

	return px, py
}

// check if a point (px,py) is inside the triangle formed by (ax,ay),(bx,by),(cx,cy)
func isInsideTriangle(px, py, ax, ay, bx, by, cx, cy float64) bool {
	area := math.Abs((ax*(by-cy) + bx*(cy-ay) + cx*(ay-by)) / 2.0)
	area1 := math.Abs((px*(by-cy) + bx*(cy-py) + cx*(py-by)) / 2.0)
	area2 := math.Abs((ax*(py-cy) + px*(cy-ay) + cx*(ay-py)) / 2.0)
	area3 := math.Abs((ax*(by-py) + bx*(py-ay) + px*(ay-by)) / 2.0)
	return math.Abs(area-(area1+area2+area3)) < 1e-6
}

// final verification after minimization
func finalVerification(px, py float64, witnesses []Witness, thresh float64) (bool, string) {
	for i, w := range witnesses {
		dist := math.Sqrt((px-w.X)*(px-w.X) + (py-w.Y)*(py-w.Y))
		err := math.Abs(w.DBi - dist)
		if err <= thresh {
			for j := i + 1; j < len(witnesses)-1; j++ {
				for k := j + 1; k < len(witnesses); k++ {
					if isInsideTriangle(px, py, w.X, w.Y, witnesses[j].X, witnesses[j].Y, witnesses[k].X, witnesses[k].Y) {
						return true, fmt.Sprintf("ACCEPT: Prover pos inside triangle with witnesses %d,%d,%d", i, j, k)
					}
				}
			}
		}
	}
	return false, "REJECT: No suitable triangle found."
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Suppose the actual prover is at (50,50), with a circle radius of 50, and n witnesses.
	proverX, proverY, circleRadius := 50.0, 50.0, 50.0
	

	witnessCounts := []int{4, 5, 6, 7, 8}

	for _, wc := range witnessCounts {
		fmt.Printf("\n========= %d WITNESSES ===========\n", wc)


		// Generate the witnesses.
		witnesses := generateWitnesses(proverX, proverY, circleRadius, wc)

		fmt.Println("Generated Witnesses:")
		for _, w := range witnesses {
			fmt.Printf("Witness at (%.2f, %.2f), DBi=%.3f\n", w.X, w.Y, w.DBi)
		}

		start := time.Now()

		// Signature verification for each witness before minimization.
		fmt.Println("\nVerifying Witness Signatures...")
		for i, w := range witnesses {
			msg := fmt.Sprintf("%f,%f,%f", w.X, w.Y, w.DBi)
			ok := verifyMessageSignature(w.PubKey, msg, w.R, w.S)
			if !ok {
				fmt.Printf("Witness %d signature verification FAILED\n", i)
				return
			}
			fmt.Printf("Witness %d signature verification OK\n", i)
		}

		// Minimize to find the best (px, py) that fits the DBi.
		estX, estY := minimizeProverPosition(witnesses)
		fmt.Printf("\nEstimated Prover Position: (%.2f, %.2f)\n", estX, estY)

		ok, msg := finalVerification(estX, estY, witnesses, 5)
		fmt.Println(msg)
		if ok {
			fmt.Println("Prover Accepted.")
		} else {
			fmt.Println("Prover Rejected.")
		}

		fmt.Println("Time (ms):", time.Since(start).Seconds()*1000)

	}
}
