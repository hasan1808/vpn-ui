// Package random provides utilities for generating random strings and numbers.
package random

import (
	"crypto/rand"
	"math/big"
	"sync"
)

var (
	numSeq      [10]rune
	lowerSeq    [26]rune
	upperSeq    [26]rune
	numLowerSeq [36]rune
	numUpperSeq [36]rune
	allSeq      [62]rune

	// Fallback pseudo-random generator when crypto/rand fails (extremely rare).
	fallbackMu sync.Mutex
	fallbackSeed uint64
)

// init initializes the character sequences used for random string generation.
// It sets up arrays for numbers, lowercase letters, uppercase letters, and combinations.
func init() {
	for i := range 10 {
		numSeq[i] = rune('0' + i)
	}
	for i := range 26 {
		lowerSeq[i] = rune('a' + i)
		upperSeq[i] = rune('A' + i)
	}

	copy(numLowerSeq[:], numSeq[:])
	copy(numLowerSeq[len(numSeq):], lowerSeq[:])

	copy(numUpperSeq[:], numSeq[:])
	copy(numUpperSeq[len(numSeq):], upperSeq[:])

	copy(allSeq[:], numSeq[:])
	copy(allSeq[len(numSeq):], lowerSeq[:])
	copy(allSeq[len(numSeq)+len(lowerSeq):], upperSeq[:])
}

// Seq generates a random string of length n containing alphanumeric characters (numbers, lowercase and uppercase letters).
// Falls back to a deterministic pseudo-random generator if crypto/rand fails.
func Seq(n int) string {
	runes := make([]rune, n)
	for i := range n {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(allSeq))))
		if err != nil {
			fallbackMu.Lock()
			if fallbackSeed == 0 {
				fallbackSeed = 0x12345678
			}
			fallbackSeed = fallbackSeed*6364136223846793005 + 1
			idx = big.NewInt(int64(fallbackSeed % uint64(len(allSeq))))
			fallbackMu.Unlock()
		}
		runes[i] = allSeq[idx.Int64()]
	}
	return string(runes)
}

// Num generates a random integer between 0 and n-1.
// Falls back to a deterministic pseudo-random generator if crypto/rand fails.
func Num(n int) int {
	bn := big.NewInt(int64(n))
	r, err := rand.Int(rand.Reader, bn)
	if err != nil {
		fallbackMu.Lock()
		if fallbackSeed == 0 {
			fallbackSeed = 0x12345678
		}
		fallbackSeed = fallbackSeed*6364136223846793005 + 1
		r = big.NewInt(int64(fallbackSeed % uint64(n)))
		fallbackMu.Unlock()
	}
	return int(r.Int64())
}
