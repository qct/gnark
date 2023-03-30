package hint

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/hash"
	"math/big"
)

func init() {
	Register(InvZero)
	Register(MIMC2Elements)
}

// InvZero computes the value 1/a for the single input a. If a == 0, returns 0.
func InvZero(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// save input
	result.Set(inputs[0])

	// a == 0, return
	if result.IsUint64() && result.Uint64() == 0 {
		return nil
	}

	result.ModInverse(result, q)
	return nil
}

func MIMC2Elements(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) < 2 {
		return errors.New("MIMCElements requires at least two input elementss")
	}
	newState := new(fr.Element).SetBigInt(inputs[1])
	block := new(fr.Element).SetBigInt(inputs[0])
	oldState := new(fr.Element).SetBigInt(inputs[1])
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])
	return nil
}

func MIMCElements(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) < 2 {
		return errors.New("MIMCHash requires at least two input elements")
	}

	var err error

	// Compute the hash for the first pair of input elements
	err = MIMC2Elements(q, inputs[:2], results)
	if err != nil {
		return err
	}

	// Compute the hash for the remaining input elements
	for i := 2; i < len(inputs); i++ {
		err = MIMC2Elements(q, []*big.Int{results[0], inputs[i]}, results)
		if err != nil {
			return err
		}
	}

	// Copy the final hash result to the output parameter
	results[0].SetBytes(results[0].Bytes())

	return nil
}

func GMimcBigInt(i1, i2 *big.Int) []byte {
	newState := new(fr.Element).SetBigInt(i2)
	block := new(fr.Element).SetBigInt(i1)
	oldState := new(fr.Element).SetBigInt(i2)
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	return bytes[:]
}

func GMimcBigInts(inputs ...*big.Int) []byte {
	if len(inputs) < 2 {
		return nil
	}

	// Compute the hash for the first pair of input elements
	hashBytes := GMimcBigInt(inputs[0], inputs[1])

	// Compute the hash for the remaining input elements
	for i := 2; i < len(inputs); i++ {
		hashBytes = GMimcBigInt(big.NewInt(0).SetBytes(hashBytes), inputs[i])
	}
	return hashBytes
}

func GMimcElements(msg []*fr.Element) *fr.Element {
	if len(msg) < 2 {
		return nil
	}

	// Convert msg []*fr.Element to inputs ...[]byte
	inputs := make([][]byte, len(msg))
	for i, e := range msg {
		res := e.Bytes()
		inputs[i] = res[:]
	}

	// Compute the hash of the inputs
	hashBytes := GMimcBytes(inputs...)

	// Convert the hash to an *fr.Element
	var hashFr fr.Element
	hashFr.SetBytes(hashBytes)
	return &hashFr
}

func GMimcBytes(inputs ...[]byte) []byte {
	if len(inputs) < 2 {
		return nil
	}

	bigIntInputs := make([]*big.Int, len(inputs))
	for i, input := range inputs {
		bigIntInputs[i] = new(big.Int).SetBytes(input)
	}
	return GMimcBigInts(bigIntInputs...)
}
