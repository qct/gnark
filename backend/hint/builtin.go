package hint

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

func init() {
	Register(IsZero)
	Register(Self)
	Register(MIMC2Elements)
}

// IsZero computes the value 1 - a^(modulus-1) for the single input a. This
// corresponds to checking if a == 0 (for which the function returns 1) or a
// != 0 (for which the function returns 0).
func IsZero(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// get fr modulus
	q := curveID.Info().Fr.Modulus()

	// save input
	result.Set(inputs[0])

	// reuse input to compute q - 1
	qMinusOne := inputs[0].SetUint64(1)
	qMinusOne.Sub(q, qMinusOne)

	// result =  1 - input**(q-1)
	result.Exp(result, qMinusOne, q)
	inputs[0].SetUint64(1)
	result.Sub(inputs[0], result).Mod(result, q)

	return nil
}

func Self(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	results[0].Set(inputs[0])
	return nil
}

func MIMC2Elements(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	newState := new(fr.Element).SetBigInt(inputs[0])
	block := new(fr.Element).SetBigInt(inputs[1])
	oldState := new(fr.Element).SetBigInt(inputs[0])
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])
	return nil
}

func MIMCElements(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) == 0 || len(results) == 0 {
		return errors.New("empty input or output")
	}

	newState := new(fr.Element).SetBigInt(inputs[0])
	for i := 1; i < len(inputs); i++ {
		block := new(fr.Element).SetBigInt(inputs[i])
		oldState := new(fr.Element).Set(newState)
		block.Sub(block, oldState)
		hash.MimcPermutationInPlace(newState, *block)
	}

	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])

	return nil
}

func ComputeMimc2Hash(i1, i2 *big.Int) []byte {
	newState := new(fr.Element).SetBigInt(i2)
	block := new(fr.Element).SetBigInt(i1)
	oldState := new(fr.Element).SetBigInt(i2)
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	return bytes[:]
}

func ComputeMimcHash(inputs ...*big.Int) []byte {
	if len(inputs) == 0 {
		return nil
	}

	newState := new(fr.Element).SetBigInt(inputs[0])
	for i := 1; i < len(inputs); i++ {
		block := new(fr.Element).SetBigInt(inputs[i])
		oldState := new(fr.Element).Set(newState)
		block.Sub(block, oldState)
		hash.MimcPermutationInPlace(newState, *block)
	}

	res := newState.Bytes()
	return res[:]
}

func MIMCFrElements(msg []*fr.Element) *fr.Element {
	newState := new(fr.Element).Set(msg[0])
	for i := 1; i < len(msg); i++ {
		block := new(fr.Element).Set(msg[i])
		oldState := new(fr.Element).Set(newState)
		block.Sub(block, oldState)
		hash.MimcPermutationInPlace(newState, *block)
	}

	return newState
}

func ComputeGMimcBytes(inputs ...[]byte) []byte {
	if len(inputs) == 0 {
		return nil
	}

	newState := new(fr.Element).SetBytes(inputs[0])
	for i := 1; i < len(inputs); i++ {
		block := new(fr.Element).SetBytes(inputs[i])
		oldState := new(fr.Element).Set(newState)
		block.Sub(block, oldState)
		hash.MimcPermutationInPlace(newState, *block)
	}

	res := newState.Bytes()
	return res[:]
}
