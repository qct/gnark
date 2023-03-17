package hint

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestMIMC2Elements(t *testing.T) {
	inputs := []*big.Int{big.NewInt(0), big.NewInt(1)}
	results := []*big.Int{big.NewInt(0)}
	err := MIMC2Elements(ecc.BN254, inputs, results)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("result:%x\n", results[0].Bytes())

	hash := ComputeMimc2Hash(big.NewInt(0), big.NewInt(1))
	fmt.Printf("result2:%x\n", hash)
	assert.Equal(t, hash, results[0].Bytes())
}

func TestGeneralMimc(t *testing.T) {
	inputs := []*big.Int{big.NewInt(0), big.NewInt(1)}
	results := []*big.Int{big.NewInt(0)}
	err := MIMC2Elements(ecc.BN254, inputs, results)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("result:%x\n", results[0].Bytes())

	results2 := []*big.Int{big.NewInt(0)}
	_ = MIMCElements(ecc.BN254, inputs, results2)
	fmt.Printf("result2:%x\n", results2[0].Bytes())
	assert.Equal(t, results[0].Bytes(), results2[0].Bytes())
}

func TestGeneralMimc2(t *testing.T) {
	inputs := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
	results := []*big.Int{big.NewInt(0)}
	_ = MIMCElements(ecc.BN254, inputs, results)
	fmt.Printf("result:%x\n", results[0].Bytes())

	results2 := ComputeMimcHash(inputs[0], inputs[1], inputs[2])
	fmt.Printf("result2:%x\n", results2)
	assert.Equal(t, results[0].Bytes(), results2)
}

func TestMIMCFrElements(t *testing.T) {
	inputs := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)}
	elements := MIMCFrElements([]*fr.Element{fromBigIntToFr(inputs[0]), fromBigIntToFr(inputs[1]), fromBigIntToFr(inputs[2])})
	res1 := elements.Bytes()
	fmt.Printf("result:%x\n", res1)

	res2 := ComputeGMimcBytes(inputs[0].Bytes(), inputs[1].Bytes(), inputs[2].Bytes())
	fmt.Printf("result2:%x\n", res2)
}

func fromBigIntToFr(b *big.Int) *fr.Element {
	ele := fr.Element{0, 0, 0, 0}
	ele.SetBigInt(b)
	return &ele
}
