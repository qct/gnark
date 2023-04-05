package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/common"
	"testing"
)

func TestGKR(t *testing.T) {
	var one fr.Element
	one.SetOne()

	c := circuit.NewCircuit(
		[][]circuit.Wire{
			// Layer 0
			[]circuit.Wire{
				circuit.Wire{L: 0, R: 1, O: 0, Gate: circuit.AddGate{}},
				circuit.Wire{L: 0, R: 1, O: 1, Gate: circuit.MulGate{}},
			},
			// Layer 1
			[]circuit.Wire{
				circuit.Wire{L: 0, R: 1, O: 0, Gate: circuit.AddGate{}},
				circuit.Wire{L: 0, R: 1, O: 1, Gate: circuit.MulGate{}},
			},
		},
	)

	inputs := [][]fr.Element{
		[]fr.Element{common.Uint64ToFr(1), common.Uint64ToFr(2)},
		[]fr.Element{common.Uint64ToFr(3), common.Uint64ToFr(4)},
	}

	a := c.Assign(inputs, 2)

	expectedValues := [][][]fr.Element{
		[][]fr.Element{
			[]fr.Element{common.Uint64ToFr(1), common.Uint64ToFr(2)},
			[]fr.Element{common.Uint64ToFr(3), common.Uint64ToFr(4)},
		},
		[][]fr.Element{
			[]fr.Element{common.Uint64ToFr(3), common.Uint64ToFr(2)},
			[]fr.Element{common.Uint64ToFr(7), common.Uint64ToFr(12)},
		},
		[][]fr.Element{
			[]fr.Element{common.Uint64ToFr(5), common.Uint64ToFr(6)},
			[]fr.Element{common.Uint64ToFr(19), common.Uint64ToFr(84)},
		},
	}

	assert.Equal(
		t,
		expectedValues,
		a.Values,
		"Assignment invalid.",
	)

	outputs := a.Values[2]

	p := NewProver(c, a)
	proof := p.Prove(1)
	v := NewVerifier(1, c)
	validity := v.Verify(proof, inputs, outputs)

	assert.Equal(
		t,
		validity,
		true,
		"Proof invalid.",
	)
}
