package gkr_mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	gkrNative "github.com/consensys/gnark/std/gkr/gkr"
	"github.com/consensys/gnark/std/gkr/snark/gkr"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
)

type GkrCircuitSlice struct {
	Circuit                 gkr.Circuit
	Proof                   gkr.Proof
	QInitial, QInitialprime []frontend.Variable
	VInput, VOutput         polynomial.MultilinearByValues
}

type GkrCircuit [7]GkrCircuitSlice

func AllocateGKRMimcTestCircuit(bN int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuit()
	return GkrCircuitSlice{
		Circuit:       circuit,
		Proof:         gkr.AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: make([]frontend.Variable, bN),
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func AllocateGKRMimcTestCircuitBatch(bN int, batch int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuitBatch(batch)
	qInitialPrime := make([]frontend.Variable, bN)
	for i := range qInitialPrime {
		qInitialPrime[i] = 0
	}
	return GkrCircuitSlice{
		Circuit:       circuit,
		Proof:         gkr.AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: qInitialPrime,
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func (c *GkrCircuitSlice) Assign(
	proof gkrNative.Proof,
	inputs [][]fr.Element,
	outputs [][]fr.Element,
	qInitialprime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialprime {
		c.QInitialprime[i] = qInitialprime[i]
	}
	c.VInput.AssignFromChunkedBKT(inputs)
	c.VOutput.AssignFromChunkedBKT(outputs)
}

func (c *GkrCircuitSlice) Define(cs frontend.API) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}
