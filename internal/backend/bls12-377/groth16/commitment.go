// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"crypto/sha256"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/constraint"
	"math/big"
)

func solveCommitmentWire(commitmentInfo *constraint.Commitment, commitment *curve.G1Affine, publicCommitted []*big.Int) (fr.Element, error) {
	bytes := sha256.Sum256(commitmentInfo.SerializeCommitment(commitment.Marshal(), publicCommitted, (fr.Bits-1)/8+1))
	bi := new(big.Int).SetBytes(bytes[:])
	return *new(fr.Element).SetBigInt(bi), nil
}
