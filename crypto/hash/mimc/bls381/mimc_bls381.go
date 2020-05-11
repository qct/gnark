// Copyright 2020 ConsenSys AG
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

// Code generated by gnark/crypto/internal/generator DO NOT EDIT

package bls381

import (
	"encoding/binary"
	"hash"
	"math/big"

	"github.com/consensys/gurvy/bls381/fr"
	"golang.org/x/crypto/sha3"
)

const mimcNbRounds = 91

// BlockSize size that mimc consumes
const BlockSize = 32

// Params constants for the mimc hash function
type Params []fr.Element

// NewParams creates new mimc object
func NewParams(seed string) Params {

	// set the constants
	res := make(Params, mimcNbRounds)

	rnd := sha3.Sum256([]byte(seed))
	value := new(big.Int).SetBytes(rnd[:])

	for i := 0; i < mimcNbRounds; i++ {
		rnd = sha3.Sum256(value.Bytes())
		value.SetBytes(rnd[:])
		res[i].SetBigInt(value)
	}

	return res
}

// digest represents the partial evaluation of the checksum
// along with the params of the mimc function
type digest struct {
	Params Params
	h      fr.Element
	data   []byte // data to hash
}

// NewMiMC returns a MiMCImpl object, pure-go reference implementation
func NewMiMC(seed string) hash.Hash {
	d := new(digest)
	params := NewParams(seed)
	//d.Reset()
	d.Params = params
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
	d.h = fr.Element{0, 0, 0, 0}
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	buffer := d.checksum()
	d.data = nil // flush the data already hashed
	hash := toBytes(buffer)
	return append(b, hash[:]...)
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	d.data = append(d.data, p...)
	return
}

// toBytes converts a fr Element into a BlockSize bytes array
func toBytes(e fr.Element) [BlockSize]byte {
	var res [BlockSize]byte
	binary.BigEndian.PutUint64(res[:8], e[0])
	binary.BigEndian.PutUint64(res[8:16], e[1])
	binary.BigEndian.PutUint64(res[16:24], e[2])
	binary.BigEndian.PutUint64(res[24:], e[3])
	return res
}

// fromBytes converts a fr Element into a BlockSize bytes array
func fromBytes(e [BlockSize]byte) fr.Element {
	var res fr.Element
	res[0] = binary.BigEndian.Uint64(e[:8])
	res[1] = binary.BigEndian.Uint64(e[8:16])
	res[2] = binary.BigEndian.Uint64(e[16:24])
	res[3] = binary.BigEndian.Uint64(e[24:])
	return res
}

// Hash hash using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition, data is in Montgomery form
func (d *digest) checksum() fr.Element {

	var buffer [32]byte

	// if data size is not multiple of BlockSizes we padd
	if len(d.data)%BlockSize != 0 {
		for i := 0; i < BlockSize-len(d.data)%BlockSize; i++ {
			d.data = append(d.data, 0)
		}
	}

	if len(d.data) == 0 {
		for i := 0; i < BlockSize; i++ {
			d.data = append(d.data, 0)
		}
	}

	nbChunks := len(d.data) / BlockSize

	for i := 0; i < nbChunks; i++ {
		copy(buffer[:], d.data[i*BlockSize:(i+1)*BlockSize])
		x := fromBytes(buffer)
		d.encrypt(x)
		d.h.Add(&x, &d.h)
	}

	return d.h
}

// plain execution of a mimc run
// m: message
// k: encryption key
func (d *digest) encrypt(m fr.Element) {

	for _, cons := range d.Params {
		// m = (m+k+c)^7
		var tmp fr.Element
		tmp.Add(&m, &d.h).Add(&tmp, &cons)
		m.Square(&tmp).
			Square(&m).
			Mul(&m, &tmp)
	}
	m.Add(&m, &d.h)
	d.h = m
}

// Sum computes the mimc hash of msg from seed
func Sum(seed string, msg []fr.Element) fr.Element {
	params := NewParams(seed)
	var d digest
	d.Params = params
	for _, stream := range msg {
		tmp := toBytes(stream)
		d.Write(tmp[:])
	}
	return d.checksum()
}
