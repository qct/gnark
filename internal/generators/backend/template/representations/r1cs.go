package representations

const R1CS = `


import (
	"errors"
	"fmt"
	"strconv"
	"math/big"

	{{if ne .Curve "GENERIC"}}
	"github.com/consensys/gnark/backend"
	{{end}}
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils/debug"

	{{ template "import_fr" . }}
)

// R1CS decsribes a set of R1CS constraint 
type R1CS struct {
	// Wires
	NbWires        int
	NbPublicWires  int // includes ONE wire
	NbPrivateWires int
	PrivateWires   []string         // private wire names, correctly ordered (the i-th entry is the name of the (offset+)i-th wire)
	PublicWires    []string         // public wire names, correctly ordered (the i-th entry is the name of the (offset+)i-th wire)
	WireTags       map[int][]string // optional tags -- debug info

	// Constraints
	NbConstraints   int // total number of constraints
	NbCOConstraints int // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []R1C
	Coefficients 	[]fr.Element // R1C coefficients indexes point here
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CS) GetNbConstraints() int {
	return r1cs.NbConstraints
}

// Solve sets all the wires and returns the a, b, c vectors.
// the r1cs system should have been compiled before. The entries in a, b, c are in Montgomery form.
// and must be []fr.Element
// assignment: map[string]value: contains the input variables
// TODO : note that currently, there is a convertion from interface{} to fr.Element for each entry in the
// assignment map. It can cost a SetBigInt() which converts from Regular ton Montgomery rep (1 mul)
// while it's unlikely to be noticeable compared to the FFT and the MultiExp compute times,
// there should be a faster (statically typed) path for production deployments.
// a, b, c vectors: ab-c = hz
// wireValues =  [intermediateVariables | privateInputs | publicInputs]
func (r1cs *R1CS) Solve(assignment map[string]interface{}, _a, _b, _c, _wireValues interface{}) error {
	// cast our inputs
	a := _a.([]fr.Element)
	b := _b.([]fr.Element)
	c := _c.([]fr.Element)
	wireValues := _wireValues.([]fr.Element)

	// compute the wires and the a, b, c polynomials
	debug.Assert(len(a) == r1cs.NbConstraints)
	debug.Assert(len(b) == r1cs.NbConstraints)
	debug.Assert(len(c) == r1cs.NbConstraints)
	debug.Assert(len(wireValues) == r1cs.NbWires)
	
	// keep track of wire that have a value
	wireInstantiated := make([]bool, r1cs.NbWires)
	

	// instantiate the public/ private inputs
	instantiateInputs := func(offset int, inputNames []string) error {
		for i := 0; i < len(inputNames); i++ {
			name := inputNames[i]
			if name == {{if ne .Curve "GENERIC"}} backend.{{- end}}OneWire {
				wireValues[i+offset].SetOne()
				wireInstantiated[i+offset] = true
			} else {
				if val, ok := assignment[name]; ok {
					wireValues[i+offset] = fr.FromInterface(val)
					wireInstantiated[i+offset] = true
				} else {
					return fmt.Errorf("%q: %w", name, {{if ne .Curve "GENERIC"}} backend.{{- end}}ErrInputNotSet)
				}
			}
		}
		return nil
	}
	// instantiate private inputs
	debug.Assert(len(r1cs.PrivateWires) == r1cs.NbPrivateWires)
	debug.Assert(len(r1cs.PublicWires) == r1cs.NbPublicWires)
	if r1cs.NbPrivateWires != 0 {
		offset := r1cs.NbWires - r1cs.NbPublicWires - r1cs.NbPrivateWires // private input start index
		if err := instantiateInputs(offset, r1cs.PrivateWires); err != nil {
			return err
		}
	}
	// instantiate public inputs
	{
		offset := r1cs.NbWires - r1cs.NbPublicWires // public input start index
		if err := instantiateInputs(offset,  r1cs.PublicWires); err != nil {
			return err
		}
	}

	// check if there is an inconsistant constraint
	var check fr.Element

	// Loop through the other Constraints
	for i, r1c := range r1cs.Constraints {

		if i < r1cs.NbCOConstraints {
			// computationalGraph : we need to solve the constraint
			// computationalGraph[i] contains exactly one uncomputed wire (due
			// to the graph being correctly ordered), we solve it
			r1cs.Constraints[i].solveR1c(r1cs, wireInstantiated, wireValues)
		}

		// A this stage we are not guaranteed that a[i+sizecg]*b[i+sizecg]=c[i+sizecg] because we only query the values (computed
		// at the previous step)
		a[i], b[i], c[i] = r1c.instantiate(r1cs, wireValues)

		// check that the constraint is satisfied
		check.Mul(&a[i], &b[i])
		if !check.Equal(&c[i]) {
			invalidA := a[i]
			invalidB := b[i]
			invalidC := c[i]

			return fmt.Errorf("%w: %q * %q != %q", {{if ne .Curve "GENERIC"}} backend.{{- end}}ErrUnsatisfiedConstraint,
				invalidA.String(),
				invalidB.String(),
				invalidC.String())
		}
	}

	return nil
}

// Inspect returns the tagged variables with their corresponding value
// If showsInput is set, it also puts in the resulting map the inputs (public and private).
// this is temporary while we refactor map[string]interface{} and use big.Int here. 
func (r1cs *R1CS) Inspect(solution map[string]interface{}, showsInputs bool) (map[string]interface{}, error) {
	res := make(map[string]interface{})

	wireValues := make([]fr.Element, r1cs.NbWires)
	a := make([]fr.Element, r1cs.NbConstraints)
	b := make([]fr.Element, r1cs.NbConstraints)
	c := make([]fr.Element, r1cs.NbConstraints)

	err := r1cs.Solve(solution, a, b, c, wireValues)

	// showsInput is set, put the inputs in the resulting map
	if showsInputs {
		offset := r1cs.NbWires - r1cs.NbPublicWires - r1cs.NbPrivateWires // private input start index
		for i := 0; i < len(r1cs.PrivateWires); i++ {
			v := new(big.Int)
			res[r1cs.PrivateWires[i]] = *(wireValues[i+offset].ToBigIntRegular(v))
		}
		offset = r1cs.NbWires - r1cs.NbPublicWires // public input start index
		for i := 0; i < len(r1cs.PublicWires); i++ {
			v := new(big.Int)
			res[r1cs.PublicWires[i]] = *(wireValues[i+offset].ToBigIntRegular(v))
		}
	}

	// get the tagged variables
	for wireID, tags := range r1cs.WireTags {
		for _, tag := range tags {
			if _, ok := res[tag]; ok {
				return nil, errors.New("duplicate tag: " + tag)
			}
			v := new(big.Int)
			res[tag] = *(wireValues[wireID].ToBigIntRegular(v))
		}

	}

	// the error cannot be caught before because the res map needs to be filled
	if err != nil {
		return res, err
	}

	return res, nil
}

// Term lightweight version of a term, no pointers
// first 4 bits are reserved
// next 30 bits represented the coefficient idx (in r1cs.Coefficients) by which the wire is multiplied
// next 30 bits represent the constraint used to compute the wire
// if we support more than 1 billion constraints, this breaks (not so soon.)
type Term uint64

// String helper for Term
func (t Term) String() string {
	// res := ""
	// res = res + t.Coeff.String() + "*:" + strconv.Itoa(int(t.ID))
	return "unimplemented"
}

const (
	specialValueMinusOne uint64 = 0b0001
	specialValueZero  uint64 = 0b0010
	specialValueOne  uint64 = 0b0100
	specialValueTwo  uint64 = 0b1000
)

func NewTerm(constraintID, coeffID, specialValue int) Term {
	_constraintID := uint64(constraintID)
	_coeffID := uint64(coeffID)
	_coeffID <<= 34
	_coeffID >>= 4
	if (_coeffID >> 30) != uint64(coeffID) {
		panic("coeffID is > 2^30, unsupported")
	}
	if ((_constraintID << 34) >> 34) != uint64(constraintID) {
		panic("constraintID is > 2^30, unsupported")
	}
	reserved := uint64(0)
	switch specialValue {
	case -1:
		reserved = specialValueMinusOne
		reserved <<= 60
	case 0:
		reserved = specialValueZero
		reserved <<= 60
	case 1:
		reserved = specialValueOne
		reserved <<= 60
	case 2:
		reserved = specialValueTwo
		reserved <<= 60
	}

	return Term(reserved | _constraintID | _coeffID)

}

// ID returns the index of the constraint used to compute this wire 
func (t Term) ID() int {
	const mask uint64 = 0x3FFFFFFF
	return int(uint64(t) & mask)
}


func (t Term) coeffID() int {
	const mask uint64 = 0xFFFFFFFC0000000
	return int((uint64(t) & mask) >> 30)
}

// MulAdd returns accumulator += (value * term.Coefficient)
func (t Term) MulAdd(r1cs *R1CS, buffer, value, accumulator *fr.Element) {
	specialValue := uint64(t) >> 60
	if specialValue == specialValueOne {
		accumulator.Add(accumulator, value)
	} else if specialValue == specialValueMinusOne {
		accumulator.Sub(accumulator, value)
	} else if specialValue == specialValueZero {
		return
	} else if specialValue == specialValueTwo {
		buffer.Double(value)
		accumulator.Add(accumulator, buffer)
	} else {
		buffer.Mul(&r1cs.Coefficients[t.coeffID()], value)
		accumulator.Add(accumulator, buffer)
	}
}

// mulInto returns into.Mul(into, term.Coefficient)
func (t Term) mulInto(r1cs *R1CS, into *fr.Element ) *fr.Element {
	specialValue := uint64(t) >> 60
	if specialValue == specialValueOne {
		return into
	} else if specialValue == specialValueMinusOne {
		return into.Neg(into)
	} else if specialValue == specialValueZero {
		return into.SetZero()
	} else if specialValue == specialValueTwo {
		return into.Double(into)
	} else {
		return into.Mul(into, &r1cs.Coefficients[t.coeffID()])
	}
}

// LinearExpression lightweight version of linear expression
type LinearExpression []Term

// String helper for LinearExpression
func (l LinearExpression) String() string {
	res := ""
	for _, t := range l {
		res += t.String()
		res += "+ "
	}
	res = res[:len(res)-2]
	return res
}

// R1C used to compute the wires (wo pointers)
type R1C struct {
	L      LinearExpression
	R      LinearExpression
	O      LinearExpression
	Solver backend.SolvingMethod
}

// String helper for a Rank1 Constraint
func (r1c R1C) String() string {
	res := "(" + r1c.L.String() + ")*(" + r1c.R.String() + ")=" + r1c.O.String()
	return res
}

// compute left, right, o part of a r1cs constraint
// this function is called when all the wires have been computed
// it instantiates the l, r o part of a R1C
func (r1c *R1C) instantiate(r1cs *R1CS, wireValues []fr.Element) (a, b, c fr.Element) {

	var tmp fr.Element

	for _, t := range r1c.L {
		t.MulAdd(r1cs, &tmp, &wireValues[t.ID()], &a)
	}

	for _, t := range r1c.R {
		t.MulAdd(r1cs, &tmp, &wireValues[t.ID()], &b)
	}

	for _, t := range r1c.O {
		t.MulAdd(r1cs, &tmp, &wireValues[t.ID()], &c)
	}

	return
}

type location uint8 
const (
	locationUnset location = iota
	locationA
	locationB
	locationC
)

func (l location) set(nloc location) location {
	if l != locationUnset {
		panic("location was already set -- we should have only one unset wire")
	}
	return nloc
}

// solveR1c computes a wire by solving a r1cs
// the function searches for the unset wire (either the unset wire is
// alone, or it can be computed without ambiguity using the other computed wires
// , eg when doing a binary decomposition: either way the missing wire can
// be computed without ambiguity because the r1cs is correctly ordered)
func (r1c *R1C) solveR1c(r1cs *R1CS, wireInstantiated []bool, wireValues []fr.Element) {

	switch r1c.Solver {

	// in this case we solve a R1C by isolating the uncomputed wire
	case backend.SingleOutput:

		// the index of the non zero entry shows if L, R or O has an uninstantiated wire
		// the content is the ID of the wire non instantiated
		loc := locationUnset

		var tmp, a, b, c fr.Element
		var _t Term

		for _, t := range r1c.L {
			cID := t.ID()
			if wireInstantiated[cID] {
				t.MulAdd(r1cs, &tmp, &wireValues[cID], &a)
			} else {
				_t = t
				loc = loc.set(locationA)
			}
		}

		for _, t := range r1c.R {
			cID := t.ID()
			if wireInstantiated[cID] {
				t.MulAdd(r1cs, &tmp, &wireValues[cID], &b)
			} else {
				_t = t
				loc = loc.set(locationB)
			}
		}

		for _, t := range r1c.O {
			cID := t.ID()
			if wireInstantiated[cID] {
				t.MulAdd(r1cs, &tmp, &wireValues[cID], &c)
			} else {
				_t = t
				loc = loc.set(locationC)
			}
		}

		// ensure we found the unset wire
		if loc == locationUnset {
			// TODO this should panic? 
			// fmt.Println("couldn't find uncomputed wire when solving R1C")
			return
		}

		cID := _t.ID()
		wireValues[cID].SetZero()
		wireInstantiated[cID] = true

		switch loc {
		case locationA:
			if !b.IsZero() {
				wireValues[cID].Div(&c, &b).
					Sub(&wireValues[cID], &a)
				_t.mulInto(r1cs, &wireValues[cID])
			}
		case locationB:
			if !a.IsZero() {
				wireValues[cID].Div(&c, &a).
					Sub(&wireValues[cID], &b)
				_t.mulInto(r1cs, &wireValues[cID])
			}
		case locationC:
			wireValues[cID].Mul(&a, &b).
				Sub(&wireValues[cID], &c)
			_t.mulInto(r1cs, &wireValues[cID])
		}

	
	// in the case the R1C is solved by directly computing the binary decomposition
	// of the variable
	case backend.BinaryDec:

		// the binary decomposition must be called on the non Mont form of the number
		n := wireValues[r1c.O[0].ID()].ToRegular()
		nbBits := len(r1c.L)

		// binary decomposition of n
		var i, j int
		for i*64 < nbBits {
			j = 0
			for j < 64 && i*64+j < len(r1c.L) {
				ithbit := (n[i] >> uint(j)) & 1
				cID := r1c.L[i*64+j].ID()
				if !wireInstantiated[cID] {
					wireValues[cID].SetUint64(ithbit)
					wireInstantiated[cID] = true
				}
				j++
			}
			i++
		}
	default:
		panic("unimplemented solving method")
	}
}

`
