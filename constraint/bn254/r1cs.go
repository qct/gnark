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

package cs

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/consensys/gnark/constraint/lazy"
	"github.com/fxamacker/cbor/v2"
	"io"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/backend/ioutils"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile"

	"github.com/consensys/gnark-crypto/ecc"
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// R1CS describes a set of R1CS constraint
type R1CS struct {
	constraint.R1CSCore
	CoeffTable
	arithEngine
}

var GKRWitnessGeneratorHandler func(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int) (values []fr.Element, startLength, endLength int)

func RegisterGKRWitnessGeneratorHandler(f func(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int) (values []fr.Element, startLength, endLength int)) {
	GKRWitnessGeneratorHandler = f
}

// NewR1CS returns a new R1CS and sets cs.Coefficient (fr.Element) from provided big.Int values
//
// capacity pre-allocates memory for capacity nbConstraints
func NewR1CS(capacity int) *R1CS {
	r := R1CS{
		R1CSCore: constraint.R1CSCore{
			System:            constraint.NewSystem(fr.Modulus()),
			Constraints:       make([]constraint.R1C, 0, capacity),
			LazyCons:          make([]constraint.LazyInputs, 0),
			LazyConsMap:       make(map[int]constraint.LazyIndexedInputs),
			StaticConstraints: make(map[string]constraint.StaticConstraints),
		},
		CoeffTable: newCoeffTable(capacity / 10),
	}
	return &r
}

func (cs *R1CS) AddConstraint(r1c constraint.R1C, debugInfo ...constraint.DebugInfo) int {
	profile.RecordConstraint()
	cs.Constraints = append(cs.Constraints, r1c)
	cID := len(cs.Constraints) - 1
	if len(debugInfo) == 1 {
		cs.DebugInfo = append(cs.DebugInfo, constraint.LogEntry(debugInfo[0]))
		cs.MDebug[cID] = len(cs.DebugInfo) - 1
	}

	cs.UpdateLevel(cID, &r1c)

	return cID
}

func (cs *R1CS) AddStaticConstraints(key string, constraintPos int, finished bool, expressions []constraint.LinearExpression) {
	nbVariables := cs.GetNbSecretVariables() + cs.GetNbPublicVariables() + cs.GetNbInternalVariables()
	// only the first static r1cs need to record static r1cs
	if c, exists := cs.StaticConstraints[key]; !exists || c.StaticR1CS == nil {
		// first time enter without any static constraint recorded
		if !finished {
			cs.StaticConstraints[key] = constraint.StaticConstraints{StaticR1CS: nil, Begin: constraintPos, InputLinearExpressions: &expressions}
		} else {
			// for the first one counting the input threshold
			inputConstraintsThreshold := constraint.ComputeInputConstraintsThreshold(cs.Constraints[cs.StaticConstraints[key].Begin:constraintPos], cs.StaticConstraints[key].InputLinearExpressions)
			cs.StaticConstraints[key] = constraint.StaticConstraints{StaticR1CS: cs.Constraints[cs.StaticConstraints[key].Begin:constraintPos], Begin: c.Begin, End: constraintPos, InputConstraintsThreshold: inputConstraintsThreshold, NbVariables: nbVariables}
		}
	}

	// first time enter, we need to record this lazy inputs
	if finished {
		count := len(cs.StaticConstraints[key].StaticR1CS)
		inputConstraintCount := cs.StaticConstraints[key].InputConstraintsThreshold
		// constraintPos - count is the start constraint of the inputs
		inputConstraints := cs.Constraints[constraintPos-count : constraintPos-count+inputConstraintCount]
		shift := nbVariables - cs.StaticConstraints[key].NbVariables
		input := constraint.NewLazyInputs(key, inputConstraints, constraintPos-count, count, len(expressions), shift)
		cs.LazyCons = append(cs.LazyCons, input)
	}
}

func (cs *R1CS) GetStaticConstraints(key string) constraint.StaticConstraints {
	return cs.StaticConstraints[key]
}

func (cs *R1CS) FinalizeGKR() {
	// adding constraint for gkr inputs / gkr outputs
	one := cs.One()
	for i := range cs.GKRMeta.MIMCHints {
		h := *cs.MHints[cs.GKRMeta.MIMCHints[i]]

		hInputVids := h.Inputs
		hOutputVid := constraint.LinearExpression{cs.MakeTerm(&one, h.Wires[0])}
		cstone := constraint.LinearExpression{cs.MakeTerm(&one, 0)}
		// 1 << bN is the total hashes size and shift of two inputs
		shift := 1 << cs.GKRMeta.GKRBN
		li0 := cs.GKRMeta.GKRInputTables[i]
		li1 := cs.GKRMeta.GKRInputTables[i+shift]
		// input constraint
		cs.AddConstraint(constraint.R1C{L: cstone, R: hInputVids[0].Clone(), O: li0.Clone()})
		cs.AddConstraint(constraint.R1C{L: cstone, R: hInputVids[1].Clone(), O: li1.Clone()})

		// we need to contraints from inputs to outpus
		for shiftI := 1; shiftI < 7; shiftI++ {
			li2l := cs.GKRMeta.GKRInputTables[i+2*shiftI*shift]
			lo2 := cs.GKRMeta.GKROutputTables[i+(shiftI-1)*shift]
			cs.AddConstraint(constraint.R1C{L: cstone, R: lo2.Clone(), O: li2l.Clone()})

			li2r := cs.GKRMeta.GKRInputTables[i+2*shiftI*shift+shift]
			cs.AddConstraint(constraint.R1C{L: cstone, R: li1.Clone(), O: li2r.Clone()})
		}

		lo := cs.GKRMeta.GKROutputTables[i+shift*6]
		// output constraint
		cs.AddConstraint(constraint.R1C{L: cstone, R: hOutputVid.Clone(), O: lo.Clone()})
	}
}

func (cs *R1CS) Lazify() map[int]int {
	// already lazify
	if len(cs.LazyConsMap) != 0 {
		return nil
	}

	// remove cons generated from Lazy
	mapFromFull := make(map[int]int)
	lastEnd := 0
	offset := 0
	bar := len(cs.Constraints) - cs.LazyCons.GetConstraintsAll()
	ret := make([]constraint.R1C, 0)

	lazyR1CIdx := 0
	for lazyIndex, con := range cs.LazyCons {
		start := con.GetLoc()
		end := con.GetLoc() + con.GetConstraintsNum()
		if start > lastEnd {
			ret = append(ret, cs.Constraints[lastEnd:start]...)
		}

		// map [lastend, start)
		for j := lastEnd; j < start; j++ {
			mapFromFull[j] = j - offset
		}
		lastEnd = end
		// map [start, end)
		for j := start; j < end; j++ {
			mapFromFull[j] = bar + offset + (j - start)
		}

		// record the index to cons
		for i := 0; i < con.GetConstraintsNum(); i++ {
			cs.LazyConsMap[bar+lazyR1CIdx] = constraint.LazyIndexedInputs{Index: i, LazyIndex: lazyIndex}
			lazyR1CIdx++
		}

		offset += con.GetConstraintsNum()
	}
	if lastEnd < len(cs.Constraints) {
		ret = append(ret, cs.Constraints[lastEnd:]...)
	}
	// map [end, endCons)
	nbCons := len(cs.Constraints)
	for j := lastEnd; j < nbCons; j++ {
		/// mapFromFull[j+offset] = j
		mapFromFull[j] = j - offset
	}
	cs.Constraints = ret

	badCnt := 0
	for i, row := range cs.Levels {
		for j, val := range row {

			if v, ok := mapFromFull[val]; ok {
				cs.Levels[i][j] = v
			} else {
				badCnt++
				panic(fmt.Sprintf("bad map loc at %d, %d", i, j))
			}
		}
	}

	return mapFromFull
}

// Solve sets all the wires and returns the a, b, c vectors.
// the cs system should have been compiled before. The entries in a, b, c are in Montgomery form.
// a, b, c vectors: ab-c = hz
// witness = [publicWires | secretWires] (without the ONE_WIRE !)
// returns  [publicWires | secretWires | internalWires ]
func (cs *R1CS) Solve(witness, a, b, c fr.Vector, opt backend.ProverConfig) (fr.Vector, error) {
	log := logger.Logger().With().Int("nbConstraints", len(cs.Constraints)).Str("backend", "groth16").Logger()

	nbWires := len(cs.Public) + len(cs.Secret) + cs.NbInternalVariables
	solution, err := newSolution(nbWires, opt.HintFunctions, cs.MHintsDependencies, cs.MHints, cs.Coefficients, &cs.System.SymbolTable, cs.GKRMeta.MIMCHints)
	if err != nil {
		return make(fr.Vector, nbWires), err
	}
	start := time.Now()

	if len(witness) != len(cs.Public)-1+len(cs.Secret) { // - 1 for ONE_WIRE
		err = fmt.Errorf("invalid witness size, got %d, expected %d = %d (public) + %d (secret)", len(witness), int(len(cs.Public)-1+len(cs.Secret)), len(cs.Public)-1, len(cs.Secret))
		log.Err(err).Send()
		return solution.values, err
	}

	// compute the wires and the a, b, c polynomials
	if len(a) != cs.GetNbConstraints() || len(b) != cs.GetNbConstraints() || len(c) != cs.GetNbConstraints() {
		err = errors.New("invalid input size: len(a, b, c) == len(Constraints)")
		log.Err(err).Send()
		return solution.values, err
	}

	solution.solved[0] = true // ONE_WIRE
	solution.values[0].SetOne()
	copy(solution.values[1:], witness)
	for i := range witness {
		solution.solved[i+1] = true
	}

	solution.InitialValuesLength = len(witness) + 1
	// keep track of the number of wire instantiations we do, for a sanity check to ensure
	// we instantiated all wires
	solution.nbSolved += uint64(len(witness) + 1)

	// now that we know all inputs are set, defer log printing once all solution.values are computed
	// (or sooner, if a constraint is not satisfied)
	defer solution.printLogs(opt.CircuitLogger, cs.Logs)

	if err := cs.parallelSolve(a, b, c, &solution); err != nil {
		if unsatisfiedErr, ok := err.(*UnsatisfiedConstraintError); ok {
			log.Err(errors.New("unsatisfied constraint")).Int("id", unsatisfiedErr.CID).Send()
		} else {
			log.Err(err).Send()
		}
		return solution.values, err
	}

	// sanity check; ensure all wires are marked as "instantiated"
	if !solution.isValid() {
		log.Err(errors.New("solver didn't instantiate all wires")).Send()
		panic("solver didn't instantiate all wires")
	}

	log.Debug().Dur("took", time.Since(start)).Msg("constraint system solver done")

	return solution.values, nil
}

func (cs *R1CS) parallelSolve(a, b, c fr.Vector, solution *solution) error {
	// minWorkPerCPU is the minimum target number of constraint a task should hold
	// in other words, if a level has less than minWorkPerCPU, it will not be parallelized and executed
	// sequentially without sync.
	const minWorkPerCPU = 50.0

	// cs.Levels has a list of levels, where all constraints in a level l(n) are independent
	// and may only have dependencies on previous levels
	// for each constraint
	// we are guaranteed that each R1C contains at most one unsolved wire
	// first we solve the unsolved wire (if any)
	// then we check that the constraint is valid
	// if a[i] * b[i] != c[i]; it means the constraint is not satisfied

	var wg sync.WaitGroup
	chTasks := make(chan []int, runtime.NumCPU())
	chError := make(chan *UnsatisfiedConstraintError, runtime.NumCPU())

	// start a worker pool
	// each worker wait on chTasks
	// a task is a slice of constraint indexes to be solved
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for t := range chTasks {
				for _, i := range t {
					if err := cs.solveConstraint(cs.GetConstraintToSolve(i), solution, &a[i], &b[i], &c[i]); err != nil {
						var debugInfo *string
						if dID, ok := cs.MDebug[i]; ok {
							debugInfo = new(string)
							*debugInfo = solution.logValue(cs.DebugInfo[dID])
						}
						chError <- &UnsatisfiedConstraintError{CID: i, Err: err, DebugInfo: debugInfo}
						wg.Done()
						return
					}
				}
				wg.Done()
			}
		}()
	}

	// clean up pool go routines
	defer func() {
		close(chTasks)
		close(chError)
	}()

	// for each level, we push the tasks
	for i, level := range cs.Levels {

		if i == cs.GKRMeta.GKRConstraintsLvl {
			cs.assignGKRProofs(solution)
		}

		// max CPU to use
		maxCPU := float64(len(level)) / minWorkPerCPU

		if maxCPU <= 1.0 {
			// we do it sequentially
			for _, i := range level {
				if err := cs.solveConstraint(cs.GetConstraintToSolve(i), solution, &a[i], &b[i], &c[i]); err != nil {
					var debugInfo *string
					if dID, ok := cs.MDebug[i]; ok {
						debugInfo = new(string)
						*debugInfo = solution.logValue(cs.DebugInfo[dID])
					}
					return &UnsatisfiedConstraintError{CID: i, Err: err, DebugInfo: debugInfo}
				}
			}
			continue
		}

		// number of tasks for this level is set to num cpus
		// but if we don't have enough work for all our CPUS, it can be lower.
		nbTasks := runtime.NumCPU()
		maxTasks := int(math.Ceil(maxCPU))
		if nbTasks > maxTasks {
			nbTasks = maxTasks
		}
		nbIterationsPerCpus := len(level) / nbTasks

		// more CPUs than tasks: a CPU will work on exactly one iteration
		// note: this depends on minWorkPerCPU constant
		if nbIterationsPerCpus < 1 {
			nbIterationsPerCpus = 1
			nbTasks = len(level)
		}

		extraTasks := len(level) - (nbTasks * nbIterationsPerCpus)
		extraTasksOffset := 0

		for i := 0; i < nbTasks; i++ {
			wg.Add(1)
			_start := i*nbIterationsPerCpus + extraTasksOffset
			_end := _start + nbIterationsPerCpus
			if extraTasks > 0 {
				_end++
				extraTasks--
				extraTasksOffset++
			}
			// since we're never pushing more than num CPU tasks
			// we will never be blocked here
			chTasks <- level[_start:_end]
		}

		// wait for the level to be done
		wg.Wait()

		if len(chError) > 0 {
			return <-chError
		}
	}

	return nil
}

func (cs *R1CS) assignGKRProofs(s *solution) {

	// only works fo mimc hints
	if len(s.MIMCHintsInputs) == 0 {
		return
	}
	var bN = cs.GKRMeta.GKRBN
	var shift = 1 << bN
	var batchSize = 13
	// Creates the assignments values
	inputs := make([][]fr.Element, 1)
	inputs[0] = make([]fr.Element, 2*(1<<bN))
	inputsCovered := 0 // inputs
	for i := range s.MIMCHintsInputs {
		inputs[0][inputsCovered].SetBigInt(s.MIMCHintsInputs[i][0])
		inputs[0][inputsCovered+shift].SetBigInt(s.MIMCHintsInputs[i][1])
		inputsCovered++
	}
	values, startLen, endLen := GKRWitnessGeneratorHandler(cs.CurveID(), inputs, bN, batchSize, s.InitialValuesLength)
	copy(s.values[startLen:endLen], values)
	// from here we are using gkr inputs
	// inputs, batchSize, bN, initial_length
	// returns fr.Elements, start_length
}

// IsSolved returns nil if given witness solves the R1CS and error otherwise
// this method wraps cs.Solve() and allocates cs.Solve() inputs
func (cs *R1CS) IsSolved(witness witness.Witness, opts ...backend.ProverOption) error {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return err
	}

	a := make(fr.Vector, cs.GetNbConstraints())
	b := make(fr.Vector, cs.GetNbConstraints())
	c := make(fr.Vector, cs.GetNbConstraints())
	v := witness.Vector().(fr.Vector)
	_, err = cs.Solve(v, a, b, c, opt)
	return err
}

// divByCoeff sets res = res / t.Coeff
func (cs *R1CS) divByCoeff(res *fr.Element, t constraint.Term) {
	cID := t.CoeffID()
	switch cID {
	case constraint.CoeffIdOne:
		return
	case constraint.CoeffIdMinusOne:
		res.Neg(res)
	case constraint.CoeffIdZero:
		panic("division by 0")
	default:
		// this is slow, but shouldn't happen as divByCoeff is called to
		// remove the coeff of an unsolved wire
		// but unsolved wires are (in gnark frontend) systematically set with a coeff == 1 or -1
		res.Div(res, &cs.Coefficients[cID])
	}
}

// solveConstraint compute unsolved wires in the constraint, if any and set the solution accordingly
//
// returns an error if the solver called a hint function that errored
// returns false, nil if there was no wire to solve
// returns true, nil if exactly one wire was solved. In that case, it is redundant to check that
// the constraint is satisfied later.
func (cs *R1CS) solveConstraint(r constraint.R1C, solution *solution, a, b, c *fr.Element) error {

	// the index of the non-zero entry shows if L, R or O has an uninstantiated wire
	// the content is the ID of the wire non instantiated
	var loc uint8

	var termToCompute constraint.Term

	processLExp := func(l constraint.LinearExpression, val *fr.Element, locValue uint8) error {
		for _, t := range l {
			vID := t.WireID()

			// wire is already computed, we just accumulate in val
			if solution.solved[vID] {
				solution.accumulateInto(t, val)
				continue
			}

			// first we check if this is a hint wire
			if hint, ok := cs.MHints[vID]; ok {
				if err := solution.solveWithHint(vID, hint); err != nil {
					return err
				}
				// now that the wire is saved, accumulate it into a, b or c
				solution.accumulateInto(t, val)
				continue
			}

			if loc != 0 {
				panic("found more than one wire to instantiate")
			}
			termToCompute = t
			loc = locValue
		}
		return nil
	}

	if err := processLExp(r.L, a, 1); err != nil {
		return err
	}

	if err := processLExp(r.R, b, 2); err != nil {
		return err
	}

	if err := processLExp(r.O, c, 3); err != nil {
		return err
	}

	if loc == 0 {
		// there is nothing to solve, may happen if we have an assertion
		// (ie a constraints that doesn't yield any output)
		// or if we solved the unsolved wires with hint functions
		var check fr.Element
		if !check.Mul(a, b).Equal(c) {
			return fmt.Errorf("%s ⋅ %s != %s", a.String(), b.String(), c.String())
		}
		return nil
	}

	// we compute the wire value and instantiate it
	wID := termToCompute.WireID()

	// solver result
	var wire fr.Element

	switch loc {
	case 1:
		if !b.IsZero() {
			wire.Div(c, b).
				Sub(&wire, a)
			a.Add(a, &wire)
		} else {
			// we didn't actually ensure that a * b == c
			var check fr.Element
			if !check.Mul(a, b).Equal(c) {
				return fmt.Errorf("%s ⋅ %s != %s", a.String(), b.String(), c.String())
			}
		}
	case 2:
		if !a.IsZero() {
			wire.Div(c, a).
				Sub(&wire, b)
			b.Add(b, &wire)
		} else {
			var check fr.Element
			if !check.Mul(a, b).Equal(c) {
				return fmt.Errorf("%s ⋅ %s != %s", a.String(), b.String(), c.String())
			}
		}
	case 3:
		wire.Mul(a, b).
			Sub(&wire, c)

		c.Add(c, &wire)
	}

	// wire is the term (coeff * value)
	// but in the solution we want to store the value only
	// note that in gnark frontend, coeff here is always 1 or -1
	cs.divByCoeff(&wire, termToCompute)
	solution.set(wID, wire)

	return nil
}

func (cs *R1CS) GetConstraintToSolve(i int) constraint.R1C {
	// constraint to solve could be lazy constraint or normal constraint
	var constraintToSolve constraint.R1C
	// for each constraint in the task, solve it.
	if lazyCons, exists := cs.LazyConsMap[i]; exists {
		lazyConstraint := cs.LazyCons[lazyCons.LazyIndex]
		constraintToSolve = lazyConstraint.FetchLazy(cs, lazyCons.Index)
	} else {
		constraintToSolve = cs.Constraints[i]
	}
	return constraintToSolve
}

// GetConstraints return the list of R1C and a coefficient resolver
func (cs *R1CS) GetConstraints() ([]constraint.R1C, constraint.Resolver) {
	return cs.Constraints, cs
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (cs *R1CS) GetNbCoefficients() int {
	return len(cs.Coefficients)
}

// CurveID returns curve ID as defined in gnark-crypto
func (cs *R1CS) CurveID() ecc.ID {
	return ecc.BN254
}

// add cbor tags to clarify lazy poseidon inputs
func (cs *R1CS) inputsCBORTags() (cbor.TagSet, error) {
	defTagOpts := cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired}
	tags := cbor.NewTagSet()
	if err := tags.Add(defTagOpts, reflect.TypeOf(lazy.GeneralLazyInputs{}), 25448); err != nil {
		return nil, fmt.Errorf("new LE tag: %w", err)
	}
	return tags, nil
}

// WriteTo encodes R1CS into provided io.Writer using cbor
func (cs *R1CS) WriteTo(w io.Writer) (int64, error) {
	tags, err := cs.inputsCBORTags()
	_w := ioutils.WriterCounter{W: w} // wraps writer to count the bytes written
	enc, err := cbor.CoreDetEncOptions().EncModeWithTags(tags)
	if err != nil {
		return 0, err
	}
	encoder := enc.NewEncoder(&_w)

	// encode our object
	err = encoder.Encode(cs)
	return _w.N, err
}

// ReadFrom attempts to decode R1CS from io.Reader using cbor
func (cs *R1CS) ReadFrom(r io.Reader) (int64, error) {
	tags, err := cs.inputsCBORTags()
	dm, err := cbor.DecOptions{
		MaxArrayElements: 268435456,
		MaxMapPairs:      268435456,
	}.DecModeWithTags(tags)

	if err != nil {
		return 0, err
	}
	decoder := dm.NewDecoder(r)

	// initialize coeff table
	cs.CoeffTable = newCoeffTable(0)

	if err := decoder.Decode(&cs); err != nil {
		return int64(decoder.NumBytesRead()), err
	}

	if err := cs.CheckSerializationHeader(); err != nil {
		return int64(decoder.NumBytesRead()), err
	}

	return int64(decoder.NumBytesRead()), nil
}

func (cs *R1CS) SplitDump(session string, batchSize int) error {

	// E part
	{
		cs2 := &R1CS{}
		cs2.CoeffTable = cs.CoeffTable
		cs2.R1CSCore.System = cs.R1CSCore.System
		cs2.R1CSCore.LazyCons = cs.R1CSCore.LazyCons
		cs2.R1CSCore.LazyConsMap = cs.R1CSCore.LazyConsMap
		cs2.R1CSCore.StaticConstraints = cs.R1CSCore.StaticConstraints

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cs2.WriteTo(csFile)
	}

	N := len(cs.R1CSCore.Constraints)
	for i := 0; i < N; {
		// dump R1C[i, min(i+batchSize, end)]
		cs2 := &R1CS{}
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		cs2.R1CSCore.Constraints = cs.R1CSCore.Constraints[i:iNew]
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cs2.WriteTo(csFile)

		i = iNew
	}

	return nil
}

func (cs *R1CS) SplitDumpBinary(session string, batchSize int) error {
	// E part
	{
		cs2 := &R1CS{}
		cs2.CoeffTable = cs.CoeffTable
		cs2.R1CSCore.System = cs.R1CSCore.System
		cs2.R1CSCore.LazyCons = cs.R1CSCore.LazyCons
		cs2.R1CSCore.LazyConsMap = cs.R1CSCore.LazyConsMap
		cs2.R1CSCore.StaticConstraints = cs.R1CSCore.StaticConstraints

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cs2.WriteTo(csFile)
	}

	N := len(cs.R1CSCore.Constraints)
	for i := 0; i < N; {
		// dump R1C[i, min(i+batchSize, end)]
		cs2 := &R1CS{}
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		cs2.R1CSCore.Constraints = cs.R1CSCore.Constraints[i:iNew]
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		writer := bufio.NewWriter(csFile)
		enc := gob.NewEncoder(writer)
		err = enc.Encode(cs2)
		if err != nil {
			panic(err)
		}

		i = iNew
	}

	return nil
}

func (cs *R1CS) LoadFromSplitConcurrent(session string, N, batchSize, NCore int) {
	cs.R1CSCore.Constraints = make([]constraint.R1C, N)

	var wg sync.WaitGroup
	chTasks := make(chan int, NCore)
	// worker pool
	for core := 0; core < NCore; core++ {
		go func() {
			for i := range chTasks {
				if i < 0 {
					// E part
					cs2 := &R1CS{}

					name := fmt.Sprintf("%s.r1cs.E.save", session)
					csFile, err := os.Open(name)
					if err != nil {
						panic(err)
					}
					_, err = cs2.ReadFrom(csFile)

					cs.CoeffTable = cs2.CoeffTable
					cs.R1CSCore.System = cs2.R1CSCore.System
					cs.R1CSCore.LazyCons = cs2.R1CSCore.LazyCons
					cs.R1CSCore.LazyConsMap = cs2.R1CSCore.LazyConsMap
					cs.R1CSCore.StaticConstraints = cs2.R1CSCore.StaticConstraints

					wg.Done()
				} else {
					cs2 := &R1CS{}
					iNew := i + batchSize
					if iNew > N {
						iNew = N
					}
					name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
					csFile, err := os.Open(name)
					if err != nil {
						panic(err)
					}
					cs2.ReadFrom(csFile)
					copy(cs.R1CSCore.Constraints[i:iNew], cs2.R1CSCore.Constraints)

					wg.Done()
				}
			}
		}()
	}

	defer func() {
		close(chTasks)
	}()

	wg.Add(1)
	chTasks <- -1
	for i := 0; i < N; {
		// read R1C[i, min(i+batchSize, end)]
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		wg.Add(1)
		chTasks <- i

		i = iNew
	}
	wg.Wait()
}

func (cs *R1CS) LoadFromSplitBinaryConcurrent(session string, N, batchSize, NCore int) {
	cs.R1CSCore.Constraints = make([]constraint.R1C, N)

	var wg sync.WaitGroup
	chTasks := make(chan int, NCore)
	// worker pool
	for core := 0; core < NCore; core++ {
		go func() {
			for i := range chTasks {
				if i < 0 {
					// E part
					cs2 := &R1CS{}

					name := fmt.Sprintf("%s.r1cs.E.save", session)
					csFile, err := os.Open(name)
					if err != nil {
						panic(err)
					}
					_, err = cs2.ReadFrom(csFile)

					cs.CoeffTable = cs2.CoeffTable
					cs.R1CSCore.System = cs2.R1CSCore.System
					cs.R1CSCore.LazyCons = cs2.R1CSCore.LazyCons
					cs.R1CSCore.LazyConsMap = cs2.R1CSCore.LazyConsMap
					cs.R1CSCore.StaticConstraints = cs2.R1CSCore.StaticConstraints

					wg.Done()
				} else {
					cs2 := &R1CS{}
					iNew := i + batchSize
					if iNew > N {
						iNew = N
					}
					name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
					csFile, err := os.Open(name)
					if err != nil {
						panic(err)
					}
					writer := bufio.NewReader(csFile)
					enc := gob.NewDecoder(writer)
					err = enc.Decode(cs2)
					copy(cs.R1CSCore.Constraints[i:iNew], cs2.R1CSCore.Constraints)

					wg.Done()
				}
			}
		}()
	}

	defer func() {
		close(chTasks)
	}()

	wg.Add(1)
	chTasks <- -1
	for i := 0; i < N; {
		// read R1C[i, min(i+batchSize, end)]
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		wg.Add(1)
		chTasks <- i

		i = iNew
	}
	wg.Wait()
}
