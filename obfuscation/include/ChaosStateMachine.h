/*
 *  OLLVM-Next (Ensia): The next generation LLVM based Obfuscator
 *  Copyright (C) 2026  Xinyu Yang(<Xinyu.Yang@apich.org>)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _CHAOS_STATE_MACHINE_H_
#define _CHAOS_STATE_MACHINE_H_

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include <cstdint>

namespace llvm {

// ChaosStateMachine: a control-flow flattening pass driven by a
// Q16 fixed-point logistic map (x_{n+1} = r*x*(1-x), r≈3.9999).
//
// Key innovations over classic CFF:
//   1. State transitions are quadratic in the IR (mul, sub, lshr chain)
//      — Binja MLIL/SSA cannot reduce these to constants without symbolic exec.
//   2. Each block-exit stores logistic_next(current_state) XOR correction,
//      where correction = logistic_next(case_i) XOR case_j (compile-time).
//      Correctness: (logistic_next(case_i) XOR correction) == case_j ✓
//   3. Case values are drawn from the chaotic attractor of the logistic map,
//      appearing as a pseudorandom permutation of [0, 65535].
//   4. A second entropy layer: case values are additionally scrambled with
//      a per-function Feistel round, doubling the apparent randomness.
//
// Annotation: add __attribute__((annotate("csm"))) to enable per-function.
FunctionPass *createChaosStateMachinePass(bool flag);
void initializeChaosStateMachinePass(PassRegistry &Registry);

// Logistic-map step in Q16 fixed-point (compile-time helper).
// Returns next chaos value in [0, 65535]. Safe: avoids fixed points.
uint32_t chaosMapStep(uint32_t x);

} // namespace llvm

#endif // _CHAOS_STATE_MACHINE_H_
