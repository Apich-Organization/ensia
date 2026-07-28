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

#include "llvm/Pass.h"
#include <cstdint>

namespace llvm {

FunctionPass *createChaosStateMachinePass(bool flag);
void initializeChaosStateMachinePass(PassRegistry &Registry);

// Logistic-map step in Q16 fixed-point (compile-time helper).
// Returns next chaos value in [0, 65535]. Safe: avoids fixed points.
uint32_t chaosMapStep(uint32_t x);

} // namespace llvm

#endif // _CHAOS_STATE_MACHINE_H_
