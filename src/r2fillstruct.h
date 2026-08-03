// SPDX-FileCopyrightText: 2026 Skliarenko Nikolai
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2FILLSTRUCT_H
#define R2GHIDRA_R2FILLSTRUCT_H

#include "R2Architecture.h"

#include <r_core.h>
#include <string>

// Port of Ghidra's Java FillOutStructureHelper.fillOutStructureDef: traces
// p-code data-flow from the named variable (a parameter or local of the
// currently-decompiled Funcdata), records every constant-offset LOAD/STORE
// reachable from it, synthesizes a struct declaration from the result, and
// registers + applies it in r2 (anal->sdb_types + r_anal_var_set_type).
// Returns true if a struct was created and applied.
bool FillOutStructure(RCore *core, R2Architecture &arch, ghidra::Funcdata *func, const std::string &varName, std::string &errorOut);

#endif
