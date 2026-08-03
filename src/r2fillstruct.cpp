// SPDX-FileCopyrightText: 2026 Skliarenko Nikolai
// SPDX-License-Identifier: LGPL-3.0-only

#include "r2fillstruct.h"
#include "R2TypeFactory.h"

#include <funcdata.hh>
#include <fspec.hh>
#include <database.hh>

#include <map>
#include <vector>
#include <list>
#include <sstream>

// Native C++ port of Ghidra's Java FillOutStructureHelper.fillOutStructureDef
// (Ghidra/Features/Decompiler/.../util/FillOutStructureHelper.java). Ghidra's
// version writes into its own Java-side DataTypeManager; here the equivalent
// sink is r2's type DB (anal->sdb_types) plus r_anal_var_set_type, since
// R2Architecture is rebuilt fresh on every decompile (nothing native persists
// across pdg invocations) -- see plan notes on why there's no point building
// a throwaway native TypeStruct first.

namespace {

struct PointerRef {
	Varnode *varnode;
	int8 offset;
};

// Reject offsets that are clearly not real struct fields, same bound Java
// uses (0x1000) to keep runaway/garbage offsets from producing huge structs.
static bool SanityCheckOffset(int8 offset, int8 existingSize) {
	if (offset < 0) {
		return false;
	}
	if (offset < existingSize) {
		return true;
	}
	return offset <= 0x1000;
}

// Fallback when Ghidra hasn't inferred any type for a LOAD/STORE'd value
// (matches Java's tolerance of a null datatype in componentMap.addDataType --
// it still reserves the offset/size even without a real type).
static std::string SizeToTypeString(int4 size) {
	switch (size) {
	case 1: return "uint8_t";
	case 2: return "uint16_t";
	case 4: return "uint32_t";
	case 8: return "uint64_t";
	default: return "";
	}
}

// Resolve the named r2-side variable to its live Varnode in this Funcdata.
// Params and locals are both reachable this way; params are checked first
// since FuncProto's parameter list is the more precise source for them.
static Varnode *FindNamedVarnode(Funcdata *func, const std::string &name) {
	FuncProto &proto = func->getFuncProto ();
	for (int4 i = 0; i < proto.numParams (); i++) {
		ProtoParameter *p = proto.getParam (i);
		if (p && p->getName () == name) {
			Varnode *vn = func->findVarnodeInput (p->getSize (), p->getAddress ());
			if (vn) {
				return vn;
			}
		}
	}
	ScopeLocal *scope = func->getScopeLocal ();
	if (!scope) {
		return nullptr;
	}
	for (MapIterator it = scope->begin (); it != scope->end (); ++it) {
		const SymbolEntry *entry = *it;
		if (!entry || entry->isPiece ()) {
			continue;
		}
		Symbol *sym = entry->getSymbol ();
		if (sym && sym->getName () == name) {
			Varnode *vn = func->findLinkedVarnode (const_cast<SymbolEntry *>(entry));
			if (vn) {
				return vn;
			}
		}
	}
	return nullptr;
}

// Direct port of FillOutStructureHelper.fillOutStructureDef's worklist walk:
// starting from the root variable's SSA instances, follow constant-offset
// pointer arithmetic (INT_ADD/INT_SUB/PTRADD/PTRSUB) and offset-preserving
// ops (CAST/COPY/MULTIEQUAL/SEGMENTOP), recording every LOAD/STORE reached
// along the way as a (offset -> type) component. CALL/CALLIND-following
// (Java's optional pushIntoCalls, capped at one level) is out of scope for
// this port -- see plan.
static void FillOutStructureDef(HighVariable *var, std::map<int8, Datatype *> &components,
		std::map<int8, int4> &sizes, int8 &maxOffset) {
	std::vector<PointerRef> todo;
	std::set<Varnode *> done;

	Varnode *startVn = var->getInstance (0);
	todo.push_back ({ startVn, 0 });
	done.insert (startVn);
	for (int4 i = 0; i < var->numInstances (); i++) {
		Varnode *vn = var->getInstance (i);
		if (done.insert (vn).second) {
			todo.push_back ({ vn, 0 });
		}
	}

	auto pushOnList = [&](Varnode *out, int8 offset) {
		if (!out || !done.insert (out).second) {
			return;
		}
		todo.push_back ({ out, offset });
	};

	while (!todo.empty ()) {
		PointerRef cur = todo.front ();
		todo.erase (todo.begin ());
		if (!cur.varnode) {
			continue;
		}
		for (auto dit = cur.varnode->beginDescend (); dit != cur.varnode->endDescend (); ++dit) {
			PcodeOp *op = *dit;
			Varnode *out = op->getOut ();
			switch (op->code ()) {
			case CPUI_INT_ADD:
			case CPUI_INT_SUB:
				{
					if (op->numInput () < 2 || !op->getIn (1)->isConstant ()) {
						break;
					}
					int8 value = (int8)sign_extend (op->getIn (1)->getOffset (), op->getIn (1)->getSize (), sizeof (uintb));
					int8 newOff = cur.offset + (op->code () == CPUI_INT_ADD ? value : -value);
					if (SanityCheckOffset (newOff, maxOffset)) {
						pushOnList (out, newOff);
						maxOffset = std::max (maxOffset, newOff);
					}
				}
				break;
			case CPUI_PTRADD:
				{
					if (op->numInput () < 3 || !op->getIn (1)->isConstant () || !op->getIn (2)->isConstant ()) {
						break;
					}
					int8 value = (int8)sign_extend (op->getIn (1)->getOffset (), op->getIn (1)->getSize (), sizeof (uintb));
					int8 newOff = cur.offset + value * (int8)op->getIn (2)->getOffset ();
					if (SanityCheckOffset (newOff, maxOffset)) {
						pushOnList (out, newOff);
						maxOffset = std::max (maxOffset, newOff);
					}
				}
				break;
			case CPUI_PTRSUB:
				{
					if (op->numInput () < 2 || !op->getIn (1)->isConstant ()) {
						break;
					}
					int8 value = (int8)sign_extend (op->getIn (1)->getOffset (), op->getIn (1)->getSize (), sizeof (uintb));
					int8 newOff = cur.offset + value;
					if (SanityCheckOffset (newOff, maxOffset)) {
						pushOnList (out, newOff);
						maxOffset = std::max (maxOffset, newOff);
					}
				}
				break;
			case CPUI_SEGMENTOP:
			case CPUI_CAST:
			case CPUI_MULTIEQUAL:
			case CPUI_COPY:
				pushOnList (out, cur.offset);
				break;
			case CPUI_LOAD:
				{
					Datatype *dt = out ? out->getHighTypeDefFacing () : nullptr;
					components[cur.offset] = dt;
					sizes[cur.offset] = out ? out->getSize () : 0;
					maxOffset = std::max (maxOffset, cur.offset + (out ? (int8)out->getSize () : 0));
				}
				break;
			case CPUI_STORE:
				{
					if (op->getSlot (cur.varnode) != 1 || op->numInput () < 3) {
						break;
					}
					Varnode *val = op->getIn (2);
					Datatype *dt = val ? val->getHighTypeReadFacing (op) : nullptr;
					components[cur.offset] = dt;
					sizes[cur.offset] = val ? val->getSize () : 0;
					maxOffset = std::max (maxOffset, cur.offset + (val ? (int8)val->getSize () : 0));
				}
				break;
			// CPUI_CALL / CPUI_CALLIND: intentionally not followed (v1 scope, see plan)
			default:
				break;
			}
		}
	}
}

} // namespace

bool FillOutStructure(RCore *core, R2Architecture &arch, Funcdata *func, const std::string &varName, std::string &errorOut) {
	Varnode *rootVn = FindNamedVarnode (func, varName);
	if (!rootVn) {
		errorOut = "no variable named '" + varName + "' in the decompiled function";
		return false;
	}
	HighVariable *high = rootVn->getHigh ();
	if (!high) {
		errorOut = "'" + varName + "' has no merged SSA variable";
		return false;
	}

	std::map<int8, Datatype *> components;
	std::map<int8, int4> sizes;
	int8 maxOffset = 0;
	FillOutStructureDef (high, components, sizes, maxOffset);

	if (components.empty ()) {
		errorOut = "no field accesses found through '" + varName + "'";
		return false;
	}

	// Find a free "astructN" name in r2's type DB, matching Java's
	// createUniqueStructure's auto-naming (astruct1, astruct2, ...).
	std::string structName;
	for (int4 n = 1; ; n++) {
		std::string candidate = "astruct" + std::to_string (n);
		if (r_type_kind (core->anal->sdb_types, candidate.c_str ()) == R_TYPE_INVALID) {
			structName = candidate;
			break;
		}
	}

	std::stringstream decl;
	decl << "struct " << structName << " {";
	for (const auto &kv : components) {
		int8 offset = kv.first;
		std::string typeStr = R2TypeFactory::toCString (kv.second);
		int4 size = sizes[offset];
		if (typeStr.empty ()) {
			typeStr = SizeToTypeString (size);
		}
		if (typeStr.empty ()) {
			continue; // no usable type/size for this field; skip rather than emit a bad decl
		}
		decl << typeStr << " field_0x" << std::hex << offset << std::dec << "; ";
	}
	decl << "};";

	char *cerr = nullptr;
	if (!r_anal_import_c_decls (core->anal, decl.str ().c_str (), &cerr)) {
		errorOut = "failed to register struct: " + std::string (cerr ? cerr : "unknown error");
		free (cerr);
		return false;
	}
	free (cerr);

	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	RAnalVar *var = fcn ? r_anal_function_get_var_byname (fcn, varName.c_str ()) : nullptr;
	if (!var) {
		errorOut = "struct '" + structName + "' registered, but no matching r2 variable '" + varName + "' to retype";
		return false;
	}
	std::string ptrType = "struct " + structName + " *";
	r_anal_var_set_type (core->anal, var, ptrType.c_str ());
	return true;
}
