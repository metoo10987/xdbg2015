#pragma once

#define MAX_FUNCTION_SIZE		64

struct CloneFuncDef {
	const char*		modName;
	const char*		funcName;
	void**			funcAddr;
};

bool CloneFunction(HMODULE hMod, const char* funcName, void* funcAddr, size_t size);
bool CloneFunctions(const CloneFuncDef defs[], size_t count);
