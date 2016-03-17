#pragma once

struct CloneFuncDef {
	const char*		modName;
	const char*		funcName;
	void**			funcAddr;
	size_t			funcSize;
};

bool CloneFunction(HMODULE hMod, const char* funcName, void* funcAddr, size_t size);
PVOID CloneFunctions(const CloneFuncDef defs[], size_t count, size_t* funcsSize);
