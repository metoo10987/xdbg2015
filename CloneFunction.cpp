#include <Windows.h>
#include "CloneFunction.h"
#include <assert.h>

PVOID CloneFunctions(const CloneFuncDef defs[], size_t count, size_t* funcsSize)
{
	size_t memSize = 0;
	for (size_t i = 0; i < count; i++) {
		memSize += defs[i].funcSize;
	}

	PVOID base = VirtualAlloc(NULL, memSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (base == NULL)
		return false;
	char* pos = (char *)base;
	for (size_t i = 0; i < count; i++) {
		HMODULE hMod = LoadLibrary(defs[i].modName);
		if (hMod == NULL) {
			VirtualFree(base, 0, MEM_RELEASE);
			assert(false);
			return NULL;
		}

		PVOID funcAddr = pos;
		if (!CloneFunction(hMod, defs[i].funcName, funcAddr, defs[i].funcSize)) {
			VirtualFree(base, 0, MEM_RELEASE);
			assert(false);
			return NULL;
		}

		*defs[i].funcAddr = funcAddr;
		pos += defs[i].funcSize;
	}

	if (funcsSize)
		*funcsSize = memSize;
	return base;
}

bool CloneFunction(HMODULE hMod, const char* funcName, void* funcAddr, size_t size)
{
	FARPROC fn = GetProcAddress(hMod, funcName);
	if (fn == NULL) {
		assert(false);
		return false;
	}

	memcpy(funcAddr, fn, size);
	return true;
}
