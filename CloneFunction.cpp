#include <Windows.h>
#include "CloneFunction.h"
#include <assert.h>

bool CloneFunctions(const CloneFuncDef defs[], size_t count)
{
	PVOID base = VirtualAlloc(NULL, MAX_FUNCTION_SIZE * count, MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE);
	if (base == NULL)
		return false;
	for (size_t i = 0; i < count; i++) {
		HMODULE hMod = LoadLibrary(defs[i].modName);
		if (hMod == NULL) {
			VirtualFree(base, MAX_FUNCTION_SIZE * count, MEM_RELEASE);
			assert(false);
			return false;
		}

		PVOID funcAddr = PVOID(ULONG(base) + MAX_FUNCTION_SIZE * i);
		if (!CloneFunction(hMod, defs[i].funcName, funcAddr, MAX_FUNCTION_SIZE)) {
			VirtualFree(base, MAX_FUNCTION_SIZE * count, MEM_RELEASE);
			assert(false);
			return false;
		}

		*defs[i].funcAddr = funcAddr;
	}

	return true;
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
