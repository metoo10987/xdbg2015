// xdbg.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>
#include <assert.h>
#include "XDbgController.h"
#include <stdio.h>

int _tmain(int argc, _TCHAR* argv[])
{
	XDbgController xdbg;
	xdbg.attach(0);
	DEBUG_EVENT dbgEvent;
	while (xdbg.waitEvent(&dbgEvent)) {
		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			if (dbgEvent.u.Exception.dwFirstChance)
				xdbg.continueEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
			else
				xdbg.continueEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		} else if (dbgEvent.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
			printf("DBG: DbgStr: %p\n", dbgEvent.u.DebugString.lpDebugStringData);
		} else if (dbgEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
			printf("DBG: LoadDll: %p\n", dbgEvent.u.LoadDll.lpImageName);
		} else if (dbgEvent.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
			printf("DBG: UnloadDll: %p\n", dbgEvent.u.UnloadDll.lpBaseOfDll);
		} else {
			printf("dbgEvent.dwDebugEventCode£º %u\n", dbgEvent.dwDebugEventCode);
			assert(false);
			return -1;
		}
	}
	return 0;
}

