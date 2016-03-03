// xdbg.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <Windows.h>
#include <assert.h>
#include "XDbgController.h"

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
		} else {
			assert(false);
			return -1;
		}
	}
	return 0;
}

