// xdbg.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>
#include <assert.h>
#include "XDbgController.h"
#include <stdio.h>
#include <Psapi.h>
#include <tlhelp32.h>

XDbgController xdbg;

void attachProcessByName(const char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			xdbg.attach(pEntry.th32ProcessID);
			break;
		}

		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

int _tmain(int argc, _TCHAR* argv[])
{
	attachProcessByName("debugee.exe");
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
			printf("DBG: LoadDll: %p\n", dbgEvent.u.LoadDll.lpBaseOfDll);
		} else if (dbgEvent.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
			printf("DBG: UnloadDll: %p\n", dbgEvent.u.UnloadDll.lpBaseOfDll);
		} else {
			printf("dbgEvent.dwDebugEventCode£º %u\n", dbgEvent.dwDebugEventCode);
			// assert(false);
			// return -1;
		}

		xdbg.continueEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dbgEvent.dwDebugEventCode);
	}
	return 0;
}

