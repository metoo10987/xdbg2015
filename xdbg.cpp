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

// XDbgController xdbg;
UINT debug_if = 0;
UINT api_hook_mask = 0;
DWORD GetProcessByName(const char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			return (pEntry.th32ProcessID);
		}

		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return 0;
}

extern BOOL(__stdcall * Real_GetThreadContext)(HANDLE a0,
	LPCONTEXT a1);

int _tmain(int argc, _TCHAR* argv[])
{
	// LoadLibrary("xdbgcore.dll");
	DWORD pid = GetProcessByName("debugee.exe");
	DebugActiveProcess(pid);
	DEBUG_EVENT dbgEvent;
	while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
		printf("dbgEvent.dwDebugEventCode£º %u\n", dbgEvent.dwDebugEventCode);
		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {

			printf("DBG: Exception: %x, Addr: %p, FirstChance: %d\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionCode,
				dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress, dbgEvent.u.Exception.dwFirstChance);

			if (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {
				ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
				//ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
				continue;
			}

			if (dbgEvent.u.Exception.dwFirstChance)
				ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
			else
				ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		} else if (dbgEvent.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
			printf("DBG: DbgStr: %p\n", dbgEvent.u.DebugString.lpDebugStringData);
		} else if (dbgEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
			printf("DBG: LoadDll: %p\n", dbgEvent.u.LoadDll.lpBaseOfDll);
		} else if (dbgEvent.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
			printf("DBG: UnloadDll: %p\n", dbgEvent.u.UnloadDll.lpBaseOfDll);
		} else {
			// printf("dbgEvent.dwDebugEventCode£º %u\n", dbgEvent.dwDebugEventCode);
			// assert(false);
			// return -1;
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}
	return 0;
}

