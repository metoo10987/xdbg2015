// xdbgcore.cpp : Defines the exported functions for the DLL application.
//

#include <Windows.h>
#include "XDbgProxy.h"
#include <assert.h>
#include "detours.h"
#include "XDbgController.h"
#include "common.h"

HANDLE hInstance;
UINT mode = 0;
UINT debug_if = 0;

XDbgController* dbgctl = NULL;

BOOL initializeDebugger();
BOOL injectDll(DWORD pid);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		
		hInstance = hModule;

		char iniName[MAX_PATH];
		GetModuleFileName(NULL, iniName, sizeof(iniName) - 1);
		strcat_s(iniName, ".ini");
		mode = GetPrivateProfileInt("xdbg", "mode", 0, iniName);
		debug_if = GetPrivateProfileInt("xdbg", "debug_if", 0, iniName);

		if (mode == 0) { // proxy mode

			MyTrace("xdbgcore initializing. mode: 0");
			if (!XDbgProxy::instance().initialize()) {
				// log error
				assert(false);
			}

		} else if (mode == 1) {
			if (debug_if == 0) { // usermode debug enginue

				MyTrace("xdbgcore initializing. mode: 1");
				if (!initializeDebugger()) {
					// log error
					assert(false);
				}
			}
		}
	}
	
	if (mode == 0) {

		return XDbgProxy::instance().DllMain(hModule, reason, lpReserved);
	}

	return TRUE;
}

BOOL (__stdcall * Real_CreateProcessA)(LPCSTR a0,
                                       LPSTR a1,
                                       LPSECURITY_ATTRIBUTES a2,
                                       LPSECURITY_ATTRIBUTES a3,
                                       BOOL a4,
                                       DWORD a5,
                                       LPVOID a6,
                                       LPCSTR a7,
                                       LPSTARTUPINFOA a8,
                                       LPPROCESS_INFORMATION a9)
    = CreateProcessA;

BOOL (__stdcall * Real_CreateProcessW)(LPCWSTR a0,
                                       LPWSTR a1,
                                       LPSECURITY_ATTRIBUTES a2,
                                       LPSECURITY_ATTRIBUTES a3,
                                       BOOL a4,
                                       DWORD a5,
                                       LPVOID a6,
                                       LPCWSTR a7,
                                       LPSTARTUPINFOW a8,
                                       LPPROCESS_INFORMATION a9)
    = CreateProcessW;

BOOL (__stdcall * Real_DebugActiveProcess)(DWORD a0)
    = DebugActiveProcess;

BOOL (__stdcall * Real_WaitForDebugEvent)(LPDEBUG_EVENT a0,
                                          DWORD a1)
    = WaitForDebugEvent;

////////////////////////////////////////////////////////////////////////////////

BOOL __stdcall Mine_CreateProcessA(LPCSTR a0,
                                   LPSTR a1,
                                   LPSECURITY_ATTRIBUTES a2,
                                   LPSECURITY_ATTRIBUTES a3,
                                   BOOL a4,
                                   DWORD dwCreationFlags,
                                   LPVOID a6,
                                   LPCSTR a7,
                                   LPSTARTUPINFOA a8,
                                   LPPROCESS_INFORMATION a9)
{
	MyTrace("%s", __FUNCTION__);
	DWORD flags = dwCreationFlags;
	if (DEBUG_PROCESS & dwCreationFlags) {
		dwCreationFlags &= ~DEBUG_PROCESS;
	}

	dwCreationFlags |= CREATE_SUSPENDED;
	if (!Real_CreateProcessA(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (dbgctl) {
		if (injectDll(a9->dwProcessId))
			dbgctl->attach(a9->dwProcessId);
	}

	if ((dwCreationFlags & CREATE_SUSPENDED) == 0) {
		ResumeThread(a9->hThread);
	}

	return TRUE;
}

BOOL __stdcall Mine_CreateProcessW(LPCWSTR a0,
                                   LPWSTR a1,
                                   LPSECURITY_ATTRIBUTES a2,
                                   LPSECURITY_ATTRIBUTES a3,
                                   BOOL a4,
                                   DWORD dwCreationFlags,
                                   LPVOID a6,
                                   LPCWSTR a7,
                                   LPSTARTUPINFOW a8,
                                   LPPROCESS_INFORMATION a9)
{
	MyTrace("%s", __FUNCTION__);
	DWORD flags = dwCreationFlags;
	if (DEBUG_PROCESS & dwCreationFlags) {
		dwCreationFlags &= ~DEBUG_PROCESS;
	}

	dwCreationFlags |= CREATE_SUSPENDED;
	if (!Real_CreateProcessW(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (dbgctl) {
		if (injectDll(a9->dwProcessId))
			dbgctl->attach(a9->dwProcessId);
	}

	if ((dwCreationFlags & CREATE_SUSPENDED) == 0) {
		ResumeThread(a9->hThread);
	}

	return TRUE;
}

BOOL __stdcall Mine_DebugActiveProcess(DWORD a0)
{
	MyTrace("%s()", __FUNCTION__);
	if (dbgctl != NULL) {
		if (injectDll(a0))
			return dbgctl->attach(a0) ? TRUE : FALSE;
		else
			return FALSE;
	} else {
		return Real_DebugActiveProcess(a0);
	}
}

BOOL __stdcall Mine_WaitForDebugEvent(LPDEBUG_EVENT a0,
                                      DWORD a1)
{
	MyTrace("%s()", __FUNCTION__);
	if (dbgctl != NULL) {
		return dbgctl->waitEvent(a0, a1) ? TRUE: FALSE;
	} else
		return Real_WaitForDebugEvent(a0, a1);
}

BOOL initializeDebugger()
{
	MyTrace("%s()", __FUNCTION__);
	dbgctl = new XDbgController();
	if (dbgctl == NULL)
		return FALSE;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_CreateProcessA, &(PVOID&)Mine_CreateProcessA);
	DetourAttach(&(PVOID&)Real_CreateProcessW, &(PVOID&)Mine_CreateProcessW);
	DetourAttach(&(PVOID&)Real_DebugActiveProcess, &(PVOID&)Mine_DebugActiveProcess);
	DetourAttach(&(PVOID&)Real_WaitForDebugEvent, &(PVOID&)Mine_WaitForDebugEvent);
	return DetourTransactionCommit() == NO_ERROR;
}

bool LoadRemoteDll(DWORD pid, const char* dllPath)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProc == NULL)
		return false;

	PVOID p = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	DWORD l;
	BOOL r = WriteProcessMemory(hProc, p, dllPath, strlen(dllPath) + 1, &l);

	if (!r) {

		VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, 
		(LPTHREAD_START_ROUTINE )GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA"), 
		p, 0, &l);

	VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);

	if (hThread == NULL) {

		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &l);
	CloseHandle(hThread);
	return l != 0;
}

BOOL injectDll(DWORD pid)
{
	char dllPath[MAX_PATH];
	GetModuleFileName((HMODULE )hInstance, dllPath, sizeof(dllPath) - 1);
	if (!LoadRemoteDll(pid, dllPath)) {
		MyTrace("injectDll(%u) failed", pid);
		return FALSE;		
	}

	return TRUE;
}
