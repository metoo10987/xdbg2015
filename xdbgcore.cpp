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
			MyTrace("xdbgcore initializing. mode: 1");
			if (!initializeDebugger()) {
				// log error
				assert(false);
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

BOOL(__stdcall * Real_ContinueDebugEvent)(DWORD a0,
	DWORD a1,
	DWORD a2)
	= ContinueDebugEvent;
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
	MyTrace("%s()", __FUNCTION__);
	DWORD flags = dwCreationFlags;
	if (dbgctl) {
		if (DEBUG_PROCESS & dwCreationFlags) {
			dwCreationFlags &= ~DEBUG_PROCESS;
		}

		if (DEBUG_ONLY_THIS_PROCESS & dwCreationFlags)
			dwCreationFlags &= ~DEBUG_ONLY_THIS_PROCESS;

		dwCreationFlags |= CREATE_SUSPENDED;
	}

	
	if (!Real_CreateProcessA(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (dbgctl) {
		if (injectDll(a9->dwProcessId))
			dbgctl->attach(a9->dwProcessId);

		if ((flags & CREATE_SUSPENDED) == 0) {
			if (dbgctl)
				ResumeThread(a9->hThread);
		}
	}

	return TRUE;
}

#include "detours.h"

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
	MyTrace("%s()", __FUNCTION__);
	DWORD flags = dwCreationFlags;
	if (dbgctl) {
		if (DEBUG_PROCESS & dwCreationFlags) {
			dwCreationFlags &= ~DEBUG_PROCESS;
		}

		if (DEBUG_ONLY_THIS_PROCESS & dwCreationFlags)
			dwCreationFlags &= ~DEBUG_ONLY_THIS_PROCESS;

		dwCreationFlags |= CREATE_SUSPENDED;
	}


	if (!Real_CreateProcessW(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (dbgctl) {
		if (injectDll(a9->dwProcessId))
			dbgctl->attach(a9->dwProcessId);

		if ((flags & CREATE_SUSPENDED) == 0) {
			if (dbgctl)
				ResumeThread(a9->hThread);
		}
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

BOOL(__stdcall * Real_GetThreadContext)(HANDLE a0,
	LPCONTEXT a1)
	= GetThreadContext;

BOOL(__stdcall * Real_SetThreadContext)(HANDLE a0,
	CONST CONTEXT* a1)
	= SetThreadContext;

#ifdef _DEBUG

DWORD eventSerial = 0;

void dumpDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT:
		MyTrace("DUMP[%d]: CREATE_PROCESS_DEBUG_EVENT [%d][start at %p]", lpDebugEvent->dwThreadId, 
			++ eventSerial,	lpDebugEvent->u.CreateProcessInfo.lpStartAddress);
		break;

	case EXIT_PROCESS_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXIT_PROCESS_DEBUG_EVENT [%d][exit code %d]", lpDebugEvent->dwThreadId, 
			++ eventSerial, lpDebugEvent->u.ExitProcess.dwExitCode);
		break;

	case CREATE_THREAD_DEBUG_EVENT:
		MyTrace("DUMP[%d]: CREATE_THREAD_DEBUG_EVENT [%d][start at %p]", lpDebugEvent->dwThreadId, 
			++ eventSerial, lpDebugEvent->u.CreateThread.lpStartAddress);
		break;

	case EXIT_THREAD_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXIT_THREAD_DEBUG_EVENT [%d][exit code %d]", lpDebugEvent->dwThreadId, 
			++ eventSerial, lpDebugEvent->u.ExitThread.dwExitCode);
		break;

	case LOAD_DLL_DEBUG_EVENT:
		MyTrace("DUMP[%d]: LOAD_DLL_DEBUG_EVENT [%d][base %p]", lpDebugEvent->dwThreadId, 
			++ eventSerial, lpDebugEvent->u.LoadDll.lpBaseOfDll);
		break;

	case UNLOAD_DLL_DEBUG_EVENT:
		MyTrace("DUMP[%d]: UNLOAD_DLL_DEBUG_EVENT [%d][base %p]", lpDebugEvent->dwThreadId, 
			++ eventSerial,	lpDebugEvent->u.UnloadDll.lpBaseOfDll);
		break;

	case EXCEPTION_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXCEPTION_DEBUG_EVENT [%d][code %x, address %p, firstChance: %d]", 
			lpDebugEvent->dwThreadId, ++ eventSerial, 
			lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode,
			lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress, 
			lpDebugEvent->u.Exception.dwFirstChance);
		break;

	case OUTPUT_DEBUG_STRING_EVENT:
		MyTrace("DUMP[%d]: OUTPUT_DEBUG_STRING_EVENT [%d][base %p]", lpDebugEvent->dwThreadId, 
			++ eventSerial, lpDebugEvent->u.DebugString.lpDebugStringData);
		break;

	case RIP_EVENT:
		MyTrace("DUMP[%d]: RIP_EVENT [%d][err %x]", lpDebugEvent->dwThreadId, ++ eventSerial, 
			lpDebugEvent->u.RipInfo.dwError);
		break;

	default:
		MyTrace("DUMP[%d]: UNKNOWN EVENT [%d][eventId %x]", lpDebugEvent->dwThreadId, ++ eventSerial, 
			lpDebugEvent->dwDebugEventCode);
		break;
	}
}

#endif

BOOL __stdcall Mine_WaitForDebugEvent(LPDEBUG_EVENT a0,
                                      DWORD a1)
{
	BOOL result;
	MyTrace("%s(%p, %u)", __FUNCTION__, a0, a1);
	if (dbgctl != NULL) {
		result = dbgctl->waitEvent(a0, a1) ? TRUE : FALSE;
	} else
		result = Real_WaitForDebugEvent(a0, a1);

#ifdef _DEBUG
	if (result)
		dumpDebugEvent(a0);
#endif
	return result;
}

BOOL __stdcall Mine_ContinueDebugEvent(DWORD a0,
	DWORD a1,
	DWORD a2)
{
	MyTrace("%s(%u, %u, %x)", __FUNCTION__, a0, a1, a2);
	if (dbgctl != NULL) {
		return dbgctl->continueEvent(a0, a1, a2) ? TRUE : FALSE;
	}
	else
		return Real_ContinueDebugEvent(a0, a1, a2);
}

BOOL __stdcall Mine_SetThreadContext(HANDLE a0,
	CONTEXT* a1)
{
	MyTrace("%s(%p, %p)", __FUNCTION__, a0, a1);
	if (dbgctl != NULL) {

		if (a1->ContextFlags & CONTEXT_CONTROL) {

			MyTrace("%s(): new pc: %x", __FUNCTION__, a1->Eip);
			dbgctl->setPC(a1->Eip);
			a1->Eip = dbgctl->getLastPc();
			MyTrace("%s(): modified pc: %x", __FUNCTION__, a1->Eip);
			if (a1->EFlags & SINGLE_STEP_FLAG) {
				dbgctl->setFlags(CDE_SINGLE_STEP);
				a1->EFlags &= ~SINGLE_STEP_FLAG;
				MyTrace("%s(): single trip toggled", __FUNCTION__);
			} else {
				dbgctl->setFlags(0);
				MyTrace("%s(): single trip cleared", __FUNCTION__);
			}
		}

		return Real_SetThreadContext(a0, a1);
	}
	else
		return Real_SetThreadContext(a0, a1);
}

BOOL __stdcall Mine_GetThreadContext(HANDLE a0,
	LPCONTEXT a1)
{
	// MyTrace("%s(%p, %p)", __FUNCTION__, a0, a1);
	if (dbgctl != NULL) {
		BOOL result = Real_GetThreadContext(a0, a1);
		if (!result)
			return result;
		if (a1->ContextFlags & CONTEXT_CONTROL) {
			if (dbgctl->getPC())
				a1->Eip = dbgctl->getPC();
			else if (dbgctl->getExceptPc())
				if (dbgctl->getExceptCode() == STATUS_BREAKPOINT)
					CTX_PC_REG(a1) = (DWORD)dbgctl->getExceptPc() + 1;
				else
					CTX_PC_REG(a1) = (DWORD)dbgctl->getExceptPc();

			/* if (dbgctl->getExceptCode() == STATUS_BREAKPOINT) {
				a1->Eip += 1;
			} */

			// MyTrace("%s(%p, %p). pc = %p", __FUNCTION__, a0, a1, a1->Eip);
			if (dbgctl->getFlags()) {
				a1->EFlags |= SINGLE_STEP_FLAG;
				// MyTrace("%s(%p, %p). SINGLE_STEP_FLAG was setted", __FUNCTION__, a0, a1);
			}
		}

		return result;
	}
	else
		return Real_GetThreadContext(a0, a1);
}

//////////////////////////////////////////////////////////////////////////

BOOL initializeDebugger()
{
	MyTrace("%s()", __FUNCTION__);

	if (debug_if == 0) {
		dbgctl = new XDbgController();
		if (dbgctl == NULL)
			return FALSE;
	}

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_CreateProcessA, &(PVOID&)Mine_CreateProcessA);
	DetourAttach(&(PVOID&)Real_CreateProcessW, &(PVOID&)Mine_CreateProcessW);
	DetourAttach(&(PVOID&)Real_DebugActiveProcess, &(PVOID&)Mine_DebugActiveProcess);
	DetourAttach(&(PVOID&)Real_WaitForDebugEvent, &(PVOID&)Mine_WaitForDebugEvent);
	DetourAttach(&(PVOID&)Real_ContinueDebugEvent, &(PVOID&)Mine_ContinueDebugEvent);
	DetourAttach(&(PVOID&)Real_GetThreadContext, &(PVOID&)Mine_GetThreadContext);
	DetourAttach(&(PVOID&)Real_SetThreadContext, &(PVOID&)Mine_SetThreadContext);
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
