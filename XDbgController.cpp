#include <Windows.h>
#include <Psapi.h>
#include <assert.h>
#include "XDbgController.h"
#include "common.h"
#include "Utils.h"
#include "detours.h"
#include <vector>

extern UINT debug_if;

std::vector<AutoDebug* > autoDebugHandlers;

//////////////////////////////////////////////////////////////////////////

XDbgController::XDbgController(void)
{
	_pid = 0;
	_hPipe = INVALID_HANDLE_VALUE;
	_pending = false;
	_hProcess = NULL;
	_ContextFlags = 0;
	_hInst = 0;
	resetDbgEvent();
}

XDbgController::~XDbgController(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);
}

bool XDbgController::initialize(HMODULE hInst, bool hookApi)
{
	_hInst = hInst;
	if (hookApi)
		return hookDbgApi();
	return true;
}

bool XDbgController::attach(DWORD pid, DWORD tid)
{
	MyTrace("%s()", __FUNCTION__);

	if (_pid)
		stop(_pid);

	std::string name = makePipeName(pid);
	// WaitNamedPipe(name.c_str(), NMPWAIT_WAIT_FOREVER);
	_hPipe = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 
		0 /*FILE_FLAG_OVERLAPPED*/, NULL);

	if (_hPipe == INVALID_HANDLE_VALUE) {
		MyTrace("%s() cannot connect to '%s'", __FUNCTION__, name.c_str());
		return false;
	}

	_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (_hProcess == NULL ) {
		CloseHandle(_hPipe);
		MyTrace("%s() OpenProcess(%u)", __FUNCTION__, pid);
		return false;
	}

	DEBUG_EVENT event;
	if (!waitEvent(&event)) { // SEND FIRST MSG TO VERIFY CONNECTION
		MyTrace("%s(): connection is unavailable");
		CloseHandle(_hPipe);
		CloseHandle(_hProcess);
		assert(false);
		return false;
	}

	assert(event.dwDebugEventCode == ATTACHED_EVENT);
	continueEvent(event.dwProcessId, tid ? tid : event.dwThreadId, DBG_CONTINUE);

	_pid = pid;
	return true;
}

bool XDbgController::stop(DWORD pid)
{
	assert(_pid = pid);

	if (_hProcess == NULL)
		return false;

	if (_hProcess) {
		CloseHandle(_hProcess);
		_hProcess = NULL;
	}

	if (_hPipe) {
		CloseHandle(_hPipe);
		_hPipe = NULL;
	}

	resetDbgEvent();
	_pid = 0;

	return true;
}

bool XDbgController::waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	MyTrace("%s()", __FUNCTION__);
	
	DWORD len;

	if (!_pending) {
		// memset(&_overlap, 0, sizeof(_overlap));
		if (ReadFile(_hPipe, &_event, sizeof(_event), &len, NULL /* &_overlap */))
			_pending = false;
		else
			if (GetLastError() == ERROR_IO_PENDING)
				_pending = true;
			else {
				MyTrace("%s(): read pipe failed, pipe: %p", __FUNCTION__, _hPipe);
				_pending = false;
				return false;
			}
	}

	if (_pending) {
		DWORD waitResult = WaitForSingleObject(_hPipe, dwMilliseconds);

		if (waitResult == WAIT_FAILED) {
			_pending = false;
			return false;

		} else if (waitResult == WAIT_TIMEOUT) {

			SetLastError(ERROR_SEM_TIMEOUT);
			return false;
		} else if (waitResult == WAIT_OBJECT_0) {
			_pending = false;
		} else {
			_pending = false;
			return false;
		}
	} 

	*lpDebugEvent = _event.event;

	MyTrace("%s(): tid: %d, lastPc: %p, event_code: %x", __FUNCTION__, lpDebugEvent->dwThreadId, 
		CTX_PC_REG(&_event.ctx), lpDebugEvent->dwDebugEventCode);

	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT:
		{
			char fileName[MAX_PATH + 1];
			GetModuleFileNameEx(_hProcess, (HMODULE)lpDebugEvent->u.CreateProcessInfo.lpBaseOfImage, 
				fileName, MAX_PATH);
			lpDebugEvent->u.CreateProcessInfo.hProcess = _hProcess;
			lpDebugEvent->u.CreateProcessInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, 
				lpDebugEvent->dwThreadId);
			MyTrace("%s(): threadId: %d, threadHandle: %x", __FUNCTION__, lpDebugEvent->dwThreadId, 
				lpDebugEvent->u.CreateProcessInfo.hThread);
			assert(lpDebugEvent->u.CreateProcessInfo.hThread);
			lpDebugEvent->u.CreateProcessInfo.hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, 
				NULL, OPEN_EXISTING, 0, NULL);
			assert(lpDebugEvent->u.CreateProcessInfo.hFile != INVALID_HANDLE_VALUE);

			MyTrace("%s(): CREATE_PROCESS_DEBUG_EVENT: hFile = %x, hProcess = %x, hThread = %x", 
				__FUNCTION__, lpDebugEvent->u.CreateProcessInfo.hFile, 
				lpDebugEvent->u.CreateProcessInfo.hProcess, lpDebugEvent->u.CreateProcessInfo.hThread);
		}
		break;

	case CREATE_THREAD_DEBUG_EVENT:
		{
			lpDebugEvent->u.CreateThread.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, lpDebugEvent->dwThreadId);
			MyTrace("%s(): CREATE_THREAD_DEBUG_EVENT. hThread: %x, tid: %u", __FUNCTION__,
				lpDebugEvent->u.CreateThread.hThread, lpDebugEvent->dwThreadId);
		}
		break;

	case EXIT_THREAD_DEBUG_EVENT:
		{
			// delThread(lpDebugEvent->dwThreadId);
		}
		break;

	case LOAD_DLL_DEBUG_EVENT:
		{
			SIZE_T len;
			if (lpDebugEvent->u.LoadDll.fUnicode){
				wchar_t buf[MAX_PATH];
				if (!ReadProcessMemory(_hProcess, lpDebugEvent->u.LoadDll.lpImageName, buf, sizeof(buf), &len)) {
					assert(false);
					break;
				}

				lpDebugEvent->u.LoadDll.hFile = CreateFileW((LPCWSTR)buf, GENERIC_READ,
					FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

				MyTrace("%s(): LOAD_DLL_DEBUG_EVENT. dll: %S, hFile: %x", __FUNCTION__,
					buf, lpDebugEvent->u.LoadDll.hFile);
			}
			else {
				char buf[MAX_PATH];
				if (!ReadProcessMemory(_hProcess, lpDebugEvent->u.LoadDll.lpImageName, buf, sizeof(buf), &len)) {
					assert(false);
					break;
				}

				lpDebugEvent->u.LoadDll.hFile = CreateFileA((LPCSTR)buf, GENERIC_READ,
					FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

				MyTrace("%s(): LOAD_DLL_DEBUG_EVENT. dll: %s, hFile: %x", __FUNCTION__,
					buf, lpDebugEvent->u.LoadDll.hFile);
			}
			assert(lpDebugEvent->u.LoadDll.hFile != INVALID_HANDLE_VALUE);
		}
		break;

	case EXCEPTION_DEBUG_EVENT:
		{
			MyTrace("%s(): exception code: %p, addr: %x", __FUNCTION__, 
				lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode,
				lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

			if (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP) {
				MyTrace("STATUS_SINGLE_STEP");
			}
		}

		break;

	default:
		break;
	}

	MyTrace("DEBUG_EVENT: %u", lpDebugEvent->dwDebugEventCode);
	return true;
}

bool XDbgController::continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
	MyTrace("%s(): CONTINUE_EVENT: %x", __FUNCTION__, dwContinueStatus);
	DebugAckPacket ack;
	ack.dwProcessId = dwProcessId;
	ack.dwThreadId = dwThreadId;
	ack.dwContinueStatus = dwContinueStatus;
	ack.ctx = _event.ctx;
	ack.ContextFlags = _ContextFlags;
	DWORD len;
	if (!WriteFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		return false;
	}
	
	resetDbgEvent();
	return true;
}

//////////////////////////////////////////////////////////////////////////

BOOL(__stdcall * Real_CreateProcessA)(LPCSTR a0,
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

BOOL(__stdcall * Real_CreateProcessW)(LPCWSTR a0,
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

BOOL(__stdcall * Real_DebugActiveProcess)(DWORD a0)
= DebugActiveProcess;

BOOL(__stdcall * Real_DebugActiveProcessStop)(DWORD a0)
= DebugActiveProcessStop;

BOOL(__stdcall * Real_WaitForDebugEvent)(LPDEBUG_EVENT a0,
	DWORD a1)
	= WaitForDebugEvent;

BOOL(__stdcall * Real_ContinueDebugEvent)(DWORD a0,
	DWORD a1,
	DWORD a2)
	= ContinueDebugEvent;

BOOL(__stdcall * Real_GetThreadContext)(HANDLE a0,
	LPCONTEXT a1)
	= GetThreadContext;

BOOL(__stdcall * Real_SetThreadContext)(HANDLE a0,
	CONST CONTEXT* a1)
	= SetThreadContext;

LPVOID(__stdcall * Real_VirtualAllocEx)(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	DWORD a4)
	= VirtualAllocEx;

BOOL(__stdcall * Real_VirtualFreeEx)(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3)
	= VirtualFreeEx;

BOOL(__stdcall * Real_VirtualProtectEx)(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	PDWORD a4)
	= VirtualProtectEx;

DWORD_PTR(__stdcall * Real_VirtualQueryEx)(HANDLE a0,
	LPCVOID a1,
	PMEMORY_BASIC_INFORMATION a2,
	DWORD_PTR a3)
	= VirtualQueryEx;

BOOL(__stdcall * Real_ReadProcessMemory)(HANDLE a0,
	LPCVOID a1,
	LPVOID a2,
	DWORD_PTR a3,
	PDWORD_PTR a4)
	= ReadProcessMemory;

BOOL(__stdcall * Real_WriteProcessMemory)(HANDLE a0,
	LPVOID a1,
	LPCVOID a2,
	DWORD_PTR a3,
	PDWORD_PTR a4)
	= WriteProcessMemory;

//////////////////////////////////////////////////////////////////////////
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

	if (debug_if == 1)
		return Real_CreateProcessA(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9);

	XDbgController& dbgctl = XDbgController::instance();

	DWORD flags = dwCreationFlags;
	if (DEBUG_PROCESS & dwCreationFlags) {
		dwCreationFlags &= ~DEBUG_PROCESS;
	}

	if (DEBUG_ONLY_THIS_PROCESS & dwCreationFlags)
		dwCreationFlags &= ~DEBUG_ONLY_THIS_PROCESS;

	dwCreationFlags |= CREATE_SUSPENDED;

	if (!Real_CreateProcessA(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (injectDll(a9->dwProcessId, dbgctl.getModuleHandle())) {
		int i;
		for (i = 30; i > 0; i--) {
			if (dbgctl.attach(a9->dwProcessId, a9->dwThreadId))
				break;

			Sleep(100);
		}

		if (i == 0)
			return FALSE;
	}

	if ((flags & CREATE_SUSPENDED) == 0) {
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
	MyTrace("%s()", __FUNCTION__);
	
	if (debug_if == 1)
		return Real_CreateProcessW(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9);

	DWORD flags = dwCreationFlags;
	XDbgController& dbgctl = XDbgController::instance();

	if (DEBUG_PROCESS & dwCreationFlags) {
		dwCreationFlags &= ~DEBUG_PROCESS;
	}

	if (DEBUG_ONLY_THIS_PROCESS & dwCreationFlags)
		dwCreationFlags &= ~DEBUG_ONLY_THIS_PROCESS;

	dwCreationFlags |= CREATE_SUSPENDED;

	if (!Real_CreateProcessW(a0, a1, a2, a3, a4, dwCreationFlags, a6, a7, a8, a9)){
		return FALSE;
	}

	if (injectDll(a9->dwProcessId, dbgctl.getModuleHandle())) {
		int i;
		for (i = 30; i > 0; i--) {
			if (dbgctl.attach(a9->dwProcessId, a9->dwThreadId))
				break;

			Sleep(100);
		}

		if (i == 0)
			return FALSE;
	}

	if ((flags & CREATE_SUSPENDED) == 0) {
		ResumeThread(a9->hThread);
	}

	return TRUE;
}

BOOL __stdcall Mine_DebugActiveProcess(DWORD a0)
{
	MyTrace("%s()", __FUNCTION__);
	if (debug_if == 1)
		return Real_DebugActiveProcess(a0);

	XDbgController& dbgctl = XDbgController::instance();
	if (injectDll(a0, dbgctl.getModuleHandle()))
		return dbgctl.attach(a0, GetProcessMainThread(a0)) ? TRUE : FALSE;
	else
		return FALSE;
}

BOOL __stdcall Mine_DebugActiveProcessStop(DWORD a0)
{
	MyTrace("%s()", __FUNCTION__);
	if (debug_if == 1)
		return Real_DebugActiveProcessStop(a0);

	XDbgController& dbgctl = XDbgController::instance();
	return dbgctl.stop(a0);
}

//////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG

static DWORD eventSerial = 0;

void dumpDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT:
		MyTrace("DUMP[%d]: CREATE_PROCESS_DEBUG_EVENT [%d][start at %p]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.CreateProcessInfo.lpStartAddress);
		break;

	case EXIT_PROCESS_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXIT_PROCESS_DEBUG_EVENT [%d][exit code %d]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.ExitProcess.dwExitCode);
		break;

	case CREATE_THREAD_DEBUG_EVENT:
		MyTrace("DUMP[%d]: CREATE_THREAD_DEBUG_EVENT [%d][start at %p]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.CreateThread.lpStartAddress);
		break;

	case EXIT_THREAD_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXIT_THREAD_DEBUG_EVENT [%d][exit code %d]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.ExitThread.dwExitCode);
		break;

	case LOAD_DLL_DEBUG_EVENT:
		MyTrace("DUMP[%d]: LOAD_DLL_DEBUG_EVENT [%d][base %p]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.LoadDll.lpBaseOfDll);
		break;

	case UNLOAD_DLL_DEBUG_EVENT:
		MyTrace("DUMP[%d]: UNLOAD_DLL_DEBUG_EVENT [%d][base %p]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.UnloadDll.lpBaseOfDll);
		break;

	case EXCEPTION_DEBUG_EVENT:
		MyTrace("DUMP[%d]: EXCEPTION_DEBUG_EVENT [%d][code %x, address %p, firstChance: %d]",
			lpDebugEvent->dwThreadId, ++eventSerial,
			lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode,
			lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress,
			lpDebugEvent->u.Exception.dwFirstChance);
		break;

	case OUTPUT_DEBUG_STRING_EVENT:
		MyTrace("DUMP[%d]: OUTPUT_DEBUG_STRING_EVENT [%d][base %p]", lpDebugEvent->dwThreadId,
			++eventSerial, lpDebugEvent->u.DebugString.lpDebugStringData);
		break;

	case RIP_EVENT:
		MyTrace("DUMP[%d]: RIP_EVENT [%d][err %x]", lpDebugEvent->dwThreadId, ++eventSerial,
			lpDebugEvent->u.RipInfo.dwError);
		break;

	default:
		MyTrace("DUMP[%d]: UNKNOWN EVENT [%d][eventId %x]", lpDebugEvent->dwThreadId, ++eventSerial,
			lpDebugEvent->dwDebugEventCode);
		break;
	}
}

#endif

//////////////////////////////////////////////////////////////////////////
BOOL __stdcall Mine_ContinueDebugEvent(DWORD a0,
	DWORD a1,
	DWORD a2);

BOOL __stdcall Mine_WaitForDebugEvent(LPDEBUG_EVENT a0,
	DWORD a1)
{
	MyTrace("%s(%p, %u)", __FUNCTION__, a0, a1);

	if (debug_if == 1)
		return Real_WaitForDebugEvent(a0, a1);

	BOOL result;
	bool ignore;

	do {

		ignore = false;
		result = XDbgController::instance().waitEvent(a0, a1) ? TRUE : FALSE;

		if (result) {
#ifdef _DEBUG
			dumpDebugEvent(a0);
#endif
			std::vector<AutoDebug* >::iterator it;
			for (it = autoDebugHandlers.begin(); it != autoDebugHandlers.end(); it++) {
				DWORD continueStatus;
				if (!(*it)->peekDebugEvent(a0, &continueStatus)) {
					XDbgController::instance().continueEvent(a0->dwProcessId, a0->dwThreadId, continueStatus);
					ignore = true;
				}
			}

		} else
			break;

	} while (ignore);

	return result;
}

BOOL __stdcall Mine_ContinueDebugEvent(DWORD a0,
	DWORD a1,
	DWORD a2)
{
	MyTrace("%s(%u, %u, %x)", __FUNCTION__, a0, a1, a2);
	if (debug_if == 1)
		return Real_ContinueDebugEvent(a0, a1, a2);

	return XDbgController::instance().continueEvent(a0, a1, a2) ? TRUE : FALSE;
}

BOOL __stdcall Mine_SetThreadContext(HANDLE a0,
	CONTEXT* a1)
{
	MyTrace("%s(%p, %p)", __FUNCTION__, a0, a1);
	if (debug_if == 1)
		return Real_SetThreadContext(a0, a1);

	XDbgController& dbgctl = XDbgController::instance();
	return dbgctl.setThreadContext(a0, a1) ? TRUE: FALSE;
}

BOOL __stdcall Mine_GetThreadContext(HANDLE a0,
	LPCONTEXT a1)
{
	// MyTrace("%s(%p, %p)", __FUNCTION__, a0, a1);
	if (debug_if == 1)
		return Real_GetThreadContext(a0, a1);

	XDbgController& dbgctl = XDbgController::instance();
	if (!dbgctl.getThreadContext(a0, a1))
		return FALSE;
#if 0
	if ((dbgctl.getContextFlags() & CONTEXT_CONTROL) != CONTEXT_CONTROL) {
		if (dbgctl.getExceptCode() == STATUS_BREAKPOINT) {		
			// CTX_PC_REG(a1) = (DWORD)dbgctl.getExceptAddress() + 1;
			CTX_PC_REG(a1) = CTX_PC_REG(a1) + 1;
		} /* else {
			// CTX_PC_REG(a1) = (DWORD)dbgctl.getExceptAddress();
		} */
	}
#endif
	return TRUE;
}

bool XDbgController::hookDbgApi()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_CreateProcessA, &(PVOID&)Mine_CreateProcessA);
	DetourAttach(&(PVOID&)Real_CreateProcessW, &(PVOID&)Mine_CreateProcessW);
	DetourAttach(&(PVOID&)Real_DebugActiveProcess, &(PVOID&)Mine_DebugActiveProcess);
	DetourAttach(&(PVOID&)Real_DebugActiveProcessStop, &(PVOID&)Mine_DebugActiveProcessStop);
	DetourAttach(&(PVOID&)Real_WaitForDebugEvent, &(PVOID&)Mine_WaitForDebugEvent);
	DetourAttach(&(PVOID&)Real_ContinueDebugEvent, &(PVOID&)Mine_ContinueDebugEvent);
	DetourAttach(&(PVOID&)Real_GetThreadContext, &(PVOID&)Mine_GetThreadContext);
	DetourAttach(&(PVOID&)Real_SetThreadContext, &(PVOID&)Mine_SetThreadContext);
	return DetourTransactionCommit() == NO_ERROR;
}

bool XDbgController::setThreadContext(HANDLE hThread, const CONTEXT* ctx)
{
	DWORD currentThreadId = getEventThreadId();
	if (currentThreadId) {
		DWORD threadId = GetThreadIdFromHandle(hThread);
		if (threadId == 0) {
			assert(false);
			return Real_SetThreadContext(hThread, ctx) == TRUE;
		}

		if (threadId == currentThreadId && getEventCode() == EXCEPTION_DEBUG_EVENT) {
			_ContextFlags |= ctx->ContextFlags;
			cloneThreadContext(&_event.ctx, ctx, ctx->ContextFlags);
			return true;
		}
	}

	// THIS IS A BUG IN X64DBG, FIX IT AT HERE.
	if (getEventCode() == 0 && (ctx->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		if (ctx->EFlags & SINGLE_STEP_FLAG)
			*(PDWORD)&ctx->EFlags &= ~SINGLE_STEP_FLAG;
	}

	return Real_SetThreadContext(hThread, ctx) == TRUE;
}

bool XDbgController::getThreadContext(HANDLE hThread, CONTEXT* ctx)
{
	DWORD currentThreadId = getEventThreadId();
	if (currentThreadId) {

		DWORD threadId = GetThreadIdFromHandle(hThread);
		if (threadId == 0) {
			assert(false);
			return Real_GetThreadContext(hThread, ctx) == TRUE;
		}

		if (threadId == currentThreadId && getEventCode() == EXCEPTION_DEBUG_EVENT) {
			cloneThreadContext(ctx, &_event.ctx, ctx->ContextFlags);

			if ((getContextFlags() & CONTEXT_CONTROL) != CONTEXT_CONTROL) {
				if (getExceptCode() == STATUS_BREAKPOINT) {
					CTX_PC_REG(ctx) = CTX_PC_REG(ctx) + 1;
				}
			}

			return true;
		}

	}

	return Real_GetThreadContext(hThread, ctx) == TRUE;
}

void registerAutoDebugHandler(AutoDebug* handler)
{
	autoDebugHandlers.push_back(handler);
}

//////////////////////////////////////////////////////////////////////////

void* XDbgController::allocMemroy(size_t size, DWORD allocType, DWORD protect)
{
	return NULL;
}

bool XDbgController::freeMemory(LPVOID lpAddress, size_t dwSize, DWORD  dwFreeType)
{
	return NULL;
}

bool XDbgController::setMemoryProtection(LPVOID lpAddress, size_t dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	return NULL;
}

size_t XDbgController::queryMemory(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, size_t dwLength)
{
	return NULL;
}

bool XDbgController::readMemory(LPCVOID lpBaseAddress, PVOID lpBuffer, size_t nSize, size_t * lpNumberOfBytesRead)
{
	return NULL;
}

bool XDbgController::writeMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, size_t nSize, size_t * lpNumberOfBytesWritten)
{
	return NULL;
}

LPVOID __stdcall Mine_VirtualAllocEx(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	DWORD a4)
{
	return NULL;
}

BOOL __stdcall Mine_VirtualFreeEx(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3)
{
	return NULL;
}

BOOL __stdcall Mine_VirtualProtectEx(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	PDWORD a4)
{

	return NULL;
}

DWORD_PTR __stdcall Mine_VirtualQueryEx(HANDLE a0,
	LPCVOID a1,
	PMEMORY_BASIC_INFORMATION a2,
	DWORD_PTR a3)
{
	return NULL;
}

BOOL __stdcall Mine_ReadProcessMemory(HANDLE a0,
	LPCVOID a1,
	LPVOID a2,
	DWORD_PTR a3,
	PDWORD_PTR a4)
{
	return NULL;
}

BOOL __stdcall Mine_WriteProcessMemory(HANDLE a0,
	LPVOID a1,
	LPVOID a2,
	DWORD_PTR a3,
	PDWORD_PTR a4)
{
	return NULL;
}
