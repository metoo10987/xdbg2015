#include <Windows.h>
#include <Psapi.h>
#include <assert.h>
#include "XDbgController.h"
#include "common.h"

XDbgController::XDbgController(void) : _lastContext(_event.ctx)
{
	_hPipe = INVALID_HANDLE_VALUE;
	// _hEvent = NULL;
	_pending = false;
	_pc = 0;
	_mask = 0;
	_eflags = 0;
	_exceptAddr = 0;
	_exceptCode = 0;
	_hProcess = NULL;
	memset(&_lastContext, 0, sizeof(_lastContext));
}

XDbgController::~XDbgController(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);
	/* if (_hEvent)
		CloseHandle(_hEvent); */
}

bool XDbgController::attach(DWORD pid)
{
	MyTrace("%s()", __FUNCTION__);
	std::string name = makePipeName(pid);
	// WaitNamedPipe(name.c_str(), NMPWAIT_WAIT_FOREVER);
	_hPipe = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 
		FILE_FLAG_OVERLAPPED, NULL);

	if (_hPipe == INVALID_HANDLE_VALUE) {
		MyTrace("%s() cannot connect to '%s'", __FUNCTION__, name.c_str());
		return false;
	}

	/* _hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (_hEvent == NULL) {
		MyTrace("%s() cannot create event", __FUNCTION__);
		return false;
	} */

	_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (_hProcess == NULL ){
		MyTrace("%s() OpenProcess(%u)", __FUNCTION__, pid);
		return false;
	}

	DEBUG_EVENT event;
	if (!waitEvent(&event))  {
		assert(false);
		return false;
	}

	assert(event.dwDebugEventCode == ATTACHED_EVENT);
	continueEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
	return true;
}

bool XDbgController::stop(DWORD pid)
{
	if (_hProcess == NULL)
		return false;

	CloseHandle(_hProcess);
	_hProcess = NULL;
	CloseHandle(_hPipe);
	_hPipe = NULL;
	// CloseHandle(_hEvent);
	// _hEvent = NULL;
	memset(&_lastContext, 0, sizeof(_lastContext));
	return true;
}

extern BOOL(__stdcall * Real_GetThreadContext)(HANDLE a0,
	LPCONTEXT a1);

#ifdef _M_X64
void XDbgController::cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags)
{
	// NO IMPLEMENTATION
	assert(false);
}

#else
void XDbgController::cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags)
{
	// no extended registers && floating point registers

	if ((ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		/* EBP, EIP and EFLAGS */
		dest->Ebp = src->Ebp;
		dest->Eip = src->Eip;
		dest->EFlags = src->EFlags;
		dest->SegCs = src->SegCs;
		dest->SegSs = src->SegSs;
		dest->Esp = src->Esp;
	}

	if ((ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
		dest->SegGs = src->SegGs;
		dest->SegFs = src->SegFs;
		dest->SegEs = src->SegEs;
		dest->SegDs = src->SegDs;
	}

	if ((ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
		dest->Eax = src->Eax;
		dest->Ebx = src->Ebx;
		dest->Ecx = src->Ecx;
		dest->Edx = src->Edx;
		dest->Esi = src->Esi;
		dest->Edi = src->Edi;
	}

	if ((ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
		dest->Dr0 = src->Dr0;
		dest->Dr1 = src->Dr1;
		dest->Dr2 = src->Dr2;
		dest->Dr3 = src->Dr3;
		dest->Dr6 = src->Dr6;
		dest->Dr7 = src->Dr7;
	}
}
#endif

void XDbgController::setThreadContext(HANDLE hThread, const CONTEXT* ctx)
{
	cloneThreadContext(&_lastContext, ctx, ctx->ContextFlags);
}

void XDbgController::getThreadContext(HANDLE hThread, CONTEXT* ctx)
{
	cloneThreadContext(ctx, &_lastContext, ctx->ContextFlags);
}

bool XDbgController::waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	MyTrace("%s()", __FUNCTION__);
	// assert(dwMilliseconds == INFINITE); // no timeout
#if 0
	if (dwMilliseconds != INFINITE) {

		// NO IMPL
		/* if (WaitForSingleObject(_hPipe, dwMilliseconds) != WAIT_OBJECT_0)
			return false; */
		assert(false);
		return false;
	}
#endif
	
	DWORD len;

	if (!_pending) {
		memset(&_overlap, 0, sizeof(_overlap));
		if (ReadFile(_hPipe, &_event, sizeof(_event), &len, &_overlap))
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

	// overlap.hEvent = _hEvent;
	
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

		/* DWORD numread;
		if (!GetOverlappedResult(_hPipe, &_overlap, &numread, FALSE)) {
			assert(false);
			return false;
		} */

		
	} 

	*lpDebugEvent = _event.event;
	_lastContext = _event.ctx;
	// FIXME:
	/*
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, lpDebugEvent->dwThreadId);
	assert(hThread);
	// SuspendThread(hThread);
	_lastContext.ContextFlags = CONTEXT_CONTROL;
	if (!Real_GetThreadContext(hThread, &_lastContext)) {
		assert(false);
	}
	// ResumeThread(hThread);
	CloseHandle(hThread);	
	*/

	MyTrace("%s(): tid: %d, lastPc: %p, event_code: %x", __FUNCTION__, lpDebugEvent->dwThreadId, 
		_lastContext.Eip, lpDebugEvent->dwDebugEventCode);

	_pc = 0;
	_mask = 0;
	_eflags = 0;
	_exceptAddr = 0;
	_exceptCode = 0;

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
			_exceptAddr = (ULONG )lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
			_exceptCode = (ULONG)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
			MyTrace("%s(): exception code: %p, addr: %x", __FUNCTION__, lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode,
				_exceptAddr);

			/* if (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
				_exceptAddr += 1;
			*/
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
	CONTINUE_DEBUG_EVENT ack;
	ack.dwProcessId = dwProcessId;
	ack.dwThreadId = dwThreadId;
	ack.dwContinueStatus = dwContinueStatus;
	ack.mask = _mask;
	ack.newpc = _pc;
	ack.eflags = _eflags;
	copyDbgRegs(ack.dbgRegs, _dbgRegs);
	DWORD len;
	if (!WriteFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		return false;
	}

	_mask = 0;
	_pc = 0;
	_eflags = 0;
	_exceptAddr = 0;
	_exceptCode = 0;

	return true;
}
