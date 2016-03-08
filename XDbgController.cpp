#include <Windows.h>
#include <Psapi.h>
#include <assert.h>
#include "XDbgController.h"
#include "common.h"

XDbgController::XDbgController(void) : _lastContext(_event.ctx)
{
	_hPipe = INVALID_HANDLE_VALUE;
	_pc = 0;
	_flags = 0;
	_exceptAddr = 0;
	_exceptCode = 0;
	_hProcess = NULL;
	memset(&_lastContext, 0, sizeof(_lastContext));
}


XDbgController::~XDbgController(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);

}

bool XDbgController::attach(DWORD pid)
{
	MyTrace("%s()", __FUNCTION__);
	std::string name = makePipeName(pid);
	// WaitNamedPipe(name.c_str(), NMPWAIT_WAIT_FOREVER);
	_hPipe = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (_hPipe == INVALID_HANDLE_VALUE) {
		MyTrace("%s() cannot connect to '%s'", __FUNCTION__, name.c_str());
		return false;
	}

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

extern BOOL(__stdcall * Real_GetThreadContext)(HANDLE a0,
	LPCONTEXT a1);

bool XDbgController::waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	MyTrace("%s()", __FUNCTION__);
	assert(dwMilliseconds == INFINITE); // no timeout
	DWORD len;
	if (!ReadFile(_hPipe, &_event, sizeof(_event), &len, NULL)) {
		MyTrace("%s(): read pipe failed, pipe: %p", __FUNCTION__, _hPipe);
		return false;
	}

	*lpDebugEvent = _event.event;
	// _lastContext = _event.ctx;
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, lpDebugEvent->dwThreadId);
	assert(hThread);
	// SuspendThread(hThread);
	_lastContext.ContextFlags = CONTEXT_CONTROL;
	if (!Real_GetThreadContext(hThread, &_lastContext)) {
		assert(false);
	}
	// ResumeThread(hThread);
	CloseHandle(hThread);
	
	MyTrace("%s(): tid: %d, lastPc: %p, event_code: %x", __FUNCTION__, lpDebugEvent->dwThreadId, 
		_lastContext.Eip, lpDebugEvent->dwDebugEventCode);

	_pc = 0;
	_flags = 0;
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
	ack.newpc = _pc;
	ack.flags = _flags;
	DWORD len;
	if (!WriteFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		return false;
	}

	_pc = 0;
	_flags = 0;
	_exceptAddr = 0;
	_exceptCode = 0;

	return true;
}
