#include <Windows.h>
#include <Psapi.h>
#include <assert.h>
#include "XDbgController.h"
#include "common.h"

XDbgController::XDbgController(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
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
	_hPipe = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (_hPipe == NULL) {
		MyTrace("%s() cannot connect to '%s'", __FUNCTION__, name.c_str());
		return false;
	}

	_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (_hProcess == NULL ){
		MyTrace("%s() OpenProcess(%u)", __FUNCTION__, pid);
		return false;
	}

	return true;
}

bool XDbgController::waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	MyTrace("%s()", __FUNCTION__);
	assert(dwMilliseconds == INFINITE); // no timeout
	DWORD len;
	if (!ReadFile(_hPipe, lpDebugEvent, sizeof(*lpDebugEvent), &len, NULL)) {
		MyTrace("%s(): read pipe failed, pipe: %p", __FUNCTION__, _hPipe);
		return false;
	}

	if (lpDebugEvent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
		char fileName[MAX_PATH + 1];
		GetModuleFileNameEx(_hProcess, (HMODULE )lpDebugEvent->u.CreateProcessInfo.lpBaseOfImage, fileName, MAX_PATH);
		lpDebugEvent->u.CreateProcessInfo.hProcess = _hProcess;
		lpDebugEvent->u.CreateProcessInfo.hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		MyTrace("CREATE_PROCESS_DEBUG_EVENT: hFile = %x, hProcess = %x", lpDebugEvent->u.CreateProcessInfo.hFile, 
			lpDebugEvent->u.CreateProcessInfo.hProcess);
	}

	MyTrace("DEBUG_EVENT: %u", lpDebugEvent->dwDebugEventCode);
	return true;
}

bool XDbgController::continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
	MyTrace("%s(): CONTINUE_EVENT: %u", __FUNCTION__, dwContinueStatus);
	CONTINUE_DEBUG_EVENT ack;
	ack.dwProcessId = dwProcessId;
	ack.dwThreadId = dwThreadId;
	ack.dwContinueStatus = dwContinueStatus;
	DWORD len;
	if (!WriteFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		return false;
	}

	return true;
}
