#include <Windows.h>
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
	std::string name = makePipeName(pid);
	_hPipe = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (_hPipe == NULL) {
		return false;
	}

	return true;
}

bool XDbgController::waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	assert(dwMilliseconds == INFINITE); // no timeout
	DWORD len;
	if (!ReadFile(_hPipe, lpDebugEvent, sizeof(*lpDebugEvent), &len, NULL)) {
		return false;
	}

	return true;
}

bool XDbgController::continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
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
