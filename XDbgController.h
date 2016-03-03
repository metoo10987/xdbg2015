#pragma once
class XDbgController
{
public:
	XDbgController(void);
	~XDbgController(void);

	bool attach(DWORD pid);
	bool waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds = INFINITE);
	bool continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
protected:
	HANDLE		_hPipe;
};
