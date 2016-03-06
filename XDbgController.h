#pragma once
class XDbgController
{
public:
	XDbgController(void);
	~XDbgController(void);

	bool attach(DWORD pid);
	bool waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds = INFINITE);
	bool continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);

	HANDLE getProcessHandle() const
	{
		return _hProcess;
	}

	PVOID getLastPc() const
	{
		return (PVOID )_lastContext.Eip;
	}

protected:

protected:
	HANDLE		_hPipe;
	HANDLE		_hProcess;
	CONTEXT		_lastContext;
};
