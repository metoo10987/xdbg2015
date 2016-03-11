#pragma once

#include "common.h"
#include "ThreadMgr.h"

class XDbgController // : public ThreadMgr
{
public:
	static XDbgController& instance()
	{
		static XDbgController inst;
		return inst;
	}

	bool initialize(HMODULE hInst, bool hookDbgApi);
	bool attach(DWORD pid);
	bool stop(DWORD pid);
	bool waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds = INFINITE);
	bool continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);

	HANDLE getProcessHandle() const
	{
		return _hProcess;
	}

	bool setThreadContext(HANDLE hThread, const CONTEXT* ctx);
	bool getThreadContext(HANDLE hThread, CONTEXT* ctx);

	DWORD getExceptCode() const
	{
		if (_event.event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			return _event.event.u.Exception.ExceptionRecord.ExceptionCode;
		}

		return 0;
	}

	ULONG getExceptAddress() const
	{
		if (_event.event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			return (ULONG )_event.event.u.Exception.ExceptionRecord.ExceptionAddress;
		}

		return 0;
	}

	HMODULE getModuleHandle() const
	{
		return _hInst;
	}

	DWORD getContextFlags() const
	{
		return _ContextFlags;
	}

protected:
	void resetDbgEvent()
	{
		memset(&_event, 0, sizeof(_event));
		_ContextFlags = 0;
	}

	bool hookDbgApi();
private:
	XDbgController(void);
	~XDbgController(void);

protected:
	HANDLE				_hPipe;
	OVERLAPPED			_overlap;
	bool				_pending;
	HANDLE				_hProcess;
	DebugEventPacket	_event;
	HMODULE				_hInst;
	DWORD				_ContextFlags;
};
