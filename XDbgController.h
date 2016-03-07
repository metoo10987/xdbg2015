#pragma once

#include "common.h"

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

	ULONG getExceptPc() const
	{
		return _exceptAddr;
	}

	ULONG getLastPc() const
	{
		return _lastContext.Eip;
	}

	void setPC(ULONG pc)
	{
		_pc = pc;
	}
	
	ULONG getPC() const
	{
		return _pc;
	}

	void setFlags(ULONG flags)
	{
		_flags = flags;
	}

	ULONG getFlags() const
	{
		return _flags;
	}

protected:

protected:
	HANDLE		_hPipe;
	HANDLE		_hProcess;
	ULONG		_exceptAddr;
	CONTEXT&	_lastContext;
	ULONG		_pc;
	ULONG		_flags;
	WAIT_DEBUG_EVENT	_event;
};
