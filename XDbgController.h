#pragma once

#include "common.h"

class XDbgController
{
public:
	XDbgController(void);
	~XDbgController(void);

	bool attach(DWORD pid);
	bool stop(DWORD pid);
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

	ULONG getExceptCode() const
	{
		return _exceptCode;
	}

	ULONG getLastPc() const
	{
		return _lastContext.Eip;
	}

	const CONTEXT& getLastContext() const
	{
		return _lastContext;
	}

	void setPC(ULONG pc)
	{
		_pc = pc;
	}
	
	ULONG getPC() const
	{
		return _pc;
	}

	void setMask(ULONG mask)
	{
		_mask |= mask;
	}

	void clearMask(ULONG mask)
	{
		_mask &= ~mask;
	}

	ULONG getMask() const
	{
		return _mask;
	}

	void setEFlags(ULONG flags)
	{
		_eflags = flags;
	}

	ULONG getEFlags() const
	{
		return _eflags;
	}

	void setDbgRegs(const DbgRegs& dbgRegs)
	{
		_dbgRegs = dbgRegs;
	}

	const DbgRegs& getDbgRegs() const
	{
		return _dbgRegs;
	}

	void setThreadContext(HANDLE hThread, const CONTEXT* ctx);
	void getThreadContext(HANDLE hThread, CONTEXT* ctx);

protected:
	void cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags);

protected:
	HANDLE		_hPipe;
	HANDLE		_hEvent;
	OVERLAPPED	_overlap;
	bool		_pending;
	HANDLE		_hProcess;
	ULONG		_exceptAddr;
	ULONG		_exceptCode;
	CONTEXT&	_lastContext;
	ULONG		_mask;
	ULONG		_pc;
	ULONG		_eflags;
	DbgRegs		_dbgRegs;
	WAIT_DEBUG_EVENT	_event;
};
