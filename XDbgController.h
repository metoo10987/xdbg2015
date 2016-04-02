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
	bool attach(DWORD pid, DWORD tid = 0);
	bool stop(DWORD pid);
	bool waitEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds = INFINITE);
	bool continueEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
	bool connectRemoteApi(DWORD pid);
	void disconnectRemoteApi();
	HANDLE getProcessHandle() const
	{
		return _hProcess;
	}

	bool setThreadContext(HANDLE hThread, const CONTEXT* ctx);
	bool getThreadContext(HANDLE hThread, CONTEXT* ctx);

	void* allocMemroy(size_t size, DWORD allocType, DWORD protect);
	bool freeMemory(LPVOID lpAddress, size_t dwSize, DWORD  dwFreeType);
	bool setMemoryProtection(LPVOID lpAddress, size_t dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	size_t queryMemory(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, size_t dwLength);
	bool readMemory(LPCVOID lpBaseAddress, PVOID lpBuffer, size_t nSize, size_t * lpNumberOfBytesRead);
	bool writeMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, size_t nSize, size_t * lpNumberOfBytesWritten);
	DWORD suspendThread(HANDLE hThread);
	DWORD resumeThread(HANDLE hThread);

	DWORD getEventCode() const
	{
		return _event.event.dwDebugEventCode;
	}

	DWORD getEventProcessId() const
	{
		return _event.event.dwProcessId;
	}

	DWORD getEventThreadId() const
	{
		return _event.event.dwThreadId;
	}

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

	DWORD getProcessId() const
	{
		return _pid;
	}

	static BOOL injectDll(DWORD pid, HMODULE hInst);

protected:
	void resetDbgEvent()
	{
		memset(&_event, 0, sizeof(_event));
		_ContextFlags = 0;
	}

	bool hookDbgApi();

	bool connectInferior(DWORD pid);
	void disconnectInferior();

	BOOL sendApiCall(const ApiCallPacket& outPkt);
	BOOL sendApiCall(const ApiCallPacket& outPkt, ApiReturnPakcet& inPkt);
	BOOL recvApiReturn(ApiReturnPakcet& inPkt);

private:
	XDbgController(void);
	~XDbgController(void);

protected:
	HANDLE				_hPipe;
	volatile DWORD		_pid;
	OVERLAPPED			_overlap;
	bool				_pending;
	HANDLE				_hProcess;
	DebugEventPacket	_event;
	HMODULE				_hInst;
	DWORD				_ContextFlags;
	HANDLE				_hApiPipe;
	Mutex				_apiMutex; // ensuring remote-API is atomic
};

class AutoDebug
{
public:
	virtual bool peekDebugEvent(LPDEBUG_EVENT event, DWORD* continueStatus) = 0;
};

void registerAutoDebugHandler(AutoDebug* handler);
