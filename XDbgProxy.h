#pragma once

#include "Thread.h"
#include "Lock.h"

#include <list>
#include <map>
#include "common.h"

class XDbgProxy : public Thread
{
private:
	XDbgProxy(void);
	~XDbgProxy(void);

public:
	bool initialize(); // ≥ı ºªØ
	static XDbgProxy& instance()
	{
		static XDbgProxy inst;
		return inst;
	}

	BOOL DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

	// TODO: Implement LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT By:
	//	HOOK NtMapViewOfSection & NtUnmapViewOfSection, CHECK DLL LIST WHEN THE SYSCALL RETURNED	
	// Ignore CREATE_PROCESS_DEBUG_EVENT & EXIT_PROCESS_DEBUG_EVENT & RIP_EVENT

protected:
	static LONG CALLBACK _VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	static VOID CALLBACK _LdrDllNotification(ULONG NotificationReason, 
		union _LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context);
	VOID CALLBACK LdrDllNotification(ULONG NotificationReason, 
		union _LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context);

	LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	bool createPipe();

	virtual long run();

	BOOL sendDbgEvent(const WAIT_DEBUG_EVENT& event);
	BOOL recvDbgAck(struct CONTINUE_DEBUG_EVENT& ack);
	BOOL sendDbgEvent(const WAIT_DEBUG_EVENT& event, struct CONTINUE_DEBUG_EVENT& ack);

	void postDbgEvent(const WAIT_DEBUG_EVENT& event);

	void onDbgConnect();
	void onDbgDisconnect();

	void sendProcessInfo();
	void sendModuleInfo();
	void sendThreadInfo();
protected:
	bool addThread(DWORD tid);
	bool delThread(DWORD tid);
	void suspendThreads(DWORD tid);
	void resumeThread(DWORD tid);
	HANDLE getThreadHandle(DWORD tid);

protected:
	HANDLE					_hPipe;
	bool					_attached;
	EXCEPTION_RECORD*		_lastException;
	ULONG					_lastExceptCode;
	PVOID					_lastExceptAddr;
	volatile int			_stopFlag;
	std::list<WAIT_DEBUG_EVENT>	_events;
	Mutex					_mutex;
	DWORD					_mainThreadId;
	_TEB*					_mainThreadTeb;
	std::map<DWORD, HANDLE>	_threads;
};
