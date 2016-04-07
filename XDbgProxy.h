#pragma once

#include "Thread.h"
#include "Lock.h"

#include <list>
#include <map>
#include "common.h"
#include "ThreadMgr.h"
#include "Utils.h"

class XDbgProxy : protected Thread, public ThreadMgr, protected Mutex
{
private:
	XDbgProxy(void);
	~XDbgProxy(void);

public:
	bool initialize(); // ≥ı ºªØ
	void stop();
	static XDbgProxy& instance()
	{
		static XDbgProxy inst;
		return inst;
	}

	bool isAttached() const
	{
		return _attached;
	}

	void waitForAttach();

	BOOL DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

protected:
	static LONG CALLBACK _VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	static VOID CALLBACK _LdrDllNotification(ULONG NotificationReason, 
		union _LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context);
	VOID CALLBACK LdrDllNotification(ULONG NotificationReason, 
		union _LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context);

	LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	LONG CALLBACK AsyncVectoredHandler(DebugEventPacket& pkt);
	bool createEventPipe();
	bool createApiPipe();
	// bool createPipe();

	virtual long run();
	virtual long runApiLoop();

	BOOL sendDbgEvent(const DebugEventPacket& event);
	BOOL recvDbgAck(struct DebugAckPacket& ack);
	BOOL sendDbgEvent(const DebugEventPacket& event, struct DebugAckPacket& ack, bool freeze = true);

	void onDbgConnect();
	void onDbgDisconnect();

	void sendProcessInfo(DWORD firstThread);
	void sendModuleInfo(DWORD firstThread);
	void sendThreadInfo();
	
	//////////////////////////////////////////////////////////////////////////
	struct DbgEventEntry {
		SLIST_ENTRY			entry;
		DebugEventPacket	pkt;
	};

	void pushDbgEvent(DebugEventPacket& pkt);
	bool popDbgEvent(DebugEventPacket& pkt);
	//////////////////////////////////////////////////////////////////////////
	// REMOTE API
	class ApiThread : public Thread {
	public:
		ApiThread(XDbgProxy& parent) : _parent(parent)
		{

		}

	protected:
		virtual long run()
		{
			return _parent.runApiLoop();
		}

		XDbgProxy&		_parent;
	};

	BOOL recvApiCall(ApiCallPacket& inPkt);
	BOOL sendApiReturn(const ApiReturnPakcet& outPkt);

	typedef void(XDbgProxy::* RemoteApiHandler)(ApiCallPacket& inPkt);

	void registerRemoteApi();

	void ReadProcessMemory(ApiCallPacket& inPkt);
	void WriteProcessMemory(ApiCallPacket& inPkt);
	void SuspendThread(ApiCallPacket& inPkt);
	void ResumeThread(ApiCallPacket& inPkt);
	void VirtualQueryEx(ApiCallPacket& inPkt);
	void GetThreadContext(ApiCallPacket& inPkt);
	void SetThreadContext(ApiCallPacket& inPkt);
	void VirtualProtectEx(ApiCallPacket& inPkt);

	//////////////////////////////////////////////////////////////////////////

protected:
	HANDLE					_hPipe;
	volatile bool			_attached;
	EXCEPTION_RECORD*		_lastException;
	ULONG					_lastExceptCode;
	PVOID					_lastExceptAddr;
	volatile int			_stopFlag;
	typedef std::list<DebugEventPacket> DbgEvtPkgs;
	DbgEvtPkgs				_pendingEvents;

	// event completion notification
	HANDLE					_evtQueueEvent;
	Mutex					_evtLock;
	Mutex					_evtQueueLock;
	LONG					_exceptHandleCode;

	PVOID					_vehCookie;
	PVOID					_dllNotifCooike;

	HANDLE					_hApiPipe;
	ApiThread				_apiThread;

	typedef std::map<DWORD, RemoteApiHandler> RemoteApiHandlers;

	RemoteApiHandlers		_apiHandlers;
};
