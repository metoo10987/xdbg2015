#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>
#include "XDbgProxy.h"
#include <assert.h>
#include "Win32ApiWrapper.h"
#include "Win32ApiWrapper.h"
#include <tlhelp32.h>
#include <Psapi.h>
#include "Utils.h"
#include "common.h"

extern UINT ignore_dbgstr;
extern UINT inject_method;
extern UINT simu_attach_bp;

XDbgProxy::XDbgProxy(void) : _apiThread(*this)//, _eventQueue(1, 1)
{
	_hPipe = INVALID_HANDLE_VALUE;
	_hApiPipe = INVALID_HANDLE_VALUE;
	memset(&_lastException, 0l, sizeof(_lastException));
	_stopFlag = 0;
	_attached = false;

	_lastExceptCode = 0;
	_lastExceptAddr = 0;
	_vehCookie = NULL;
	registerRemoteApi();

	_exceptHandleCode = 0;
	_evtQueueEvent = NULL;
}

XDbgProxy::~XDbgProxy(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		XDbgCloseHandle(_hPipe);
}

BOOL XDbgProxy::sendDbgEvent(const DebugEventPacket& event)
{
	if (event.event.dwDebugEventCode > LAST_EVENT) {
		assert(false);
		return FALSE;
	}

	if (event.event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		memset((void* )&event.ctx, 0l, sizeof(event.ctx));
	DWORD len;
	if (!XDbgWriteFile(_hPipe, &event, sizeof(event), &len, NULL)) {
		// log error
		return FALSE;
	}

	return TRUE;
}

BOOL XDbgProxy::recvDbgAck(struct DebugAckPacket& ack)
{
	DWORD len;
	if (!XDbgReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		// log error
		return FALSE;
	}

	return TRUE;
}

BOOL XDbgProxy::sendDbgEvent(const DebugEventPacket& event, struct DebugAckPacket& ack, bool freeze)
{
	BOOL result;
	if (freeze)
		suspendAll(XDbgGetCurrentThreadId());
	if (sendDbgEvent(event))
		result = recvDbgAck(ack);
	else
		result = FALSE;
	if (freeze)
		resumeAll(XDbgGetCurrentThreadId());
	return result;
}

void XDbgProxy::pushDbgEvent(DebugEventPacket& pkt)
{
	MutexGuard guard2(&_evtLock);

	{
		MutexGuard guard(&_evtQueueLock);
		::ResetEvent(_evtQueueEvent);
		_pendingEvents.push_back(pkt);
	}

	::WaitForSingleObject(_evtQueueEvent, INFINITE);
}

bool XDbgProxy::popDbgEvent(DebugEventPacket& pkt)
{
	if (!_evtQueueLock.trylock())
		return false;

	bool result = false;

	if (_pendingEvents.size()) {
		DebugEventPacket& ret = _pendingEvents.front();
		pkt = ret;
		_pendingEvents.pop_front();		
		result = true;
	}

	_evtQueueLock.unlock();
	return result;
}

LONG CALLBACK XDbgProxy::_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	return XDbgProxy::instance().VectoredHandler(ExceptionInfo);
}

VOID CALLBACK XDbgProxy::_LdrDllNotification(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, 
	PVOID Context)
{
	XDbgProxy::instance().LdrDllNotification(NotificationReason, NotificationData, Context);
}

VOID CALLBACK XDbgProxy::LdrDllNotification(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, 
	PVOID Context)
{
	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = XDbgGetCurrentThreadId();
	
	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		msg.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
		msg.u.LoadDll.dwDebugInfoFileOffset = 0;
		msg.u.LoadDll.fUnicode = 1;
		msg.u.LoadDll.hFile = NULL;
		msg.u.LoadDll.lpBaseOfDll = NotificationData->Loaded.DllBase;
		msg.u.LoadDll.lpImageName = _wcsdup(NotificationData->Loaded.FullDllName->Buffer);
		msg.u.LoadDll.nDebugInfoSize = 0;
	} else if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		msg.dwDebugEventCode = UNLOAD_DLL_DEBUG_EVENT;
		msg.u.UnloadDll.lpBaseOfDll = NotificationData->Unloaded.DllBase;
	} else
		return;

	// FIXME: 
	// 加载 Dll 可能在 APC 中进行， 这会导致其它的通知过程（sendDbgEvent）被打断， 造成错误
	// 现在 Dll 相关的通知全部缓存， 但是会导致 LoadDll 断点失效
	pushDbgEvent(event);
}

bool XDbgProxy::initialize()
{
	_evtQueueEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!(/* _threadHandled && _dllHandled && */ _evtQueueEvent)) {
		assert(false);
		return false;
	}

	if (!InitWin32ApiWrapper()) {
		assert(false);
		return false;
	}

	/* if (!createPipe())
		return false; */

	_vehCookie = AddVectoredExceptionHandler(1, &XDbgProxy::_VectoredHandler);
	if (_vehCookie == NULL)
		return false;

	typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, PCLDR_DLL_NOTIFICATION_DATA, PVOID);
	typedef NTSTATUS (NTAPI *LdrRegDllNotifFunc)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID *);
	LdrRegDllNotifFunc LdrRegisterDllNotification = (LdrRegDllNotifFunc )GetProcAddress(
		GetModuleHandle("ntdll.dll"), "LdrRegisterDllNotification");
	if (LdrRegisterDllNotification) {
		
		if (LdrRegisterDllNotification(0, &XDbgProxy::_LdrDllNotification, NULL, &_dllNotifCooike) != 0) {
			// log error
			assert(false);			
		}
	}

	MyTrace("%s(): starting thread.", __FUNCTION__);
	_stopFlag = false;
	if (!start()) {
		assert(false);
		return false;
	}
	
	if (!_apiThread.start()) {
		assert(false);
		return false;
	}

	return true;
}

// FIXME: it's not always right. Thread::stop might hang.
void XDbgProxy::stop()
{
	assert(false);

	_stopFlag = true;
	Thread::stop(-1); // stop xdbg thread
	typedef NTSTATUS (NTAPI *LdrUnregDllNotifFunc)(PVOID Cookie);
	LdrUnregDllNotifFunc LdrUnregisterDllNotification = (LdrUnregDllNotifFunc)GetProcAddress(
		GetModuleHandle("ntdll.dll"), "LdrUnregisterDllNotification");
	if (LdrUnregisterDllNotification) {
		LdrUnregisterDllNotification(_dllNotifCooike);
		_dllNotifCooike = NULL;
	}

	RemoveVectoredExceptionHandler(_vehCookie);
	_vehCookie = NULL;
	UninitWin32ApiWrapper();
	if (_hPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(_hPipe);
		_hPipe = INVALID_HANDLE_VALUE;
	}

	if (_hApiPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(_hApiPipe);
		_hApiPipe = INVALID_HANDLE_VALUE;
	}
}

LONG CALLBACK XDbgProxy::VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// MyTrace("%s()", __FUNCTION__);

	if (!_attached)
		return EXCEPTION_CONTINUE_SEARCH;

	DWORD currentTid = XDbgGetCurrentThreadId();
	if (currentTid == getId() || currentTid == _apiThread.getId())
		return EXCEPTION_CONTINUE_SEARCH;

	if (ignore_dbgstr) {
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C ||
			ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C) {
			
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;

	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = XDbgGetCurrentThreadId();
	msg.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
	msg.u.Exception.ExceptionRecord.ExceptionInformation[0] = (ULONG_PTR )ExceptionInfo;
	pushDbgEvent(event);
	return _exceptHandleCode;
}

LONG CALLBACK XDbgProxy::AsyncVectoredHandler(DebugEventPacket& pkt)
{
	// MyTrace("%s()", __FUNCTION__);
	MutexGuard guard(this);
	
	if (threadIdToHandle(pkt.event.dwThreadId) == NULL) {
		// assert(false);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	PEXCEPTION_POINTERS ExceptionInfo = (PEXCEPTION_POINTERS )pkt.event.u.Exception.
		ExceptionRecord.ExceptionInformation[0];

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;
	msg.dwProcessId = pkt.event.dwProcessId;
	msg.dwThreadId = pkt.event.dwThreadId;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C) {

		msg.dwDebugEventCode = OUTPUT_DEBUG_STRING_EVENT;
		msg.u.DebugString.fUnicode = 0;
		msg.u.DebugString.nDebugStringLength = (WORD )ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
		msg.u.DebugString.lpDebugStringData = (LPSTR )ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	} else if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C) {

		msg.dwDebugEventCode = OUTPUT_DEBUG_STRING_EVENT;
		msg.u.DebugString.fUnicode = 1;
		msg.u.DebugString.nDebugStringLength = (WORD)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
		msg.u.DebugString.lpDebugStringData = (LPSTR)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	} else {
		
		msg.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
		
		if (_lastException == ExceptionInfo->ExceptionRecord && 
			_lastExceptCode == ExceptionInfo->ExceptionRecord->ExceptionCode && 
			_lastExceptAddr == ExceptionInfo->ExceptionRecord->ExceptionAddress) {

			msg.u.Exception.dwFirstChance = 0;
		} else
			msg.u.Exception.dwFirstChance = 1;

		msg.u.Exception.ExceptionRecord = *ExceptionInfo->ExceptionRecord;
		_lastException = ExceptionInfo->ExceptionRecord;
		_lastExceptCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
		_lastExceptAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	};

	event.ctx = *ExceptionInfo->ContextRecord;
	DebugAckPacket ack;
	if (!sendDbgEvent(event, ack)) {
		// log error
		return EXCEPTION_CONTINUE_SEARCH;
	}

	cloneThreadContext(ExceptionInfo->ContextRecord, &ack.ctx, ack.ContextFlags);

	if ((ack.ContextFlags & CONTEXT_CONTROL) != CONTEXT_CONTROL) {
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
			if (ack.dwContinueStatus == DBG_CONTINUE) {
				CTX_PC_REG(ExceptionInfo->ContextRecord) += 1;
			}
		}
	}

	if (ack.dwContinueStatus == DBG_CONTINUE)
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

/* bool XDbgProxy::createPipe()
{
	std::string name = makePipeName(XDbgGetCurrentProcessId());	
	_hPipe = ::CreateNamedPipe(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
		PIPE_UNLIMITED_INSTANCES, EVENT_MESSAGE_SIZE, CONTINUE_MESSAGE_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);

	if (_hPipe == INVALID_HANDLE_VALUE)
		return false;

	std::string apiName = makeApiPipeName(XDbgGetCurrentProcessId());
	_hApiPipe = ::CreateNamedPipe(apiName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, RETURN_MESSAGE_SIZE, CALL_MESSAGE_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);

	if (_hApiPipe == INVALID_HANDLE_VALUE) {
		CloseHandle(_hPipe);
		_hPipe = INVALID_HANDLE_VALUE;
		return false;
	}

	MyTrace("%s(): _hPipe = %x[%d, %d], _hApiPipe = %x[%d, %d]", __FUNCTION__, 
		_hPipe, EVENT_MESSAGE_SIZE, CONTINUE_MESSAGE_SIZE, 
		_hApiPipe, RETURN_MESSAGE_SIZE, CALL_MESSAGE_SIZE);

	return true;
} */

bool XDbgProxy::createEventPipe()
{
	std::string name = makePipeName(XDbgGetCurrentProcessId());
	_hPipe = ::CreateNamedPipe(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, EVENT_MESSAGE_SIZE, CONTINUE_MESSAGE_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);

	if (_hPipe == INVALID_HANDLE_VALUE)
		return false;

	return true;
}

bool XDbgProxy::createApiPipe()
{
	std::string apiName = makeApiPipeName(XDbgGetCurrentProcessId());
	_hApiPipe = ::CreateNamedPipe(apiName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, RETURN_MESSAGE_SIZE, CALL_MESSAGE_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);

	if (_hApiPipe == INVALID_HANDLE_VALUE) {
		CloseHandle(_hPipe);
		_hPipe = INVALID_HANDLE_VALUE;
		return false;
	}

	return true;
}

// SO, THIS MODULE MUST BE A DLL
BOOL XDbgProxy::DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	// MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));

	DEBUG_EVENT& msg = event.event;

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		{
			char dllPath[MAX_PATH + 1];
			GetModuleFileName(hModule, dllPath, sizeof(dllPath) - 1);
			dllPath[sizeof(dllPath) - 1] = 0;
			LoadLibrary(dllPath);
		}
		// MyTrace("%s(): process(%u) xdbg proxy loaded. thread id: %u", __FUNCTION__, 
		//		GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_PROCESS_DETACH:
		// MyTrace("%s(): process(%u) xdbg proxy unloaded. thread id: %u", __FUNCTION__, 
		//		GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_THREAD_ATTACH:

		//MyTrace("%s(): process(%u) xdbg proxy attach thread. thread id: %u <<<", __FUNCTION__,
		//	XDbgGetCurrentProcessId(), XDbgGetCurrentThreadId());

		if (!_attached)
			return TRUE;

		// REPORT CreateThread
		msg.dwProcessId = XDbgGetCurrentProcessId();
		msg.dwThreadId = XDbgGetCurrentThreadId();
		msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
		msg.u.CreateThread.hThread = NULL;
		
		msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE )
			GetThreadStartAddress(XDbgGetCurrentThread());

		msg.u.CreateThread.lpThreadLocalBase = NtCurrentTeb();

		pushDbgEvent(event);
		//MyTrace("%s(): process(%u) xdbg proxy attach thread. thread id: %u >>>", __FUNCTION__,
		//	GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_THREAD_DETACH:
		// REPORT ExitThread

		//MyTrace("%s(): process(%u) xdbg proxy detach thread. thread id: %u <<<", __FUNCTION__,
		//	GetCurrentProcessId(), GetCurrentThreadId());

		if (!_attached)
			return TRUE;

		msg.dwProcessId = XDbgGetCurrentProcessId();
		msg.dwThreadId = XDbgGetCurrentThreadId();
		msg.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
		if (!GetExitCodeThread(XDbgGetCurrentThread(), &msg.u.ExitThread.dwExitCode))
			msg.u.ExitThread.dwExitCode = 0;

		pushDbgEvent(event);

		//MyTrace("%s(): process(%u) xdbg proxy detach thread. thread id: %u >>>", __FUNCTION__,
		//	GetCurrentProcessId(), GetCurrentThreadId());

		break;
	};

	return TRUE;
}

void XDbgProxy::waitForAttach()
{
	while (!_attached) {
		Sleep(0);
		MemoryBarrier();
	}
}

long XDbgProxy::run()
{
	MyTrace("XDBG Thread started");

	while (!_stopFlag) {

		if (_attached) {

			{
				// MutexGuard guard(this);

				DebugEventPacket event;
				DebugAckPacket ack;

				if (popDbgEvent(event)) {

					MyTrace("%s(): eventId: %d, threadId: %d", __FUNCTION__, event.event.dwDebugEventCode, 
						event.event.dwThreadId);

					switch (event.event.dwDebugEventCode) {

					case EXCEPTION_DEBUG_EVENT:
						_exceptHandleCode = AsyncVectoredHandler(event);
						break;

					case LOAD_DLL_DEBUG_EVENT:

						if (!sendDbgEvent(event, ack)) {
							break;
						}

						if (event.event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
							free(event.event.u.LoadDll.lpImageName);
						}

						break;
					case CREATE_THREAD_DEBUG_EVENT:

						if (threadIdToHandle(event.event.dwThreadId) != NULL) {
							// reentry
							break;
						}

						if (!sendDbgEvent(event, ack)) {
							break;
						}

						addThread(event.event.dwThreadId);
						break;

					case EXIT_THREAD_DEBUG_EVENT:

						if (threadIdToHandle(event.event.dwThreadId) == NULL) {
							// reentry
							break;;
						}

						if (!sendDbgEvent(event, ack)) {
							break;
						}

						delThread(event.event.dwThreadId);
						break;

					default:
						break;
					}

					SetEvent(_evtQueueEvent);
				} else {

					Sleep(10);
				}
			}			

		} else {

			if (!createEventPipe()) {
				continue;
			}

			if (!ConnectNamedPipe(_hPipe, NULL)) {
				if (GetLastError() == ERROR_PIPE_CONNECTED) {
					onDbgConnect();
					_attached = true;
					MyTrace("debugger attached");
					continue;

				} else {
					MyTrace("%s(): ConnectNamedPipe(%p) failed. errCode: %d ", __FUNCTION__, _hPipe, GetLastError());
					// assert(false);
					// return -1;
					CloseHandle(_hPipe);
					_hPipe = INVALID_HANDLE_VALUE;
					Sleep(100);
				}				

			} else {
				onDbgConnect();
				_attached = true;
				MyTrace("debugger attached");
			}
		}
	}

	return 0;
}

void XDbgProxy::onDbgConnect()
{
	MutexGuard guard(this);

	clearThreads();
	addAllThreads(XDbgGetCurrentThreadId());
	delThread(_apiThread.getId());
	suspendAll(XDbgGetCurrentThreadId());

	DebugEventPacket event;
	DebugAckPacket ack;
	event.event.dwProcessId = XDbgGetCurrentProcessId();
	event.event.dwThreadId = getFirstThread();
	event.event.dwDebugEventCode = ATTACHED_EVENT; // THIS MSG DONT PASS TO DEBUGGER
	sendDbgEvent(event, ack, false);
	ignore_dbgstr = ack.args.ignore_dbgstr;
	inject_method = ack.args.inject_method;
	simu_attach_bp = ack.args.simu_attach_bp;

	sendProcessInfo(ack.dwThreadId);
	sendThreadInfo();
	sendModuleInfo(ack.dwThreadId);
	// attach breakpoint
	if (simu_attach_bp && !ack.args.createProcess) {
		DWORD tid;
		HANDLE hThread = ::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DebugBreak, NULL, 0, &tid);
		CloseHandle(hThread);
	}

	resumeAll(XDbgGetCurrentThreadId());
}

void XDbgProxy::onDbgDisconnect()
{
	MyTrace("%s()", __FUNCTION__);
	// MutexGuard guard(this);
}

void XDbgProxy::sendProcessInfo(DWORD firstThread)
{
	MyTrace("%s()", __FUNCTION__);
	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = firstThread;

	char modName[MAX_PATH + 1] = {0};

	memset(&msg.u.CreateProcessInfo, 0, sizeof(msg.u.CreateProcessInfo));
	msg.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
	msg.u.CreateProcessInfo.dwDebugInfoFileOffset = 0;
	msg.u.CreateProcessInfo.fUnicode = 0;
	msg.u.CreateProcessInfo.hFile = NULL;
	msg.u.CreateProcessInfo.hProcess = NULL;
	msg.u.CreateProcessInfo.hThread = NULL;
	msg.u.CreateProcessInfo.lpBaseOfImage = (PVOID )GetModuleHandle(NULL);
	GetModuleFileName(GetModuleHandle(NULL), modName, MAX_PATH);
	msg.u.CreateProcessInfo.lpImageName = modName;
	msg.u.CreateProcessInfo.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(firstThread);
	MyTrace("%s(): mod: %s, main thread start at: %p", __FUNCTION__, modName, 
		msg.u.CreateProcessInfo.lpStartAddress);
	msg.u.CreateProcessInfo.lpThreadLocalBase = GetThreadTeb(firstThread);
	msg.u.CreateProcessInfo.nDebugInfoSize = 0;
	sendDbgEvent(event, ack, false);
}

void XDbgProxy::sendModuleInfo(DWORD firstThread)
{
	MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;

	msg.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = firstThread;

	char modName[MAX_PATH + 1] = {0};

	HMODULE hMainModule = GetModuleHandle(NULL);
	/*msg.u.LoadDll.dwDebugInfoFileOffset = 0;
	msg.u.LoadDll.fUnicode = 0;
	msg.u.LoadDll.hFile = NULL;
	msg.u.LoadDll.lpBaseOfDll = hMainModule;
	GetModuleFileName(hMainModule, modName, MAX_PATH);
	msg.u.LoadDll.lpImageName = modName;
	sendDbgEvent(event, ack);
	MyTrace("%s(): module: %s, %p", __FUNCTION__, modName, msg.u.LoadDll.lpBaseOfDll);*/

	HMODULE hModules[512];
	DWORD len;
	if (!EnumProcessModules(XDbgGetCurrentProcess(), hModules, sizeof(hModules), &len)) {
		// log error
		assert(false);
		return;
	}

	len /= sizeof(HMODULE);
	MyTrace("%s(): module count: %d", __FUNCTION__, len);

	for (DWORD i = 0; i < len; i++) {
		if (hMainModule == hModules[i])
			continue;

		msg.u.LoadDll.dwDebugInfoFileOffset = 0;
		msg.u.LoadDll.fUnicode = 0;
		msg.u.LoadDll.hFile = NULL;
		msg.u.LoadDll.lpBaseOfDll = hModules[i];
		memset(modName, 0, sizeof(modName));
		if (GetModuleFileName(hModules[i], modName, MAX_PATH) == 0 || modName[0] == '\0')
			continue;
		msg.u.LoadDll.lpImageName = modName;
		sendDbgEvent(event, ack, false);
		MyTrace("%s(): module: %s, %p", __FUNCTION__, modName, msg.u.LoadDll.lpBaseOfDll);
	}
}

void XDbgProxy::sendThreadInfo()
{
	MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;

	msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	
	DWORD threadId = getFirstThread();
	while (threadId) {

		msg.dwThreadId = threadId;
		msg.u.CreateThread.hThread = NULL;
		msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)
			GetThreadStartAddress(threadId);

		msg.u.CreateThread.lpThreadLocalBase = GetThreadTeb(threadId);
		sendDbgEvent(event, ack, false);
		threadId = getNextThread();
	}

	/*
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(hSnapshot, &te)) {
			do {
				if (te.th32OwnerProcessID == XDbgGetCurrentProcessId()) {

					if (te.th32ThreadID == getId())
						continue; // skip xdbg thread;
					msg.dwThreadId = te.th32ThreadID;
					msg.u.CreateThread.hThread = NULL;
					msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)
						GetThreadStartAddress(te.th32ThreadID);

					msg.u.CreateThread.lpThreadLocalBase = GetThreadTeb(te.th32ThreadID);
					addThread(te.th32ThreadID);
					sendDbgEvent(event, ack, false);
				}

				te.dwSize = sizeof(te);
			} while (Thread32Next(hSnapshot, &te));
		}

		XDbgCloseHandle(hSnapshot);
	}
	*/
}

//////////////////////////////////////////////////////////////////////////
void XDbgProxy::registerRemoteApi()
{
	_apiHandlers[ID_ReadProcessMemory] = &XDbgProxy::ReadProcessMemory;
	_apiHandlers[ID_WriteProcessMemory] = &XDbgProxy::WriteProcessMemory;
	_apiHandlers[ID_SuspendThread] = &XDbgProxy::SuspendThread;
	_apiHandlers[ID_ResumeThread] = &XDbgProxy::ResumeThread;
	_apiHandlers[ID_VirtualQueryEx] = &XDbgProxy::VirtualQueryEx;
	_apiHandlers[ID_VirtualProtectEx] = &XDbgProxy::VirtualProtectEx;
	_apiHandlers[ID_GetThreadContext] = &XDbgProxy::GetThreadContext;
	_apiHandlers[ID_SetThreadContext] = &XDbgProxy::SetThreadContext;
	_apiHandlers[ID_GetModuleFileNameExW] = &XDbgProxy::_GetModuleFileNameExW;	
}

BOOL XDbgProxy::recvApiCall(ApiCallPacket& inPkt)
{
	DWORD len;
	if (!ReadFile(_hApiPipe, &inPkt, sizeof(inPkt), &len, NULL)) {
		// assert(false);
		return FALSE;
	}

	return TRUE;
}

BOOL XDbgProxy::sendApiReturn(const ApiReturnPakcet& outPkt)
{
	DWORD len;
	if (!WriteFile(_hApiPipe, &outPkt, sizeof(outPkt), &len, NULL)) {
		return FALSE;
	}

	return TRUE;
}

long XDbgProxy::runApiLoop()
{	
	ApiCallPacket inPkt;
	bool attached = false;

	while (!_stopFlag) {

		if (!attached) {
			if (!createApiPipe()) {
				Sleep(100);
				continue;
			}

			if (!ConnectNamedPipe(_hApiPipe, NULL)) {

				if (GetLastError() == ERROR_PIPE_CONNECTED) {

					MyTrace("%s(): attached", __FUNCTION__);
					attached = true;
					
				} else {

					MyTrace("%s(): ConnectNamedPipe() failed.", __FUNCTION__);
					// assert(false);
					// return -1;
					CloseHandle(_hApiPipe);
					_hApiPipe = INVALID_HANDLE_VALUE;
					Sleep(100);
					continue;
				}

			} else {
				MyTrace("%s(): attached", __FUNCTION__);
				attached = true;
			}
		}

		if (!recvApiCall(inPkt)) {
			// assert(false);
			// return -1;
			attached = false;
			continue;
		}

		// MyTrace("%s(): ApiCall: id = %d", __FUNCTION__, inPkt.apiId);

		RemoteApiHandlers::iterator it;
		it = _apiHandlers.find(inPkt.apiId);
		if (it == _apiHandlers.end()) {
			assert(false);
			// return -1;
			continue;
		}

		RemoteApiHandler handler = it->second;
		(this->*handler)(inPkt);
		// MyTrace("%s(): ApiCall: id = %d completed", __FUNCTION__, inPkt.apiId);
	}

	return 0;
}

// #define _API_TRACE

#if 1
void XDbgProxy::ReadProcessMemory(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	assert(inPkt.ReadProcessMemory.size <= MAX_MEMORY_BLOCK);

	PVOID addr = inPkt.ReadProcessMemory.addr;
	SIZE_T size = inPkt.ReadProcessMemory.size;

	ApiReturnPakcet outPkt;
	__try {
		outPkt.ReadProcessMemory.result = ::ReadProcessMemory(GetCurrentProcess(), addr,
			outPkt.ReadProcessMemory.buffer, size, &outPkt.ReadProcessMemory.size);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		outPkt.ReadProcessMemory.result = FALSE;
	}

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): addr: %p, size: %d, result: %d, errno: %d", __FUNCTION__, addr, size, 
		outPkt.ReadProcessMemory.result, outPkt.lastError);
#endif
	sendApiReturn(outPkt);
}

void XDbgProxy::WriteProcessMemory(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);
	assert(inPkt.WriteProcessMemory.size <= MAX_MEMORY_BLOCK);
	ApiReturnPakcet outPkt;

	PVOID addr = inPkt.WriteProcessMemory.addr;
	PUCHAR buffer = inPkt.WriteProcessMemory.buffer;
	SIZE_T size = inPkt.WriteProcessMemory.size;
	
	__try {
		outPkt.WriteProcessMemory.result = ::WriteProcessMemory(GetCurrentProcess(), addr,
			buffer, size, &outPkt.WriteProcessMemory.writtenSize);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		outPkt.WriteProcessMemory.result = FALSE;
	}

	outPkt.lastError = GetLastError();
#ifdef _API_TRACE
	MyTrace("%s(): addr: %p, size: %d, result: %d, errno: %d", __FUNCTION__, addr, size, 
		outPkt.WriteProcessMemory.result, outPkt.lastError);
#endif
	sendApiReturn(outPkt);
}

#else 

void XDbgProxy::ReadProcessMemory(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	assert(inPkt.ReadProcessMemory.size <= MAX_MEMORY_BLOCK);

	PVOID addr = inPkt.ReadProcessMemory.addr;
	SIZE_T size = inPkt.ReadProcessMemory.size;

	ApiReturnPakcet outPkt;
	if (IsBadReadPtr(addr, size)) {
		outPkt.lastError = ERROR_INVALID_ADDRESS;
		outPkt.ReadProcessMemory.result = FALSE;
		sendApiReturn(outPkt);
		return;
	}
	
	__try {
		memcpy(outPkt.ReadProcessMemory.buffer, inPkt.ReadProcessMemory.addr,
			inPkt.ReadProcessMemory.size);
		outPkt.ReadProcessMemory.result = TRUE;
		outPkt.ReadProcessMemory.size = inPkt.ReadProcessMemory.size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		outPkt.lastError = ERROR_INVALID_ADDRESS;
		outPkt.ReadProcessMemory.result = FALSE;
		sendApiReturn(outPkt);
	}

	sendApiReturn(outPkt);
}

void XDbgProxy::WriteProcessMemory(ApiCallPacket& inPkt)
{
	MyTrace("%s()", __FUNCTION__);
	assert(inPkt.WriteProcessMemory.size <= MAX_MEMORY_BLOCK);
	ApiReturnPakcet outPkt;

	PVOID addr = inPkt.WriteProcessMemory.addr;
	PUCHAR buffer = inPkt.WriteProcessMemory.buffer;
	SIZE_T size = inPkt.WriteProcessMemory.size;

	if (IsBadWritePtr(addr, size)) {
		outPkt.lastError = ERROR_INVALID_ADDRESS;
		outPkt.WriteProcessMemory.result = FALSE;
		sendApiReturn(outPkt);
		return;
	}

	memcpy(addr, buffer, size);

	outPkt.lastError = 0;
	outPkt.WriteProcessMemory.result = TRUE;
	outPkt.WriteProcessMemory.writtenSize = size;
	sendApiReturn(outPkt);
}

#endif

void XDbgProxy::SuspendThread(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;
	HANDLE hThread;

#ifdef _DEBUG
	if (inPkt.SuspendThread.threadId == getId() || inPkt.SuspendThread.threadId == _apiThread.getId()) {
		// log error
		assert(false);
		outPkt.SuspendThread.result = -1;
		SetLastError(ERROR_INVALID_PARAMETER);
		sendApiReturn(outPkt);
	}
#endif
	
	// 如果被调试线程已经被suspend， 并且正在执行threadmgr中的函数， 这里就会死锁. 
	// 所以改成OpenThread
	// hThread = threadIdToHandle(inPkt.SuspendThread.threadId);
	hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, inPkt.SuspendThread.threadId);

	if (hThread == NULL) {
		outPkt.SuspendThread.result = -1;
		// SetLastError(ERROR_INVALID_PARAMETER);
	} else {
		outPkt.SuspendThread.result = ::SuspendThread(hThread);
		CloseHandle(hThread);
	}

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): threadId: %d, result: %d, errno: %d", __FUNCTION__, 
		inPkt.SuspendThread.threadId, outPkt.SuspendThread.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::ResumeThread(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;
	HANDLE hThread;

	// 如果被调试线程已经被suspend， 并且正在执行threadmgr中的函数， 这里就会死锁. 
	// 所以改成OpenThread
	// hThread = threadIdToHandle(inPkt.SuspendThread.threadId);
	hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, inPkt.SuspendThread.threadId);

	if (hThread == NULL) {
		outPkt.ResumeThread.result = -1;
		// SetLastError(ERROR_INVALID_PARAMETER);
	} else {
		outPkt.ResumeThread.result = ::ResumeThread(hThread);
		CloseHandle(hThread);
	}

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): threadId: %d, result: %d, errno: %d", __FUNCTION__, 
		inPkt.ResumeThread.threadId, outPkt.ResumeThread.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::VirtualQueryEx(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;
	outPkt.VirtualQueryEx.result = ::VirtualQuery(inPkt.VirtualQueryEx.addr, &outPkt.VirtualQueryEx.memInfo,
		sizeof(outPkt.VirtualQueryEx.memInfo));
	
	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): addr: %p, result: %d, errno: %d", __FUNCTION__, inPkt.VirtualQueryEx.addr, 
		outPkt.VirtualQueryEx.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::GetThreadContext(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;
	HANDLE hThread;

	// 如果被调试线程已经被suspend， 并且正在执行threadmgr中的函数， 这里就会死锁. 
	// 所以改成OpenThread
	hThread = threadIdToHandle(inPkt.SuspendThread.threadId);
	// hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, inPkt.SuspendThread.threadId);

	if (hThread == NULL || hThread == (HANDLE )-1) {
		outPkt.GetThreadContext.result = FALSE;
		SetLastError(ERROR_INVALID_PARAMETER);
		MyTrace("%s(): cannot found the threadId: %d", __FUNCTION__, inPkt.GetThreadContext.threadId);
	} else {
		outPkt.GetThreadContext.ctx.ContextFlags = inPkt.GetThreadContext.contextFlags;
		outPkt.GetThreadContext.result = ::GetThreadContext(hThread, &outPkt.GetThreadContext.ctx);
		// CloseHandle(hThread);
	}

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): th: %x, tid: %d, result: %d, errno: %d", __FUNCTION__, hThread,
		inPkt.GetThreadContext.threadId, outPkt.GetThreadContext.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::SetThreadContext(ApiCallPacket& inPkt)
{
	// MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;
	HANDLE hThread;

#ifdef _DEBUG
	if (inPkt.SuspendThread.threadId == getId() || inPkt.SuspendThread.threadId == _apiThread.getId()) {
		// log error
		assert(false);
		outPkt.SuspendThread.result = -1;
		SetLastError(ERROR_INVALID_PARAMETER);
		sendApiReturn(outPkt);
	}
#endif

	// 如果被调试线程已经被suspend， 并且正在执行threadmgr中的函数， 这里就会死锁. 
	// 所以改成OpenThread
	hThread = threadIdToHandle(inPkt.SuspendThread.threadId);
	// hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, inPkt.SuspendThread.threadId);

	if (hThread == NULL || hThread == (HANDLE)-1) {
		outPkt.SetThreadContext.result = FALSE;
		SetLastError(ERROR_INVALID_PARAMETER);
		MyTrace("%s(): cannot found the threadId: %d", __FUNCTION__, inPkt.SetThreadContext.threadId);
	}
	else {
		outPkt.SetThreadContext.result = ::SetThreadContext(hThread, &inPkt.SetThreadContext.ctx);
		// CloseHandle(hThread);
	}

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): th: %x, tid: %d, result: %d, errno: %d", __FUNCTION__, hThread, 
		inPkt.SetThreadContext.threadId, outPkt.SetThreadContext.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::VirtualProtectEx(ApiCallPacket& inPkt)
{
	ApiReturnPakcet outPkt;
	outPkt.VirtualProtectEx.result = ::VirtualProtect(inPkt.VirtualProtectEx.addr,
		inPkt.VirtualProtectEx.size, inPkt.VirtualProtectEx.prot,
		&outPkt.VirtualProtectEx.oldProt);
	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): addr: %p, result: %d, errno: %d", __FUNCTION__, inPkt.VirtualProtectEx.addr,
		outPkt.VirtualProtectEx.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}

void XDbgProxy::_GetModuleFileNameExW(ApiCallPacket& inPkt)
{
	ApiReturnPakcet outPkt;
	outPkt._GetModuleFileNameExW.result = ::GetModuleFileNameExW(GetCurrentProcess(), 
		inPkt._GetModuleFileNameExW.hMod, outPkt._GetModuleFileNameExW.fileName, 
		sizeof(outPkt._GetModuleFileNameExW.fileName));

	outPkt.lastError = GetLastError();

#ifdef _API_TRACE
	MyTrace("%s(): hMod: %p, result: %d, errno: %d", __FUNCTION__, inPkt._GetModuleFileNameExW.hMod,
		outPkt._GetModuleFileNameExW.result, outPkt.lastError);
#endif

	sendApiReturn(outPkt);
}
