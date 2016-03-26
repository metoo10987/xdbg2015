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

XDbgProxy::XDbgProxy(void) : _apiThread(*this)
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
	
	MutexGuard guard(this);

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

	_pendingEvents.push_back(event);
	/* DebugAckPacket ack;
	if (!sendDbgEvent(event, ack)) {

	} */
}

bool XDbgProxy::initialize()
{
	if (!InitWin32ApiWrapper()) {
		assert(false);
		return false;
	}

	if (!createPipe())
		return false;

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
	if (_hPipe) {
		CloseHandle(_hPipe);
		_hPipe = NULL;
	}
}

LONG CALLBACK XDbgProxy::VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	MutexGuard guard(this);

	if (!_attached)
		return EXCEPTION_CONTINUE_SEARCH;

	if (XDbgGetCurrentThreadId() == getId() || XDbgGetCurrentThreadId() == _apiThread.getId())
		return EXCEPTION_CONTINUE_SEARCH;

	if (threadIdToHandle(XDbgGetCurrentThreadId()) == NULL) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));
	DEBUG_EVENT& msg = event.event;

	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = XDbgGetCurrentThreadId();
	
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

bool XDbgProxy::createPipe()
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
}

// SO, THIS MODULE MUST BE A DLL
BOOL XDbgProxy::DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	// MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));

	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;
	
	MutexGuard guard(this);

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		// MyTrace("%s(): process(%u) xdbg proxy loaded. thread id: %u", __FUNCTION__, GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_PROCESS_DETACH:
		// MyTrace("%s(): process(%u) xdbg proxy unloaded. thread id: %u", __FUNCTION__, GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_THREAD_ATTACH:		
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

		if (!sendDbgEvent(event, ack)) {

		}

		addThread(XDbgGetCurrentThreadId());
		// MYTRACE("%s(): process(%u) xdbg proxy attach thread. thread id: %u", __FUNCTION__,
		//	GetCurrentProcessId(), GetCurrentThreadId());
		break;

	case DLL_THREAD_DETACH:
		// MYTRACE("%s(): process(%u) xdbg proxy detach thread. thread id: %u", __FUNCTION__,
		//	GetCurrentProcessId(), GetCurrentThreadId());

		// REPORT ExitThread
		if (!_attached)
			return TRUE;
		msg.dwProcessId = XDbgGetCurrentProcessId();
		msg.dwThreadId = XDbgGetCurrentThreadId();
		msg.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
		if (!GetExitCodeThread(XDbgGetCurrentThread(), &msg.u.ExitThread.dwExitCode))
			msg.u.ExitThread.dwExitCode = 0;

		if (!sendDbgEvent(event, ack)) {
			
		}

		delThread(XDbgGetCurrentThreadId());
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
				MutexGuard guard(this);
				while (_pendingEvents.size() > 0) {
					DebugEventPacket& event = _pendingEvents.front();
					DebugAckPacket ack;
					if (!sendDbgEvent(event, ack)) {

					}

					if (event.event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
						free(event.event.u.LoadDll.lpImageName);
					}

					_pendingEvents.pop_front();
				}
			}

			Sleep(100);

		} else {

			if (!ConnectNamedPipe(_hPipe, NULL)) {
				if (GetLastError() == ERROR_PIPE_CONNECTED) {
					onDbgConnect();
					_attached = true;
					MyTrace("debugger attached");
				} else {
					MyTrace("%s(): ConnectNamedPipe(%p) failed. errCode: %d ", __FUNCTION__, _hPipe, GetLastError());
					assert(false);
					return -1;
				}

				Sleep(100);

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
	sendProcessInfo(ack.dwThreadId);
	sendThreadInfo();
	sendModuleInfo(ack.dwThreadId);
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
}

//////////////////////////////////////////////////////////////////////////
void XDbgProxy::registerRemoteApi()
{
	_apiHandlers[ID_ReadProcessMemory] = &XDbgProxy::ReadProcessMemory;
	_apiHandlers[ID_WriteProcessMemory] = &XDbgProxy::WriteProcessMemory;
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
			if (!ConnectNamedPipe(_hApiPipe, NULL)) {				
				if (GetLastError() != ERROR_PIPE_CONNECTED) {
					MyTrace("%s(): ConnectNamedPipe() failed.", __FUNCTION__);
					assert(false);
					return -1;
				} else {
					MyTrace("%s(): attached", __FUNCTION__);
					attached = true;
				}

			} else {
				MyTrace("%s(): attached", __FUNCTION__);
				attached = true;
			}
		}

		if (!recvApiCall(inPkt)) {
			assert(false);
			// return -1;
			attached = false;
			continue;
		}

		MyTrace("%s(): ApiCall: id = %d", __FUNCTION__, inPkt.apiId);

		RemoteApiHandlers::iterator it;
		it = _apiHandlers.find(inPkt.apiId);
		if (it == _apiHandlers.end()) {
			assert(false);
			// return -1;
			continue;
		}

		RemoteApiHandler handler = it->second;
		(this->*handler)(inPkt);
		MyTrace("%s(): ApiCall: id = %d completed", __FUNCTION__, inPkt.apiId);
	}

	return 0;
}

void XDbgProxy::ReadProcessMemory(ApiCallPacket& inPkt)
{
	MyTrace("%s()", __FUNCTION__);

	assert(inPkt.ReadProcessMemory.size <= MAX_MEMORY_BLOCK);

	PVOID addr = inPkt.ReadProcessMemory.addr;
	SIZE_T size = inPkt.ReadProcessMemory.size;

	ApiReturnPakcet outPkt;
	/*if (IsBadReadPtr(addr, size)) {
		outPkt.lastError = ERROR_INVALID_ADDRESS;
		outPkt.ReadProcessMemory.result = FALSE;
		sendApiReturn(outPkt);
		return;
	}*/

	outPkt.ReadProcessMemory.result = ::ReadProcessMemory(GetCurrentProcess(), addr, 
		outPkt.ReadProcessMemory.buffer, size, &outPkt.ReadProcessMemory.size);

	outPkt.lastError = GetLastError();	
	sendApiReturn(outPkt);
}

void XDbgProxy::WriteProcessMemory(ApiCallPacket& inPkt)
{
	MyTrace("%s()", __FUNCTION__);

	ApiReturnPakcet outPkt;

	PVOID addr = inPkt.WriteProcessMemory.addr;
	PUCHAR buffer = inPkt.WriteProcessMemory.buffer;
	SIZE_T size = inPkt.WriteProcessMemory.size;
	
	/* if (IsBadWritePtr(addr, size)) {
		outPkt.lastError = ERROR_INVALID_ADDRESS;
		outPkt.WriteProcessMemory.result = FALSE;
		sendApiReturn(outPkt);
		return;
	}

	memcpy(addr, buffer, size);

	outPkt.lastError = 0;
	outPkt.WriteProcessMemory.result = TRUE;
	outPkt.WriteProcessMemory.writtenSize = size;
	sendApiReturn(outPkt); */

	outPkt.WriteProcessMemory.result = ::WriteProcessMemory(GetCurrentProcess(), addr,
		buffer, size, &outPkt.WriteProcessMemory.writtenSize);

	outPkt.lastError = GetLastError();
	sendApiReturn(outPkt);
}
