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

XDbgProxy::XDbgProxy(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
	memset(&_lastException, 0, sizeof(_lastException));
	_stopFlag = 0;
	_attached = false;

	_lastExceptCode = 0;
	_lastExceptAddr = 0;
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
	DEBUG_EVENT& msg = event.event;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = XDbgGetCurrentThreadId();

	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		msg.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
		msg.u.LoadDll.dwDebugInfoFileOffset = 0;
		msg.u.LoadDll.fUnicode = 1;
		msg.u.LoadDll.hFile = NULL;
		msg.u.LoadDll.lpBaseOfDll = NotificationData->Loaded.DllBase;
		msg.u.LoadDll.lpImageName = NotificationData->Loaded.FullDllName->Buffer;
		msg.u.LoadDll.nDebugInfoSize = 0;
	} else if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		msg.dwDebugEventCode = UNLOAD_DLL_DEBUG_EVENT;
		msg.u.UnloadDll.lpBaseOfDll = NotificationData->Unloaded.DllBase;
	} else
		return;
	
	DebugAckPacket ack;
	if (!sendDbgEvent(event, ack)) {

	}	
}

bool XDbgProxy::initialize()
{
	if (!InitWin32ApiWrapper()) {
		assert(false);
		return false;
	}

	if (!createPipe())
		return false;

	if (AddVectoredExceptionHandler(1, &XDbgProxy::_VectoredHandler) == NULL)
		return false;

	typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, PCLDR_DLL_NOTIFICATION_DATA, PVOID);
	typedef NTSTATUS (NTAPI *LdrRegDllNotifFunc)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID *);
	LdrRegDllNotifFunc LdrRegisterDllNotification = (LdrRegDllNotifFunc )GetProcAddress(
		GetModuleHandle("ntdll.dll"), "LdrRegisterDllNotification");
	if (LdrRegisterDllNotification) {
		PVOID cookie;
		if (LdrRegisterDllNotification(0, &XDbgProxy::_LdrDllNotification, NULL, &cookie) != 0) {
			// log error
			assert(false);			
		}
	}

	MyTrace("%s(): starting thread.", __FUNCTION__);
	if (!start()) {
		assert(false);
		return false;
	}
	
	return true;
}



LONG CALLBACK XDbgProxy::VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (!_attached)
		return EXCEPTION_CONTINUE_SEARCH;

	if (XDbgGetCurrentThreadId() == getId())
		return EXCEPTION_CONTINUE_SEARCH;

	if (threadIdToHandle(XDbgGetCurrentThreadId()) == NULL) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	DebugEventPacket event;
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

	return (_hPipe != INVALID_HANDLE_VALUE);
}

// SO, THIS MODULE MUST BE A DLL
BOOL XDbgProxy::DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	memset(&event, 0, sizeof(event));

	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;

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
			GetThreadStartAddress(GetCurrentThread());

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
		if (!GetExitCodeThread(GetCurrentThread(), &msg.u.ExitThread.dwExitCode))
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

			Sleep(200);

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
	clearThreads();
	addAllThreads(XDbgGetCurrentThreadId());
	suspendAll(XDbgGetCurrentThreadId());

	DebugEventPacket event;
	DebugAckPacket ack;
	event.event.dwProcessId = GetCurrentProcessId();
	event.event.dwThreadId = GetCurrentThreadId();
	event.event.dwDebugEventCode = ATTACHED_EVENT;
	sendDbgEvent(event, ack, false);
	sendProcessInfo();
	sendThreadInfo();
	sendModuleInfo();
	resumeAll(XDbgGetCurrentThreadId());
}

void XDbgProxy::onDbgDisconnect()
{

}

void XDbgProxy::sendProcessInfo()
{
	MyTrace("%s()", __FUNCTION__);
	DebugEventPacket event;
	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = getFirstThread();

	char modName[MAX_PATH + 1];

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
	msg.u.CreateProcessInfo.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(getFirstThread());
	MyTrace("%s(): main thread start at: %p", __FUNCTION__, msg.u.CreateProcessInfo.lpStartAddress);
	msg.u.CreateProcessInfo.lpThreadLocalBase = GetThreadTeb(getFirstThread());
	msg.u.CreateProcessInfo.nDebugInfoSize = 0;
	sendDbgEvent(event, ack, false);
}

void XDbgProxy::sendModuleInfo()
{
	MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
	DEBUG_EVENT& msg = event.event;
	DebugAckPacket ack;

	msg.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
	msg.dwProcessId = XDbgGetCurrentProcessId();
	msg.dwThreadId = getFirstThread();

	char modName[MAX_PATH + 1];

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
	if (!EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &len)) {
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
		GetModuleFileName(hModules[i], modName, MAX_PATH);
		msg.u.LoadDll.lpImageName = modName;
		sendDbgEvent(event, ack, false);
		MyTrace("%s(): module: %s, %p", __FUNCTION__, modName, msg.u.LoadDll.lpBaseOfDll);
	}
}

void XDbgProxy::sendThreadInfo()
{
	MyTrace("%s()", __FUNCTION__);

	DebugEventPacket event;
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
