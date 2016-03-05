#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>
#include <tlhelp32.h>
#include <Psapi.h>

#include "XDbgProxy.h"
#include "common.h"
#include <assert.h>

XDbgProxy::XDbgProxy(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
	memset(&_lastException, 0, sizeof(_lastException));
	_stopFlag = 0;
	_attached = false;
}


XDbgProxy::~XDbgProxy(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);
}

BOOL XDbgProxy::sendDbgEvent(const DEBUG_EVENT& event)
{
	DWORD len;
	if (!WriteFile(_hPipe, &event, sizeof(event), &len, NULL)) {
		// log error
		return FALSE;
	}

	return TRUE;
}

BOOL XDbgProxy::recvDbgAck(struct CONTINUE_DEBUG_EVENT& ack)
{
	DWORD len;
	if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		// log error
		return FALSE;
	}

	return TRUE;
}

BOOL XDbgProxy::sendDbgEvent(const DEBUG_EVENT& event, struct CONTINUE_DEBUG_EVENT& ack)
{
	if (!sendDbgEvent(event))
		return FALSE;

	return recvDbgAck(ack);
}

void XDbgProxy::postDbgEvent(const DEBUG_EVENT& event)
{
	MutexGuard guard(&_mutex);
	_events.push_back(event);
}

bool XDbgProxy::addThread(DWORD tid)
{
	_threads[tid] = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	return true;
}

bool XDbgProxy::delThread(DWORD tid)
{
	_threads.erase(tid);
	return true;
}

void XDbgProxy::suspendThreads(DWORD tid)
{
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		if (it->first == tid)
			continue;
		SuspendThread(it->second);
	}
}

void XDbgProxy::resumeThread(DWORD tid)
{
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		if (it->first == tid)
			continue;
		ResumeThread(it->second);
	}
}

LONG CALLBACK XDbgProxy::_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	return XDbgProxy::instance().VectoredHandler(ExceptionInfo);
}

typedef struct _UNICODE_STRING {
  USHORT  Length;     //UNICODE占用的内存字节数，个数*2；
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING ,*PUNICODE_STRING, *PCUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA, *PCLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED		1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED	2

VOID CALLBACK XDbgProxy::_LdrDllNotification(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, 
	PVOID Context)
{
	XDbgProxy::instance().LdrDllNotification(NotificationReason, NotificationData, Context);
}

VOID CALLBACK XDbgProxy::LdrDllNotification(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, 
	PVOID Context)
{
	DEBUG_EVENT msg;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = GetCurrentThreadId();

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
	}
	
	CONTINUE_DEBUG_EVENT ack;
	if (!sendDbgEvent(msg, ack)) {

	}	
}

bool XDbgProxy::initialize()
{
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
	printf("%s, code: %x\n", __FUNCTION__, ExceptionInfo->ExceptionRecord->ExceptionCode);
	if (!_attached)
		return EXCEPTION_CONTINUE_SEARCH;

	if (GetCurrentThreadId() == getId())
		return EXCEPTION_CONTINUE_SEARCH;

	DEBUG_EVENT msg;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = GetCurrentThreadId();

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C) {
		msg.dwDebugEventCode = OUTPUT_DEBUG_STRING_EVENT;
		msg.u.DebugString.fUnicode = 0;
		msg.u.DebugString.nDebugStringLength = (WORD )ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
		msg.u.DebugString.lpDebugStringData = (LPSTR )ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	} else {

		msg.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
		if (_lastException.ExceptionCode == ExceptionInfo->ExceptionRecord->ExceptionCode && 
			_lastException.ExceptionAddress == ExceptionInfo->ExceptionRecord->ExceptionAddress) {
			msg.u.Exception.dwFirstChance = 0;
		} else {
			msg.u.Exception.dwFirstChance = 1;
		}

		msg.u.Exception.ExceptionRecord = *ExceptionInfo->ExceptionRecord;
		_lastException = *ExceptionInfo->ExceptionRecord;
	}

	CONTINUE_DEBUG_EVENT ack;
	if (!sendDbgEvent(msg, ack)) {
		// log error
		return EXCEPTION_CONTINUE_SEARCH;
	}
	
	if (ack.dwContinueStatus == DBG_CONTINUE)
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

bool XDbgProxy::createPipe()
{
	std::string name = makePipeName(GetCurrentProcessId());	
	_hPipe = ::CreateNamedPipe(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
		PIPE_UNLIMITED_INSTANCES, EVENT_MESSAGE_SIZE, CONTINUE_MESSAGE_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);

	return (_hPipe != INVALID_HANDLE_VALUE);
}

typedef NTSTATUS(NTAPI* pNtQIT)(HANDLE ThreadHandle, LONG ThreadInformationClass, PVOID ThreadInformation,
	ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL);

static pNtQIT NtQueryInformationThread = NULL;

PVOID WINAPI GetThreadStartAddress(HANDLE hThread)
{
    NTSTATUS ntStatus;
    HANDLE hDupHandle;
    PVOID dwStartAddress;
		
	if (NtQueryInformationThread == NULL)
		pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

    if(NtQueryInformationThread == NULL) 
        return 0;

    HANDLE hCurrentProcess = GetCurrentProcess();
    if(!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
        SetLastError(ERROR_ACCESS_DENIED);

        return 0;
    }
	
	UINT32 ThreadQuerySetWin32StartAddress = 9;
    ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(PVOID), NULL);
    CloseHandle(hDupHandle);
    if(ntStatus != 0) 
       return 0;

    return dwStartAddress;
}

PVOID WINAPI GetThreadStartAddress(DWORD tid)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	PVOID addr = GetThreadStartAddress(hThread);
	CloseHandle(hThread);
	return addr;
}

typedef ULONG KPRIORITY;

typedef struct _CLIENT_ID {
	DWORD   UniqueProcess;
	DWORD   UniqueThread;
} CLIENT_ID;
typedef   CLIENT_ID   *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

_TEB* GetThreadTeb(DWORD tid)
{
	NTSTATUS ntStatus;
	if (NtQueryInformationThread == NULL)
		pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

	if (NtQueryInformationThread == NULL)
		return 0;

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	UINT32 ThreadBasicInformation = 0;
	THREAD_BASIC_INFORMATION bi;
	ntStatus = NtQueryInformationThread(hThread, ThreadBasicInformation, &bi, sizeof(bi), NULL);
	CloseHandle(hThread);
	if (ntStatus != 0)
		return 0;

	return (_TEB* )bi.TebBaseAddress;
}

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

DWORD GetProcessMainThread(DWORD dwProcID)
{
	DWORD dwMainThreadID = 0;
	ULONGLONG ullMinCreateTime = MAXULONGLONG;

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 th32;
		th32.dwSize = sizeof(THREADENTRY32);
		BOOL bOK = TRUE;
		for (bOK = Thread32First(hThreadSnap, &th32); bOK;
			bOK = Thread32Next(hThreadSnap, &th32)) {
			if (th32.th32OwnerProcessID == dwProcID) {
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
					TRUE, th32.th32ThreadID);
				if (hThread) {
					FILETIME afTimes[4] = { 0 };
					if (GetThreadTimes(hThread,
						&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
						ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
							afTimes[0].dwHighDateTime);
						if (ullTest && ullTest < ullMinCreateTime) {
							ullMinCreateTime = ullTest;
							dwMainThreadID = th32.th32ThreadID; // let it be main... :)
						}
					}
					CloseHandle(hThread);
				}
			}
		}

		CloseHandle(hThreadSnap);
	}

	return (dwMainThreadID);
}

// SO, THIS MODULE MUST BE A DLL
BOOL XDbgProxy::DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	DEBUG_EVENT msg;
	CONTINUE_DEBUG_EVENT ack;

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		_mainThreadId = GetProcessMainThread(GetCurrentProcessId());
		_mainThreadTeb = GetThreadTeb(_mainThreadId);
		MyTrace("%s(): process(%u) xdbg proxy loaded. thread id: %u", __FUNCTION__, GetCurrentProcessId(), _mainThreadId);
		break;

	case DLL_PROCESS_DETACH:
		MyTrace("%s(): process(%u) xdbg proxy unloaded. thread id: %u", __FUNCTION__, GetCurrentProcessId(), _mainThreadId);
		break;

	case DLL_THREAD_ATTACH:
		if (!_attached)
			return TRUE;
		// REPORT CreateThread
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
		msg.u.CreateThread.hThread = NULL;
		msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE )GetThreadStartAddress(GetCurrentThread());
		msg.u.CreateThread.lpThreadLocalBase = NtCurrentTeb();

		if (!sendDbgEvent(msg, ack)) {

		}

		addThread(GetCurrentThreadId());

		break;

	case DLL_THREAD_DETACH:
		// REPORT ExitThread
		if (!_attached)
			return TRUE;
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
		if (!GetExitCodeThread(GetCurrentThread(), &msg.u.ExitThread.dwExitCode))
			msg.u.ExitThread.dwExitCode = 0;

		if (!sendDbgEvent(msg, ack)) {
			
		}

		delThread(GetCurrentThreadId());
		break;
	};

	return TRUE;
}

long XDbgProxy::run()
{
	MyTrace("XDBG Thread started");

	while (!_stopFlag) {
		if (!ConnectNamedPipe(_hPipe, NULL)) {
			if (GetLastError() ==  ERROR_PIPE_CONNECTED) {
				break;
			} else {
				MyTrace("%s(): ConnectNamedPipe(%p) failed. errCode: %d ", __FUNCTION__, _hPipe, GetLastError());
				assert(false);
				return -1;
			}
		} else {
			MyTrace("debugger connected");
			break;
		}
	}

	while (!_stopFlag) {

		if (_attached) {

			MutexGuard guard(&_mutex);
			while (_events.size() > 0) {

				DEBUG_EVENT& msg = _events.front();
				if (!sendDbgEvent(msg)) {				
					_attached = false;
					_events.clear();
					onDbgDisconnect();
					break;
				}

				CONTINUE_DEBUG_EVENT ack;
				if (!recvDbgAck(ack)) {
					_attached = false;
					_events.clear();
					onDbgDisconnect();
					break;
				}

				_events.pop_front();
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

				Sleep(200);

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
	sendProcessInfo();
	sendThreadInfo();
	sendModuleInfo();
}

void XDbgProxy::onDbgDisconnect()
{

}

void XDbgProxy::sendProcessInfo()
{
	MyTrace("%s()", __FUNCTION__);
	DEBUG_EVENT msg;
	CONTINUE_DEBUG_EVENT ack;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = _mainThreadId;
	memset(&msg.u.CreateProcessInfo, 0, sizeof(msg.u.CreateProcessInfo));
	msg.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
	msg.u.CreateProcessInfo.dwDebugInfoFileOffset = 0;
	msg.u.CreateProcessInfo.fUnicode = 0;
	msg.u.CreateProcessInfo.hFile = NULL;
	msg.u.CreateProcessInfo.hProcess = NULL;
	msg.u.CreateProcessInfo.hThread = NULL;
	msg.u.CreateProcessInfo.lpBaseOfImage = (PVOID )GetModuleHandle(NULL);
	msg.u.CreateProcessInfo.lpImageName = NULL;
	msg.u.CreateProcessInfo.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(_mainThreadId);
	msg.u.CreateProcessInfo.lpThreadLocalBase = _mainThreadTeb;
	msg.u.CreateProcessInfo.nDebugInfoSize = 0;
	sendDbgEvent(msg, ack);
}

void XDbgProxy::sendModuleInfo()
{
	MyTrace("%s()", __FUNCTION__);

	DEBUG_EVENT msg;
	CONTINUE_DEBUG_EVENT ack;

	HMODULE hModules[512];
	DWORD len;
	if (!EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &len)) {
		// log error
		assert(false);
		return;
	}

	msg.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = _mainThreadId;

	char modName[MAX_PATH + 1];

	len /= sizeof(HMODULE);
	for (DWORD i = 0; i < len; i++) {
		msg.u.LoadDll.dwDebugInfoFileOffset = 0;
		msg.u.LoadDll.fUnicode = 0;
		msg.u.LoadDll.hFile = NULL;
		msg.u.LoadDll.lpBaseOfDll = hModules[i];
		GetModuleFileName(hModules[i], modName, MAX_PATH);
		msg.u.LoadDll.lpImageName = modName;
		sendDbgEvent(msg, ack);
	}
}

void XDbgProxy::sendThreadInfo()
{
	MyTrace("%s()", __FUNCTION__);

	DEBUG_EVENT msg;
	CONTINUE_DEBUG_EVENT ack;

	msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
	msg.dwProcessId = GetCurrentProcessId();
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(hSnapshot, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {

					if (te.th32ThreadID == getId())
						continue; // skip xdbg thread;
					msg.dwThreadId = te.th32ThreadID;
					msg.u.CreateThread.hThread = NULL;
					msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(GetCurrentThread());
					msg.u.CreateThread.lpThreadLocalBase = GetThreadTeb(te.th32ThreadID);
					addThread(te.th32ThreadID);
					sendDbgEvent(msg, ack);
				}

				te.dwSize = sizeof(te);
			} while (Thread32Next(hSnapshot, &te));
		}

		CloseHandle(hSnapshot);
	}
}
