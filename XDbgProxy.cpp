#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>

#include "XDbgProxy.h"
#include "common.h"
#include <assert.h>

XDbgProxy::XDbgProxy(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
	memset(&_lastException, 0, sizeof(_lastException));
	_stopFlag = 0;
	_initOK = false;
}


XDbgProxy::~XDbgProxy(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);
}

void XDbgProxy::postMsg(DEBUG_EVENT& event)
{
	MutexGuard guard(&_mutex);
	_events.push_back(event);
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
	
	DWORD len;
	if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
		// log error
		return;
	}

	CONTINUE_DEBUG_EVENT ack;
	if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
		// log error
		return;
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
	if (!_initOK)
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

	DWORD len;
	if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
		// log error
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CONTINUE_DEBUG_EVENT ack;
	if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
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

PVOID WINAPI GetThreadStartAddress(HANDLE hThread)
{
    NTSTATUS ntStatus;
    HANDLE hDupHandle;
    PVOID dwStartAddress;

	typedef NTSTATUS (NTAPI* pNtQIT)(HANDLE ThreadHandle, LONG ThreadInformationClass, PVOID ThreadInformation, 
		ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL);

	static pNtQIT NtQueryInformationThread = NULL;
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

// SO, THIS MODULE MUST BE A DLL
BOOL XDbgProxy::DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	// IMPL ME: 
	DEBUG_EVENT msg;
	DWORD len;
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		memset(&msg.u.CreateProcessInfo, 0, sizeof(msg.u.CreateProcessInfo));
		msg.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
		msg.u.CreateProcessInfo.dwDebugInfoFileOffset = 0;
		msg.u.CreateProcessInfo.fUnicode = 0;
		msg.u.CreateProcessInfo.hFile = NULL;
		msg.u.CreateProcessInfo.hProcess = NULL;
		msg.u.CreateProcessInfo.hThread = NULL;
		msg.u.CreateProcessInfo.lpBaseOfImage = (PVOID )GetModuleHandle(NULL);
		msg.u.CreateProcessInfo.lpImageName = "ExeFile";
		msg.u.CreateProcessInfo.lpStartAddress = (LPTHREAD_START_ROUTINE )GetThreadStartAddress(GetCurrentThread());
		msg.u.CreateProcessInfo.lpThreadLocalBase = NtCurrentTeb();
		msg.u.CreateProcessInfo.nDebugInfoSize = 0;
		postMsg(msg);

		MyTrace("%s(): process attached", __FUNCTION__);		
		break;

	case DLL_PROCESS_DETACH:
		// DO NOTHING
		break;

	case DLL_THREAD_ATTACH:
		return TRUE;
		if (!_initOK)
			return TRUE;
		// REPORT CreateThread
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
		msg.u.CreateThread.hThread = GetCurrentThread();
		msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE )GetThreadStartAddress(GetCurrentThread());
		msg.u.CreateThread.lpThreadLocalBase = NtCurrentTeb();
				
		if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
			// log error
			return TRUE;
		}

		CONTINUE_DEBUG_EVENT ack;
		if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
			// log error
			return TRUE;
		}

		break;

	case DLL_THREAD_DETACH:
		// REPORT ExitThread
		if (!_initOK)
			return TRUE;
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
		if (GetExitCodeThread(GetCurrentThread(), &msg.u.ExitThread.dwExitCode)) {
						
			if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
				// log error
				return TRUE;
			}

			CONTINUE_DEBUG_EVENT ack;
			if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
				// log error
				return TRUE;
			}
		}

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
		if (!ConnectNamedPipe(_hPipe, NULL)) {
			if (GetLastError() !=  ERROR_PIPE_CONNECTED) {
				MyTrace("%s(): ConnectNamedPipe(%p) failed. errCode: %d ", __FUNCTION__, _hPipe, GetLastError());
				assert(false);
				return -1;
			}
			_initOK = false;

		} else {

			MyTrace("debugger connected");			
		}

		{
			MutexGuard guard(&_mutex);
			while (_events.size() > 0) {				

				DEBUG_EVENT& msg = _events.front();
				DWORD len;
				if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
					// log error
					break;
				}

				CONTINUE_DEBUG_EVENT ack;
				if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
					// log error
					break;
				}

				_events.pop_front();

				if (msg.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
					_initOK = true;
					DebugBreak();
				}
			}
		}

		Sleep(100);
	}

	return 0;
}
