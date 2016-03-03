#include <tchar.h>
#include <Windows.h>
#include <WinNT.h>

#include "XDbgProxy.h"
#include "common.h"

XDbgProxy::XDbgProxy(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
	memset(&_lastException, 0, sizeof(_lastException));
}


XDbgProxy::~XDbgProxy(void)
{
	if (_hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(_hPipe);
}

bool XDbgProxy::initialize()
{
	if (!createPipe())
		return false;

	// TODO: HOOK LdrLoadDll & LdrUnloadDll[DONT WORK];
	// TODO: HOOK NtMapViewOfSection & NtUnmapViewOfSection, CHECK DLL LIST WHEN THE SYSCALL RETURNED

	return AddVectoredExceptionHandler(1, &XDbgProxy::_VectoredHandler) != NULL;
}

LONG CALLBACK XDbgProxy::_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	return XDbgProxy::instance().VectoredHandler(ExceptionInfo);
}


LONG CALLBACK XDbgProxy::VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
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
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		// DO NOTHING
		break;

	case DLL_PROCESS_DETACH:
		// DO NOTHING
		break;

	case DLL_THREAD_ATTACH:
		// REPORT CreateThread
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
		msg.u.CreateThread.hThread = GetCurrentThread();
		msg.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE )GetThreadStartAddress(GetCurrentThread());
		msg.u.CreateThread.lpThreadLocalBase = NtCurrentTeb();

		DWORD len;
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
		msg.dwProcessId = GetCurrentProcessId();
		msg.dwThreadId = GetCurrentThreadId();
		msg.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
		if (GetExitCodeThread(GetCurrentThread(), &msg.u.ExitThread.dwExitCode)) {

			DWORD len;
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
