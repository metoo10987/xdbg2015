#include <Windows.h>
#include "XDbgProxy.h"
#include "common.h"

XDbgProxy::XDbgProxy(void)
{
	_hPipe = INVALID_HANDLE_VALUE;
	_lastException = NULL;
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

	return AddVectoredExceptionHandler(1, &XDbgProxy::_VectoredHandler) != NULL;
}

LONG CALLBACK XDbgProxy::_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	return XDbgProxy::instance().VectoredHandler(ExceptionInfo);
}

LONG CALLBACK XDbgProxy::VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	DEBUG_EVENT msg;
	msg.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
	msg.dwProcessId = GetCurrentProcessId();
	msg.dwThreadId = GetCurrentThreadId();
	msg.u.Exception.dwFirstChance = _lastException != ExceptionInfo->ExceptionRecord;
	msg.u.Exception.ExceptionRecord = *ExceptionInfo->ExceptionRecord;
	// info.ContextRecord = *ExceptionInfo->ContextRecord;
	// info.ExceptionRecord = *ExceptionInfo->ExceptionRecord;
	_lastException = ExceptionInfo->ExceptionRecord;

	DWORD len;
	if (!WriteFile(_hPipe, &msg, sizeof(msg), &len, NULL)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CONTINUE_DEBUG_EVENT ack;
	if (!ReadFile(_hPipe, &ack, sizeof(ack), &len, NULL)) {
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

BOOL XDbgProxy::DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	// IMPL ME: 
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	};

	return 0;
}
