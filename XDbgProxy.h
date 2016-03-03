#pragma once
class XDbgProxy
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
	LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	bool createPipe();

protected:
	HANDLE				_hPipe;
	EXCEPTION_RECORD	_lastException;
};
