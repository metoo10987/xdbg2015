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

	// TODO: Add loadddll, unloaddll, outputdubgstr event

protected:
	static LONG CALLBACK _VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
	bool createPipe();

protected:
	HANDLE				_hPipe;
	PEXCEPTION_RECORD	_lastException;
};
