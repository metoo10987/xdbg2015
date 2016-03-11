#pragma once

BOOL InitWin32ApiWrapper();

BOOL WINAPI XDbgReadFile(IN HANDLE hFile, IN LPVOID lpBuffer, IN DWORD nNumberOfBytesToRead,
	OUT LPDWORD lpNumberOfBytesRead OPTIONAL, IN LPOVERLAPPED lpOverlapped OPTIONAL);

BOOL WINAPI XDbgWriteFile(IN HANDLE hFile, IN LPCVOID lpBuffer, IN DWORD nNumberOfBytesToWrite OPTIONAL,
	OUT LPDWORD lpNumberOfBytesWritten OPTIONAL, IN LPOVERLAPPED lpOverlapped OPTIONAL);

DWORD WINAPI XDbgGetCurrentProcessId();
DWORD WINAPI XDbgGetCurrentThreadId();

DWORD WINAPI XDbgSuspendThread(IN HANDLE hThread);
DWORD WINAPI XDbgResumeThread(IN HANDLE hThread);
HANDLE WINAPI XDbgGetCurrentProcess();
HANDLE WINAPI XDbgGetCurrentThread();
BOOL WINAPI XDbgCloseHandle(HANDLE hObj);