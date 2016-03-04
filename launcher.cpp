// launcher.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <windows.h>
#include "detours.h"
#include <stdio.h>


void EnableDebugPrivilege()
{ 

	HANDLE Token;  
	TOKEN_PRIVILEGES tp;      
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{ 
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);     
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
		AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL);    
	}      
}

bool LoadRemoteDll(DWORD pid, const char* dllPath)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProc == NULL)
		return false;

	PVOID p = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	DWORD l;
	BOOL r = WriteProcessMemory(hProc, p, dllPath, strlen(dllPath) + 1, &l);

	if (!r) {

		VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, 
		(LPTHREAD_START_ROUTINE )GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA"), 
		p, 0, &l);

	VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);

	if (hThread == NULL) {

		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &l);
	CloseHandle(hThread);
	return l != 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	// EnableDebugPrivilege();
	// LoadRemoteDll(5804, "xdbgcore.dll");
	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	
	PROCESS_INFORMATION pi;

	if (!DetourCreateProcessWithDll(NULL, argv[1], NULL, NULL, FALSE, 0, NULL, NULL, 
		&si, &pi, "xdbgcore.dll", NULL)) {

		printf("failed!\n");
	}

	return 0;
}

