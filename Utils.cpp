#include <Windows.h>
#include "Utils.h"
#include "common.h"

#include "Win32ApiWrapper.h"
#include <tlhelp32.h>
#include <Psapi.h>
#include <assert.h>

bool LoadRemoteDll(DWORD pid, const char* dllPath)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProc == NULL)
		return false;

	PVOID p = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	SIZE_T l;
	BOOL r = WriteProcessMemory(hProc, p, dllPath, strlen(dllPath) + 1, &l);

	if (!r) {

		VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);
		return false;
	}

	DWORD tid;
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA"),
		p, 0, &tid);

	VirtualFreeEx(hProc, p, strlen(dllPath) + 1, MEM_RELEASE);

	if (hThread == NULL) {

		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);
	return exitCode != 0;
}

BOOL injectDll(DWORD pid, HMODULE hInst)
{
	char dllPath[MAX_PATH];
	if (!GetModuleFileName((HMODULE)hInst, dllPath, sizeof(dllPath) - 1)) {
		assert(false);
		return FALSE;
	}

	if (!LoadRemoteDll(pid, dllPath)) {
		assert(false);
		MyTrace("injectDll(%u) failed", pid);
		return FALSE;
	}

	return TRUE;
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
		NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"),
		"NtQueryInformationThread");

	if (NtQueryInformationThread == NULL) {
		MyTrace("%s(): cannot found NtQueryInformationThread()", __FUNCTION__);
		return 0;
	}

	HANDLE hCurrentProcess = GetCurrentProcess();
	if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
		SetLastError(ERROR_ACCESS_DENIED);
		MyTrace("%s(): cannot found open thread", __FUNCTION__);
		return 0;
	}

	UINT32 ThreadQuerySetWin32StartAddress = 9;
	ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, 
		sizeof(PVOID), NULL);
	XDbgCloseHandle(hDupHandle);
	if (ntStatus != 0) {
		MyTrace("%s(): NtQueryInformationThread() failed. status: %x, threadHandle: %x, threadId: %d", 
			__FUNCTION__, ntStatus, hThread, GetThreadId(hThread));
		return 0;
	}

	return dwStartAddress;
}

PVOID WINAPI GetThreadStartAddress(DWORD tid)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	PVOID addr = GetThreadStartAddress(hThread);
	XDbgCloseHandle(hThread);
	return addr;
}

_TEB* GetThreadTeb(DWORD tid)
{
	NTSTATUS ntStatus;
	if (NtQueryInformationThread == NULL)
		NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"),
		"NtQueryInformationThread");

	if (NtQueryInformationThread == NULL) {
		MyTrace("%s(): cannot found NtQueryInformationThread()", __FUNCTION__);
		return 0;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	UINT32 ThreadBasicInformation = 0;
	THREAD_BASIC_INFORMATION bi;
	ntStatus = NtQueryInformationThread(hThread, ThreadBasicInformation, &bi, sizeof(bi), NULL);
	XDbgCloseHandle(hThread);
	if (ntStatus != 0)
		return 0;

	return (_TEB*)bi.TebBaseAddress;
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

#ifdef _M_X64
void cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags)
{
	// NO IMPLEMENTATION
	assert(false);
}

#else
void cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags)
{
	// no extended registers && floating point registers

	if ((ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		/* EBP, EIP and EFLAGS */
		dest->Ebp = src->Ebp;
		dest->Eip = src->Eip;
		dest->EFlags = src->EFlags;
		dest->SegCs = src->SegCs;
		dest->SegSs = src->SegSs;
		dest->Esp = src->Esp;
	}

	if ((ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
		dest->SegGs = src->SegGs;
		dest->SegFs = src->SegFs;
		dest->SegEs = src->SegEs;
		dest->SegDs = src->SegDs;
	}

	if ((ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
		dest->Eax = src->Eax;
		dest->Ebx = src->Ebx;
		dest->Ecx = src->Ecx;
		dest->Edx = src->Edx;
		dest->Esi = src->Esi;
		dest->Edi = src->Edi;
	}

	if ((ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
		dest->Dr0 = src->Dr0;
		dest->Dr1 = src->Dr1;
		dest->Dr2 = src->Dr2;
		dest->Dr3 = src->Dr3;
		dest->Dr6 = src->Dr6;
		dest->Dr7 = src->Dr7;
	}
}
#endif

DWORD WINAPI GetThreadIdFromHandle(HANDLE hThread)
{
	NTSTATUS ntStatus;
	if (NtQueryInformationThread == NULL)
		NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"),
		"NtQueryInformationThread");

	if (NtQueryInformationThread == NULL) {
		MyTrace("%s(): cannot found NtQueryInformationThread()", __FUNCTION__);
		return 0;
	}

	HANDLE hThread2;
	if (!DuplicateHandle(GetCurrentProcess(), hThread, GetCurrentProcess(), &hThread2, 
		THREAD_ALL_ACCESS, FALSE, 0))
		return 0;

	UINT32 ThreadBasicInformation = 0;
	THREAD_BASIC_INFORMATION bi;
	ntStatus = NtQueryInformationThread(hThread2, ThreadBasicInformation, &bi, sizeof(bi), NULL);
	CloseHandle(hThread2);
	if (ntStatus != 0)
		return 0;

	return bi.ClientId.UniqueThread;
}
