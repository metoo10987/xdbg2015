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

BOOL injectDllByRemoteThread(DWORD pid, HMODULE hInst)
{
	char dllPath[MAX_PATH];
	if (!GetModuleFileName((HMODULE)hInst, dllPath, sizeof(dllPath) - 1)) {
		assert(false);
		return FALSE;
	}

	if (!LoadRemoteDll(pid, dllPath)) {
		// assert(false);
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
	CloseHandle(hDupHandle);
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
	CloseHandle(hThread);
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
	if ((ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
	{
		dest->Rax = src->Rax;
		dest->Rbx = src->Rbx;
		dest->Rcx = src->Rcx;
		dest->Rdx = src->Rdx;
		dest->Rsi = src->Rsi;
		dest->Rdi = src->Rdi;
		dest->Rbp = src->Rbp;
		dest->R8 = src->R8;
		dest->R9 = src->R9;
		dest->R10 = src->R10;
		dest->R11 = src->R11;
		dest->R12 = src->R12;
		dest->R13 = src->R13;
		dest->R14 = src->R14;
		dest->R15 = src->R15;
	}

	if ((ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
		dest->Xmm0 = src->Xmm0;
		dest->Xmm1 = src->Xmm1;
		dest->Xmm2 = src->Xmm2;
		dest->Xmm3 = src->Xmm3;
		dest->Xmm4 = src->Xmm4;
		dest->Xmm5 = src->Xmm5;
		dest->Xmm6 = src->Xmm6;
		dest->Xmm7 = src->Xmm7;
		dest->Xmm8 = src->Xmm8;
		dest->Xmm9 = src->Xmm9;
		dest->Xmm10 = src->Xmm10;
		dest->Xmm11 = src->Xmm11;
		dest->Xmm12 = src->Xmm12;
		dest->Xmm13 = src->Xmm13;
		dest->Xmm14 = src->Xmm14;
		dest->Xmm15 = src->Xmm15;

		dest->MxCsr = src->MxCsr;
		dest->FltSave.MxCsr = src->FltSave.MxCsr;
		dest->FltSave.ControlWord = src->FltSave.ControlWord;
	}

	if ((ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		/* EBP, EIP and EFLAGS */
		dest->Rbp = src->Rbp;
		dest->Rip = src->Rip;
		dest->EFlags = src->EFlags;
		dest->SegCs = src->SegCs;
		dest->SegSs = src->SegSs;
		dest->Rsp = src->Rsp;
	}

	if ((ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
		dest->SegGs = src->SegGs;
		dest->SegFs = src->SegFs;
		dest->SegEs = src->SegEs;
		dest->SegDs = src->SegDs;
	}

	if ((ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
		dest->Dr0 = src->Dr0;
		dest->Dr1 = src->Dr1;
		dest->Dr2 = src->Dr2;
		dest->Dr3 = src->Dr3;
		dest->Dr6 = src->Dr6;
		dest->Dr7 = src->Dr7;

		dest->LastBranchToRip = src->LastBranchToRip;
		dest->LastBranchFromRip = src->LastBranchFromRip;
		dest->LastExceptionToRip = src->LastExceptionToRip;
		dest->LastExceptionFromRip = src->LastExceptionFromRip;
	}
	
}

#else // #ifdef _M_X64

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

	if ((ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
		dest->FloatSave = src->FloatSave;
	}

	if ((ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS) {
		memcpy(dest->ExtendedRegisters, src->ExtendedRegisters, sizeof(src->ExtendedRegisters));
	}
}

#endif // #ifdef _M_X64

DWORD WINAPI GetThreadIdFromHandle(HANDLE hThread, LPDWORD processId)
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

	if (processId)
		*processId = bi.ClientId.UniqueProcess;

	return (DWORD )bi.ClientId.UniqueThread;
}

typedef NTSTATUS(NTAPI* pNtQIT)(HANDLE ProcessHandle, LONG ThreadInformationClass, PVOID ThreadInformation,
	ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL);

static pNtQIT NtQueryInformationProcess = NULL;

DWORD WINAPI GetProcessIdFromHandle(HANDLE hProcess)
{
	NTSTATUS ntStatus;
	if (NtQueryInformationProcess == NULL)
		NtQueryInformationProcess = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"),
		"NtQueryInformationProcess");

	if (NtQueryInformationProcess == NULL) {
		MyTrace("%s(): cannot found NtQueryInformationThread()", __FUNCTION__);
		return 0;
	}

	HANDLE hProcess2;
	if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hProcess2,
		PROCESS_ALL_ACCESS, FALSE, 0))
		return 0;

	UINT32 ProcessBasicInformation = 0;
	PROCESS_BASIC_INFORMATION bi;
	ntStatus = NtQueryInformationProcess(hProcess2, ProcessBasicInformation, &bi, sizeof(bi), NULL);
	CloseHandle(hProcess2);
	if (ntStatus != 0)
		return 0;

	return (DWORD)bi.UniqueProcessId;
}

struct EnumParam {
	DWORD		pid;
	HWND*		result;
	DWORD*		threadId;
};

static BOOL CALLBACK __EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	EnumParam* param = (EnumParam* )lParam;
	DWORD dwProcessId;
	DWORD threadId = GetWindowThreadProcessId(hwnd, &dwProcessId);
	if (dwProcessId == param->pid) {
		*param->result = hwnd;
		*param->threadId = threadId;
		return FALSE;
	}

	return TRUE;
}

HWND getWinFromPid(DWORD pid, DWORD* threadId)
{
	HWND result = NULL;
	DWORD tid = 0;
	EnumParam param;
	param.pid = pid;
	param.result = &result;
	param.threadId = &tid;
	EnumWindows(__EnumWindowsProc, (LPARAM )&param);
	if (tid)
		*threadId = tid;
	return result;
}


//////////////////////////////////////////////////////////////////////////
//#pragma data_seg(".shared")
//HHOOK callWndhookHandle = NULL;
//#pragma data_seg()
//#pragma comment(linker,"/SECTION:.shared,RWS")

#define HOOK_RESPONSE_MAGIC		(0x12345678)
LRESULT CALLBACK CallWndRetHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// PCWPRETSTRUCT param = (PCWPRETSTRUCT)lParam;
	LRESULT r = CallNextHookEx(NULL, nCode, wParam, lParam);
	// UnhookWindowsHookEx(callWndhookHandle);
	return r;
}

BOOL injectDllByWinHook(DWORD pid, HMODULE hInst)
{
	DWORD threadId;
	HWND hWnd = getWinFromPid(pid, &threadId);
	if (hWnd && threadId) {
		HHOOK callWndhookHandle = SetWindowsHookEx(WH_CALLWNDPROCRET, CallWndRetHookProc, hInst, threadId);
		SendMessage(hWnd, WM_NULL, 0, 0);
		UnhookWindowsHookEx(callWndhookHandle);
		return TRUE;
	} else
		return FALSE;
}
