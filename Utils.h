#pragma once

template <typename T1, typename T2>
inline void copyDbgRegs(T1& dest, const T2& src)
{
	dest.Dr0 = src.Dr0;
	dest.Dr1 = src.Dr1;
	dest.Dr2 = src.Dr2;
	dest.Dr3 = src.Dr3;
	dest.Dr6 = src.Dr6;
	dest.Dr7 = src.Dr7;
}

#ifdef _M_X64
#define CTX_PC_REG(CTX)		(CTX)->Rip
#else
#define CTX_PC_REG(CTX)		(CTX)->Eip
#endif // #ifdef _M_X64

void cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags);

bool LoadRemoteDll(DWORD pid, const char* dllPath);
BOOL injectDllByRemoteThread(DWORD pid, HMODULE hInst);
BOOL injectDllByWinHook(DWORD pid, HMODULE hInst);

typedef struct _UNICODE_STRING {
	USHORT  Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING, *PCUNICODE_STRING;

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

typedef ULONG KPRIORITY;

typedef struct _CLIENT_ID {
	ULONG_PTR   UniqueProcess;
	ULONG_PTR   UniqueThread;
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

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

PVOID WINAPI GetThreadStartAddress(HANDLE hThread);
PVOID WINAPI GetThreadStartAddress(DWORD tid);
DWORD WINAPI GetThreadIdFromHandle(HANDLE hThread, LPDWORD processId = NULL);
_TEB* GetThreadTeb(DWORD tid);
DWORD GetProcessMainThread(DWORD dwProcID);
DWORD WINAPI GetProcessIdFromHandle(HANDLE hProcess);
