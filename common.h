#pragma once
#include <string>

static inline std::string makePipeName(DWORD pid)
{
	char buf[256];
	sprintf_s(buf, "\\\\.\\pipe\\__XDBG__%u__", pid);
	return buf;
}

static inline std::string makeApiPipeName(DWORD pid)
{
	char buf[256];
	sprintf_s(buf, "\\\\.\\pipe\\__XDBGAPI__%u__", pid);
	return buf;
}

#define EVENT_MESSAGE_SIZE		sizeof(DebugEventPacket)
#define CONTINUE_MESSAGE_SIZE	sizeof(DebugAckPacket)

struct DebugEventPacket {	
	struct {
		DEBUG_EVENT		event;
		union {
			CONTEXT			ctx;
			// ANOTHER MEMBER;			
		};
	};	
};

struct DbgAttachArgs {
	UINT32	ignore_dbgstr;
	UINT32	inject_method;
	BOOL	createProcess;
};

struct DebugAckPacket {
	struct {
		DWORD	dwProcessId;
		DWORD	dwThreadId;
		DWORD	dwContinueStatus;
		union {
			struct {
				CONTEXT	ctx;
				DWORD	ContextFlags;
			};			

			// ANOTHER MEMBER;
			DbgAttachArgs	args;
		};
	};	
};

#define SINGLE_STEP_FLAG				0x100
#define DBG_PRINTEXCEPTION_WIDE_C		(0x4001000AL)

#define ATTACHED_EVENT	(RIP_EVENT + 1)
#define LAST_EVENT		ATTACHED_EVENT

//////////////////////////////////////////////////////////////////////////
// Remote API
#define MAX_MEMORY_BLOCK				(1024)

#define ID_ReadProcessMemory			(0x00000001)
#define ID_WriteProcessMemory			(0x00000002)
#define ID_SuspendThread				(0x00000004)
#define ID_ResumeThread					(0x00000008)
#define ID_VirtualQueryEx				(0x00000010)
#define ID_GetThreadContext				(0x00000020)
#define ID_SetThreadContext				(0x00000040)
#define ID_VirtualProtectEx				(0x00000080)
#define ID_VirtualAllocEx				(0x00000100)
#define ID_VirtualFreeEx				(0x00000200)
#define ID_GetModuleFileNameExW			(0x00000400)
#define ID_NtQueryInformationProcess	(0x00000800)

#define CALL_MESSAGE_SIZE		sizeof(ApiCallPacket)
#define RETURN_MESSAGE_SIZE		sizeof(ApiReturnPakcet)

struct ApiCallPacket {
	
	DWORD			apiId;

	union {
		struct {
			PVOID		addr;
			SIZE_T		size;
		} ReadProcessMemory;

		struct {
			PVOID		addr;
			UCHAR		buffer[MAX_MEMORY_BLOCK];
			SIZE_T		size;
		} WriteProcessMemory;

		struct  {
			DWORD		threadId;
		} SuspendThread;

		struct  {
			DWORD		threadId;
		} ResumeThread;

		struct {
			PVOID		addr;
		} VirtualQueryEx;

		struct {
			DWORD		threadId;
			DWORD		contextFlags;
		} GetThreadContext;

		struct {
			DWORD		threadId;
			CONTEXT		ctx;
		} SetThreadContext;

		struct {
			PVOID		addr;
			SIZE_T		size;
			DWORD		prot;
		} VirtualProtectEx;

		struct {
			PVOID		addr;
			SIZE_T		size;
			DWORD		type;
			DWORD		prot;
		} VirtualAllocEx;

		struct {
			PVOID		addr;
			SIZE_T		size;
			DWORD		type;
		} VirtualFreeEx;

		struct {
			HMODULE		hMod;
		} _GetModuleFileNameExW;
	};
};

struct ApiReturnPakcet {
	
	DWORD		lastError;
	union {
		struct  {
			BOOL		result;
			UCHAR		buffer[MAX_MEMORY_BLOCK];
			SIZE_T		size;
		} ReadProcessMemory;

		struct  {
			BOOL		result;
			SIZE_T		writtenSize;
		} WriteProcessMemory;

		struct  {
			DWORD		result;
		} SuspendThread;

		struct  {
			DWORD		result;
		} ResumeThread;

		struct {
			SIZE_T						result;
			MEMORY_BASIC_INFORMATION	memInfo;
		} VirtualQueryEx;

		struct {
			BOOL		result;
			CONTEXT		ctx;
		} GetThreadContext;

		struct {
			BOOL		result;
		} SetThreadContext;

		struct {
			BOOL		result;
			DWORD		oldProt;
		} VirtualProtectEx;

		struct {
			PVOID		result;
		} VirtualAllocEx;

		struct {
			BOOL		result;
		} VirtualFreeEx;

		struct {
			wchar_t		fileName[MAX_PATH];
			DWORD		result;
		} _GetModuleFileNameExW;
	};
};

//////////////////////////////////////////////////////////////////////////
