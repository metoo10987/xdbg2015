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
	union {
		struct {
			DEBUG_EVENT		event;
			CONTEXT			ctx;
		};

		// ANOTHER MEMBER;
	};
};

struct DebugAckPacket {
	union {
		struct {
			DWORD	dwProcessId;
			DWORD	dwThreadId;
			DWORD	dwContinueStatus;
			CONTEXT	ctx;
			DWORD	ContextFlags;
		};

		// ANOTHER MEMBER;
	};
};

void _MyTrace(LPCSTR fmt, ...);

#ifdef _DEBUG
#define MyTrace		_MyTrace
#else
#define MyTrace
#endif

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
	};	
};

//////////////////////////////////////////////////////////////////////////