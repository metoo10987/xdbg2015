#pragma once
#include <string>

template<typename T>
void* CastProcAddr(T p)
{
	union u {
		T		var;
		void*	f;
	} u1;

	u1.var = p;
	return u1.f;
};

static inline std::string makePipeName(DWORD pid)
{
	char buf[256];
	sprintf_s(buf, "\\\\.\\pipe\\__xdbg__%u__", pid);
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
