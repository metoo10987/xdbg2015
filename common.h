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

#define EVENT_MESSAGE_SIZE		sizeof(DEBUG_EVENT)
#define CONTINUE_MESSAGE_SIZE	sizeof(CONTINUE_DEBUG_EVENT)
static inline std::string makePipeName(DWORD pid)
{
	char buf[256];
	sprintf_s(buf, "\\\\.\\pipe\\__xdbg__%u__", pid);
	return buf;
}

#define CDE_SINGLE_STEP		1

struct WAIT_DEBUG_EVENT {
	DEBUG_EVENT		event;
	CONTEXT			ctx;
};

struct CONTINUE_DEBUG_EVENT {
	DWORD	dwProcessId;
	DWORD	dwThreadId;
	DWORD	dwContinueStatus;
	ULONG	newpc;
	ULONG	flags;
};

void MyTrace(LPCSTR fmt, ...);

#ifdef _DEBUG
#define MYTRACE		MyTrace
#else
#define MYTRACE		
#endif

#define SINGLE_STEP_FLAG	0x100
