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

// #define CDE_SINGLE_STEP		1
// #define CDE_DEBUG_REG		2

struct WAIT_DEBUG_EVENT {
	DEBUG_EVENT		event;
	CONTEXT			ctx;
};

struct DbgRegs {
	ULONG	Dr0;
	ULONG	Dr1;
	ULONG	Dr2;
	ULONG	Dr3;
	ULONG	Dr6;
	ULONG	Dr7;
};

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

struct CONTINUE_DEBUG_EVENT {
	DWORD	dwProcessId;
	DWORD	dwThreadId;
	DWORD	dwContinueStatus;
	ULONG	mask;
	ULONG	newpc;
	ULONG	eflags;
	DbgRegs dbgRegs;
};

void MyTrace(LPCSTR fmt, ...);

#ifdef _DEBUG
#define MYTRACE		MyTrace
#else
#define MYTRACE		
#endif

#define SINGLE_STEP_FLAG	0x100

#ifdef _M_X64
#define CTX_PC_REG(CTX)		(CTX)->Rip
#else
#define CTX_PC_REG(CTX)		(CTX)->Eip
#endif

#define ATTACHED_EVENT	(RIP_EVENT + 1)
#define LAST_EVENT		ATTACHED_EVENT
