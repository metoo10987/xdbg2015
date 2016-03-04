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

struct CONTINUE_DEBUG_EVENT {
	DWORD dwProcessId;
	DWORD dwThreadId;
	DWORD dwContinueStatus;
};

void MyTrace(LPCSTR fmt, ...);
