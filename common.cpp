#include <windows.h>
#include "common.h"

void MyTrace(LPCSTR fmt, ...)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	va_list vlist;
	va_start(vlist, fmt);
	char buf[2048];

	int len = sprintf_s(buf, sizeof(buf), "<TRACE>~%04d[%02d:%02d:%02d.%03d] ", GetCurrentThreadId(), 
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	len = vsprintf_s(&buf[len], sizeof(buf) - len, fmt, vlist);
	strcat_s(buf, sizeof(buf), "\n");
	OutputDebugStringA(buf);
}
