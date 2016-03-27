#pragma once
#include <Windows.h>
#include "XDbgController.h"
#include <vector>

class IgnoreException : public AutoDebug {
public:
	IgnoreException();
	virtual bool peekDebugEvent(LPDEBUG_EVENT event, DWORD* continueStatus);

	std::vector<std::pair<ULONG_PTR, ULONG_PTR> >	_exceptions;
};
