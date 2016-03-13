#include <Windows.h>
#include "AutoDebug.h"
#include "XDbgController.h"

IgnoreException::IgnoreException()
{
	char iniName[MAX_PATH];
	GetModuleFileName(NULL, iniName, sizeof(iniName) - 1);
	strcat_s(iniName, ".ini");
	char ignoreExceptions[1024];
	GetPrivateProfileString("xdbg", "ignored_exceptions", "", ignoreExceptions, 
		sizeof(ignoreExceptions) - 1, iniName);

	char* entry = strtok(ignoreExceptions, ",");
	while (entry) {
		unsigned long start;
		unsigned long end;
		if (sscanf(entry, "%08X-%08X", &start, &end) == 2 && start <= end) {
			std::pair<ULONG, ULONG> range;
			range.first = start;
			range.second = end;
			_exceptions.push_back(range);
		}

		entry = strtok(0, ",");
	}
}

bool IgnoreException::peekDebugEvent(LPDEBUG_EVENT event, DWORD* continueStatus)
{
	if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
		std::vector<std::pair<ULONG, ULONG> >::iterator it;
		for (it = _exceptions.begin(); it != _exceptions.end(); it ++) {
			if (event->u.Exception.ExceptionRecord.ExceptionCode >= it->first &&
				event->u.Exception.ExceptionRecord.ExceptionCode <= it->second) {
				*continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				return false;
			}
		}
	}

	return true;
}
