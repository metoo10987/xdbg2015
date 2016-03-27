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
		ULONG_PTR start;
		ULONG_PTR end;
		if (sscanf(entry, "%X-%X", &start, &end) == 2) {
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
			if (it->first == 0 && (ULONG )event->u.Exception.ExceptionRecord.ExceptionAddress == it->second) {
				*continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				return false;
			}

			if (event->u.Exception.ExceptionRecord.ExceptionCode >= it->first &&
				event->u.Exception.ExceptionRecord.ExceptionCode <= it->second) {
				*continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				return false;
			}

			if (it->second == 0) {
				DWORD code = 0;
				SIZE_T len;
				::ReadProcessMemory(XDbgController::instance().getProcessHandle(), 
					event->u.Exception.ExceptionRecord.ExceptionAddress, &code,
					sizeof(code), &len);
				if (code == it->first) {
					*continueStatus = DBG_EXCEPTION_NOT_HANDLED;
					return false;
				}
			}
		}
	}

	return true;
}
