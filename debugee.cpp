// debugee.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <Windows.h>
#include "XDbgProxy.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if (!XDbgProxy::instance().initialize()) {
		return -1;
	}
	
	Sleep(10000);
	// OutputDebugString("test");
	__try {
		//int* p = NULL;
		//*p = 10;
		OutputDebugString("test\n");
	} __except(EXCEPTION_EXECUTE_HANDLER) {

	}

	return 0;
}

