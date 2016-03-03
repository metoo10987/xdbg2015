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
	int* p = NULL;
	*p = 10;
	

	return 0;
}

