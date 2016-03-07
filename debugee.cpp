// debugee.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include <Windows.h>
#include "XDbgProxy.h"

int _tmain(int argc, _TCHAR* argv[])
{
	LoadLibrary("xdbgcore.dll");
	/* XDbgProxy::instance().DllMain(GetModuleHandle(NULL), DLL_PROCESS_ATTACH, NULL);

	if (!XDbgProxy::instance().initialize()) {
		return -1;
	} */
	
	// Sleep(10000);
	//__try {
	int* p = NULL;
	*p = 10;
	DebugBreak();
	return 0;
	Sleep(10000);
	//} __except (EXCEPTION_EXECUTE_HANDLER) {
		printf("aaaa\n");
	//}
	// OutputDebugString("test");
	__try {
		//int* p = NULL;
		//*p = 10;
		OutputDebugString("test\n");
	} __except(EXCEPTION_EXECUTE_HANDLER) {

	}

	return 0;
}

