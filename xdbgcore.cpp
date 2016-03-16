// xdbgcore.cpp : Defines the exported functions for the DLL application.
//

#include <Windows.h>
#include "XDbgProxy.h"
#include <assert.h>
#include "detours.h"
#include "XDbgController.h"
#include "common.h"
#include "AutoDebug.h"
#include "pluginsdk/_plugins.h"

#define XDBG_VER		(1)

HANDLE hInstance;
UINT exec_mode = 0;
UINT debug_if = 0;

XDbgController* dbgctl = NULL;

static void loadConfig()
{
	char iniName[MAX_PATH];
	GetModuleFileName(NULL, iniName, sizeof(iniName) - 1);
	strcat_s(iniName, ".ini");
	exec_mode = GetPrivateProfileInt("xdbg", "mode", 0, iniName);
	debug_if = GetPrivateProfileInt("xdbg", "debug_if", 0, iniName);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		
		hInstance = hModule;
		loadConfig();

		if (exec_mode == 0) { // proxy mode

			MyTrace("xdbgcore initializing. mode: 0");
			if (!XDbgProxy::instance().initialize()) {
				// log error
				assert(false);
			}

			// XDbgProxy::instance().waitForAttach();

		} else if (exec_mode == 1) {
			MyTrace("xdbgcore initializing. mode: 1");
			if (!XDbgController::instance().initialize(hModule, true)) {
				// log error
				assert(false);
			}

			registerAutoDebugHandler(new IgnoreException());
		}
	}
	
	if (exec_mode == 0) {

		return XDbgProxy::instance().DllMain(hModule, reason, lpReserved);
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////

bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->pluginVersion = XDBG_VER;
	strcpy(initStruct->pluginName, "XDbg");
	initStruct->sdkVersion = PLUG_SDKVERSION;
	return true;
}

void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
	int(*plugin_menuadd)(int hMenu, const char* title) = (int(* )(int hMenu, const char* title) )GetProcAddress(GetModuleHandle("x32dbg.dll"), "_plugin_menuadd");
	plugin_menuadd(setupStruct->hMenu, "Enable XDbg");
}

bool plugstop()
{
	return true;
}
