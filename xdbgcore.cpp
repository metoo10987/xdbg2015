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
#include "Utils.h"
#include <Psapi.h>

#define XDBG_VER		(1)

HMODULE hInstance;
UINT exec_mode = 0;
UINT debug_if = 0;
UINT api_hook_mask = ID_ReadProcessMemory | ID_WriteProcessMemory | ID_SuspendThread | ID_ResumeThread;
UINT inject_method = 0;
UINT ignore_dbgstr = 1;

// XDbgController* dbgctl = NULL;

//////////////////////////////////////////////////////////////////////////
void (* plugin_registercallback)(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin) = NULL;
int (* plugin_menuaddentry)(int hMenu, int entry, const char* title) = NULL;
bool (* plugin_menuclear)(int hMenu);
void (* plugin_logprintf)(const char* format, ...);

bool preparePlugin();
void ResiserListViewClass();
void initMode2();

//////////////////////////////////////////////////////////////////////////

static void loadConfig()
{
	char iniName[MAX_PATH];
	GetModuleFileName(NULL, iniName, sizeof(iniName) - 1);
	strcat_s(iniName, ".ini");
	exec_mode = GetPrivateProfileInt("xdbg", "mode", exec_mode, iniName);
	debug_if = GetPrivateProfileInt("xdbg", "debug_if", debug_if, iniName);
	api_hook_mask = GetPrivateProfileInt("xdbg", "api_hook_mask", api_hook_mask, iniName);
	inject_method = GetPrivateProfileInt("xdbg", "inject_method", inject_method, iniName);
	ignore_dbgstr = GetPrivateProfileInt("xdbg", "ignore_dbgstr", ignore_dbgstr, iniName);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		hInstance = hModule;
		loadConfig();
		// ModifyExe();
		if (exec_mode == 1 || preparePlugin()) {

			exec_mode = 1;
			preparePlugin();

			MyTrace("xdbgcore initializing. mode: 1");
			if (!XDbgController::instance().initialize(hModule, true)) {
				// log error
				assert(false);
			}

			registerAutoDebugHandler(new IgnoreException());

		} else if (exec_mode == 0) { // proxy mode

			MyTrace("xdbgcore initializing. mode: 0");
			if (!XDbgProxy::instance().initialize()) {
				// log error
				assert(false);
				return FALSE;
			}

			// XDbgProxy::instance().waitForAttach();
		} else if (exec_mode == 2) {
			initMode2();
		} else {
			assert(false);
			return FALSE;
		}
	}
	
	if (exec_mode == 0) {

		return XDbgProxy::instance().DllMain(hModule, reason, lpReserved);
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////

#define MENU_ID_ENABLE		1
#define MENU_ID_DISABLE		2
#define MENU_ID_ABOUT		3
#define MENU_ID_STATE		4

bool preparePlugin()
{
#ifdef _M_X64
#define X64DBG_DLL		"x64dbg.dll"
#else
#define X64DBG_DLL		"x32dbg.dll"
#endif

	plugin_registercallback = (void ( *)(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin))
		GetProcAddress(GetModuleHandle(X64DBG_DLL), "_plugin_registercallback");

	plugin_menuaddentry = (int (* )(int hMenu, int entry, const char* title))
		GetProcAddress(GetModuleHandle(X64DBG_DLL), "_plugin_menuaddentry");

	plugin_menuclear = (bool (*)(int hMenu))
		GetProcAddress(GetModuleHandle(X64DBG_DLL), "_plugin_menuclear");

	plugin_logprintf = ( void(*)(const char* format, ...)) 
		GetProcAddress(GetModuleHandle(X64DBG_DLL), "_plugin_logprintf");

	return (plugin_registercallback && plugin_registercallback && plugin_menuclear && plugin_logprintf);
}

void menuHandler(CBTYPE Type, PLUG_CB_MENUENTRY *Info);
void createProcessHandler(CBTYPE type, PLUG_CB_CREATEPROCESS* info);
void attachHandler(CBTYPE type, PLUG_CB_ATTACH* info);

bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->pluginVersion = XDBG_VER;
	strcpy(initStruct->pluginName, "XDbg");
	initStruct->sdkVersion = PLUG_SDKVERSION;

	assert(plugin_registercallback);
	plugin_registercallback(initStruct->pluginHandle, CB_MENUENTRY, (CBPLUGIN)menuHandler);
	plugin_registercallback(initStruct->pluginHandle, CB_CREATEPROCESS, (CBPLUGIN)createProcessHandler);
	plugin_registercallback(initStruct->pluginHandle, CB_ATTACH, (CBPLUGIN)attachHandler);
	return true;
}

HWND hWnd;
void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
	hWnd = setupStruct->hwndDlg;

	assert(plugin_menuaddentry);
	plugin_menuaddentry(setupStruct->hMenu, MENU_ID_ENABLE, "Enable XDbg");
	plugin_menuaddentry(setupStruct->hMenu, MENU_ID_DISABLE, "Disable XDbg");
	plugin_menuaddentry(setupStruct->hMenu, MENU_ID_STATE, "Current state");
	plugin_menuaddentry(setupStruct->hMenu, MENU_ID_ABOUT, "About XDbg");
}

bool plugstop()
{
	return true;
}

void menuHandler(CBTYPE Type, PLUG_CB_MENUENTRY *info)
{
	switch (info->hEntry) {
	case MENU_ID_ENABLE:
		debug_if = 0;
		plugin_logprintf("XDbg enabled\n");
		break;
	case MENU_ID_DISABLE:
		debug_if = 1;
		plugin_logprintf("XDbg disabled\n");
		break;
	case MENU_ID_STATE:
		plugin_logprintf("XDbg state: %s\n", debug_if == 0 ? "Enabled" : "Disabled" );
		break;
	case MENU_ID_ABOUT:
		MessageBox(hWnd, "XDbg v0.1\nAuthor: Brock\nEmail: xiaowave@gmail.com", "XDbg", MB_OK | MB_ICONINFORMATION);
		break;
	}
}

void createProcessHandler(CBTYPE type, PLUG_CB_CREATEPROCESS* info)
{
	if (debug_if == 0)
		plugin_logprintf("Current debug engine is XDbg\n");
}

void attachHandler(CBTYPE type, PLUG_CB_ATTACH* info)
{
	if (debug_if == 0)
		plugin_logprintf("Current debug engine is XDbg\n");
}

//////////////////////////////////////////////////////////////////////////
// mode 2

#define LISTVIEW_CLASS			L"SysListView32"
#define MY_LISTVIEW_CLASS		L"XDBGLV"

void ResiserListViewClass()
{
	WNDCLASSW wndCls;
	if (!GetClassInfoW(NULL, LISTVIEW_CLASS, &wndCls)) {
		assert(false);
	}

	wndCls.lpszClassName = MY_LISTVIEW_CLASS;
	if (RegisterClassW(&wndCls) == 0) {
		assert(false);
	}
}

HWND(__stdcall * Real_CreateWindowExW)(DWORD a0,
	LPCWSTR a1,
	LPCWSTR a2,
	DWORD a3,
	int a4,
	int a5,
	int a6,
	int a7,
	HWND a8,
	HMENU a9,
	HINSTANCE a10,
	LPVOID a11)
	= CreateWindowExW;

HWND __stdcall Mine_CreateWindowExW(DWORD a0,
	LPCWSTR lpClassName,
	LPCWSTR a2,
	DWORD a3,
	int a4,
	int a5,
	int a6,
	int a7,
	HWND a8,
	HMENU a9,
	HINSTANCE a10,
	LPVOID a11)
{
	// MyTrace("%s() classname: %S", __FUNCTION__, lpClassName);
	if (LOWORD(lpClassName) != ULONG_PTR(lpClassName) && 
		lstrcmpW(lpClassName, LISTVIEW_CLASS) == 0) {

		lpClassName = MY_LISTVIEW_CLASS;
		// MyTrace("%s() new classname: %S", __FUNCTION__, lpClassName);
	}

	return Real_CreateWindowExW(a0, lpClassName, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

HRSRC(__stdcall * Real_FindResourceExW)(HMODULE a0,
	LPCWSTR a1,
	LPCWSTR a2,
	WORD a3)
	= FindResourceExW;

HRSRC(__stdcall * Real_FindResourceExA)(HMODULE a0,
	LPCSTR a1,
	LPCSTR a2,
	WORD a3)
	= FindResourceExA;

HRSRC __stdcall Mine_FindResourceExA(HMODULE a0,
	LPCSTR a1,
	LPCSTR a2,
	WORD a3)
{
	return Real_FindResourceExA(a0, a1, a2, a3);
}

HRSRC __stdcall Mine_FindResourceExW(HMODULE a0,
	LPCWSTR a1,
	LPCWSTR a2,
	WORD a3)
{
	return Real_FindResourceExW(a0, a1, a2, a3);
}

static PVOID mallocRecSec(PVOID base, SIZE_T size)
{
	return VirtualAlloc((PVOID)0x20000000, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

PVOID memblockCache = NULL;
PVOID memBase = NULL;

void restoreMemory(PVOID base, ULONG_PTR offset, SIZE_T len)
{
	memcpy((PVOID)MakePtr(base, offset), (PVOID)MakePtr(memblockCache, offset), len);
}


std::vector<std::pair<ULONG_PTR, ULONG_PTR> > records;
void prebeSign(PVOID base, SIZE_T len)
{
	if (len < 16)
		return;

	// MyTrace("memBase: %p, base: %p, size_t: %u", memBase, base, len);
	PVOID addr = base;
	SIZE_T part = len / 2;
	memset(addr, 0, part);
	char msg[256];
	sprintf(msg, "memBase: %p, base: %p, part: %u. is detected?", memBase, base, part);
	if (MessageBox(NULL, msg, msg, MB_YESNO) == IDNO) {
		// records.push_back(std::pair<ULONG_PTR, ULONG_PTR>((ULONG_PTR)addr, (ULONG_PTR)part));
		MyTrace("FOUND! memBase: %p, base: %p, size_t: %u", memBase, addr, part);
		restoreMemory(memBase, (ULONG_PTR)addr - (ULONG_PTR)memBase, part);
		prebeSign(addr, part);
		return;
	}

	// restoreMemory(memBase, (ULONG_PTR )addr - (ULONG_PTR )memBase, part);

	PVOID addr2 = (PVOID )MakePtr(base, part);
	SIZE_T part2 = len - part;
	memset(addr2, 0, part2);
	sprintf(msg, "memBase: %p, base: %p, part: %u. is detected?", memBase, addr2, part2);
	if (MessageBox(NULL, msg, msg, MB_YESNO) == IDNO) {
		// records.push_back(std::pair<ULONG_PTR, ULONG_PTR>((ULONG_PTR)addr2, (ULONG_PTR)part2));
		MyTrace("FOUND! memBase: %p, base: %p, size_t: %u", memBase, addr2, part2);
		restoreMemory(memBase, (ULONG_PTR)addr2 - (ULONG_PTR)memBase, part2);
		prebeSign(addr2, part2);
	}

	restoreMemory(base, (ULONG_PTR)base - (ULONG_PTR)memBase, len);
}

BOOL ModifyExe()
{
#if 0
	HMODULE hMod = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hMod;
	PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)(ULONG_PTR(dosHdr) + dosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(ntHdrs + 1);
	PVOID resSec = NULL;
	DWORD oldProt;
#endif

#if 0
	ULONG_PTR imgSize = ntHdrs->OptionalHeader.SizeOfImage;
	void* buf = malloc(imgSize);
	memcpy(buf, (void*)hMod, imgSize);
	UnmapViewOfFile((LPVOID)hMod);
	PVOID base = VirtualAlloc((LPVOID)hMod, imgSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(base, buf, imgSize);
	FlushInstructionCache(GetCurrentProcess(), base, imgSize);
	free(buf);
	// DebugBreak();
	// return TRUE;
#endif

#if 0
	// char buf[sizeof(*dosHdr) + sizeof(*ntHdrs)] = { 0 };
	// DWORD len;
	//VirtualProtect(dosHdr, sizeof(*dosHdr), PAGE_READWRITE, &oldProt);
	// WriteProcessMemory(GetCurrentProcess(), ntHdrs, buf, sizeof(*ntHdrs), &len);
	VirtualProtect(ntHdrs, sizeof(*ntHdrs), PAGE_READWRITE, &oldProt);
	// WriteProcessMemory(GetCurrentProcess(), dosHdr, buf, sizeof(*dosHdr), &len);
	// memset(ntHdrs, 0, sizeof(*ntHdrs));
	// memset(dosHdr, 0, sizeof(*dosHdr));

	// VirtualProtect(sections, sizeof(*sections) * ntHdrs->FileHeader.NumberOfSections, PAGE_READWRITE, &oldProt);
	// memset(sections, 0, sizeof(*sections) * ntHdrs->FileHeader.NumberOfSections);


	// ntHdrs->FileHeader.NumberOfSections = 0;
	ntHdrs->FileHeader.SizeOfOptionalHeader = 0;
	ntHdrs->OptionalHeader.SizeOfImage = 0;
	ntHdrs->OptionalHeader.ImageBase = 0;
	ntHdrs->OptionalHeader.AddressOfEntryPoint = 0;
	ntHdrs->OptionalHeader.BaseOfCode = 0;
	ntHdrs->OptionalHeader.BaseOfData = 0;
	ntHdrs->OptionalHeader.SizeOfCode = 0;
	ntHdrs->OptionalHeader.SizeOfInitializedData = 0;
	ntHdrs->OptionalHeader.SizeOfHeaders = 0;

	PLIST_ENTRY entry;
	PLIST_ENTRY moduleListHead;
	PLDR_DATA_TABLE_ENTRY module;

	PPEB_LDR_DATA ldrData = *(PPEB_LDR_DATA *)MakePtr(_GetCurrentPeb(), 0xc);

	moduleListHead = &ldrData->InMemoryOrderModuleList;
	entry = moduleListHead->Flink;

	while (entry != moduleListHead) {
		module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
		if (module->DllBase == (PVOID)hMod) {
			/* size_t len = lstrlenW(module->FullDllName.Buffer);
			module->FullDllName.Buffer[len - 1] = 'l';
			module->FullDllName.Buffer[len - 2] = 'l';
			module->FullDllName.Buffer[len - 3] = 'd';
			MessageBoxW(NULL, module->FullDllName.Buffer, module->FullDllName.Buffer, 0);
			*/
			entry->Flink->Blink = entry->Blink;
			entry->Blink->Flink = entry->Flink;

			ULONG_PTR peb = (ULONG_PTR)_GetCurrentPeb();
			ULONG_PTR* imageBase = (ULONG_PTR*)(peb + 8);
			module = CONTAINING_RECORD(entry->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
			*imageBase = (ULONG_PTR)module->DllBase;
			HMODULE hMod2 = GetModuleHandle(NULL);
			break;
		}

		entry = entry->Flink;
	}

#endif 

#if 0
	for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++) {
		if (strcmp((char*)sections[i].Name, ".rdata") == 0) {

			//* memblockCache = malloc(sections[i].Misc.VirtualSize);
			
			// resSec = mallocRecSec(hMod, sections[i].Misc.VirtualSize);
			PVOID secAddr = (PVOID)MakePtr(hMod, sections[i].VirtualAddress);
			// memcpy(memblockCache, secAddr, sections[i].Misc.VirtualSize);

			// memcpy(resSec, secAddr, sections[i].Misc.VirtualSize);
			VirtualProtect(secAddr, sections[i].Misc.VirtualSize, PAGE_READWRITE, &oldProt);
			//* memBase = secAddr;
			// prebeSign(secAddr, sections[i].Misc.VirtualSize);

			memset((PVOID)MakePtr(secAddr, (sections[i].Misc.VirtualSize / 1024) * ((83) - 1)),

				0, sectio0ns[i].Misc.VirtualSize / 1024);

			/* memset((PVOID)MakePtr(secAddr, (sections[i].Misc.VirtualSize / 64) * ((7) - 1)),

				0, sections[i].Misc.VirtualSize / 64); */

			/* memset((PVOID)MakePtr(secAddr, (sections[i].Misc.VirtualSize / 128) * ((15) - 1) ),

				0, sections[i].Misc.VirtualSize / 128); */

			/* memset((PVOID)MakePtr(secAddr, (sections[i].Misc.VirtualSize / 256) * 31),

				0, sections[i].Misc.VirtualSize / 256);*/

#if 0
			// 下半部分档起来
			memset((PVOID)MakePtr(secAddr, sections[i].Misc.VirtualSize / 16 + 
				sections[i].Misc.VirtualSize / 32),

				0, sections[i].Misc.VirtualSize / 32);

			// 上半部分的上半部分挡起来[X]
			/* memset((PVOID)MakePtr(secAddr, sections[i].Misc.VirtualSize / 16),

				0, sections[i].Misc.VirtualSize / 64); */

			// 上半部分的下半部分挡起来[O]
			memset((PVOID)MakePtr(secAddr, sections[i].Misc.VirtualSize / 16 + 
				sections[i].Misc.VirtualSize / 64),

			0, sections[i].Misc.VirtualSize / 512);

#endif

			// SIZE_T blcokSize = sections[i].Misc.VirtualSize / 32;
#if 0
			// 上半部分档起来
			memset((PVOID )MakePtr(secAddr, sections[i].Misc.VirtualSize / 16), 0, 
				sections[i].Misc.VirtualSize / 32);


			// 下半部分的上半部分挡起来[X]
			/* memset((PVOID)MakePtr(secAddr, 
				sections[i].Misc.VirtualSize / 16 + sections[i].Misc.VirtualSize / 32), 0,
				sections[i].Misc.VirtualSize / 64); */

			// 下半部分的下半部分挡起来[O]
			memset((PVOID)MakePtr(secAddr,
				sections[i].Misc.VirtualSize / 16 + sections[i].Misc.VirtualSize / 32 + 
				sections[i].Misc.VirtualSize / 64), 

				0, sections[i].Misc.VirtualSize / 64);
#endif
			break;
		}
	}

	//VirtualProtect(ntHdrs, sizeof(*ntHdrs), PAGE_READWRITE, &oldProt);
	//(PVOID &)ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress =
	//	PVOID((ULONG_PTR)resSec - (ULONG_PTR)hMod);
	//VirtualProtect(ntHdrs, sizeof(*ntHdrs), oldProt, &oldProt);
	DebugBreak();
#endif
	return TRUE;
}

void initMode2()
{
	ModifyExe();
	inject_method = 1; // WIN HOOK
	api_hook_mask = ID_ReadProcessMemory | ID_WriteProcessMemory | ID_SuspendThread | ID_ResumeThread | 
		ID_GetThreadContext | ID_SetThreadContext | ID_VirtualQueryEx | ID_VirtualProtectEx | ID_GetModuleFileNameExW;
	MyTrace("xdbgcore initializing. mode: 2");
	if (!XDbgController::instance().initialize(hInstance, true)) {
		// log error
		assert(false);
	}

	ResiserListViewClass();
	DetourTransactionBegin();
	DetourAttach(&(PVOID&)Real_CreateWindowExW, &(PVOID&)Mine_CreateWindowExW);
	// DetourAttach(&(PVOID&)Real_FindResourceExA, &(PVOID&)Mine_FindResourceExA);
	// DetourAttach(&(PVOID&)Real_FindResourceExW, &(PVOID&)Mine_FindResourceExW);
	DetourTransactionCommit();
}

BOOL WINAPI CE_OpenProcess(DWORD pid)
{
	MyTrace("%s()", __FUNCTION__);
	XDbgController& dbgctl = XDbgController::instance();
	if (!dbgctl.injectDll(pid, dbgctl.getModuleHandle())) {
		MyTrace("%s(): injectDll() failed.", __FUNCTION__);
	}

	dbgctl.disconnectRemoteApi();
	int i;
	for (i = 30; i > 0; i--) {
		if (dbgctl.connectRemoteApi(pid))
			break;

		Sleep(100);
	}

	if (i == 0) {
		assert(false);
		// log error
		return FALSE;
	}

	return TRUE;
}
