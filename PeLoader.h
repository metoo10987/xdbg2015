#pragma once
class PeLoader
{
public:
	PeLoader();
	~PeLoader();

	PVOID load(HANDLE hProc, LPCTSTR fileName, PVOID base);

protected:
	bool loadImage(PVOID cachedBase, PVOID imgBase);
	bool loadImport(PVOID cachedBase, PVOID imgBase, PIMAGE_NT_HEADERS cachedNtHdrs, PIMAGE_NT_HEADERS imgNtHdrs);
	bool loadRelocation(PVOID cachedBase, PVOID imgBase, PIMAGE_NT_HEADERS cachedNtHdrs, PIMAGE_NT_HEADERS imgNtHdrs);
	HMODULE loadDll(HANDLE hProc, LPCTSTR dllPath);

protected:
	HANDLE			_hProc;
	PVOID			_base;
};
