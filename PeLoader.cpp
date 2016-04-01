#include <windows.h>
#include <assert.h>
#include "PeLoader.h"
#include "Utils.h"
#include <ImageHlp.h>

PeLoader::PeLoader()
{
}


PeLoader::~PeLoader()
{
}

PVOID PeLoader::load(HANDLE hProc, LPCTSTR fileName, PVOID base)
{
	HANDLE hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	CloseHandle(hFile);
	if (hMap == NULL) {
		return NULL;
	}

	_hProc = hProc;

	PVOID fileCache = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMap);
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER )fileCache;
	PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS )MakePtr(fileCache, dosHdr->e_lfanew);
	base = VirtualAllocEx(hProc, base, ntHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, 
		PAGE_READWRITE);
	loadImage(fileCache, base);	

	PIMAGE_DOS_HEADER imgDosHdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS imgNtHdrs = (PIMAGE_NT_HEADERS)MakePtr(base, dosHdr->e_lfanew);

	if (!loadImport(fileCache, base, ntHdrs, imgNtHdrs)) {
		assert(false);
		return false;
	}

	if (!loadRelocation(fileCache, base, ntHdrs, imgNtHdrs)) {
		assert(false);
		return false;
	}

	UnmapViewOfFile(fileCache);

	return base;
}


bool PeLoader::loadImage(PVOID cachedBase, PVOID imgBase)
{
	SIZE_T len;
	PIMAGE_DOS_HEADER dosHdrSrc = (PIMAGE_DOS_HEADER)cachedBase;
	PIMAGE_DOS_HEADER dosHdrDest = (PIMAGE_DOS_HEADER)imgBase;
	WriteProcessMemory(_hProc, dosHdrDest, dosHdrSrc, sizeof(*dosHdrSrc), &len);
	PIMAGE_NT_HEADERS ntHdrsSrc = (PIMAGE_NT_HEADERS)MakePtr(cachedBase, dosHdrSrc->e_lfanew);
	PIMAGE_NT_HEADERS ntHdrsDest = (PIMAGE_NT_HEADERS)MakePtr(imgBase, dosHdrSrc->e_lfanew);
	WriteProcessMemory(_hProc, ntHdrsDest, ntHdrsSrc, sizeof(*ntHdrsSrc), &len);
	WORD secNum = ntHdrsSrc->FileHeader.NumberOfSections;
	WriteProcessMemory(_hProc, ntHdrsDest + 1, ntHdrsSrc + 1, sizeof(IMAGE_SECTION_HEADER) * secNum, &len);

	PIMAGE_SECTION_HEADER secHdrSrc = PIMAGE_SECTION_HEADER(ntHdrsSrc + 1);
	PIMAGE_SECTION_HEADER secHdrDest = PIMAGE_SECTION_HEADER(ntHdrsDest + 1);
	for (WORD i = 0; i < secNum; i ++) {
		PVOID secAddrSrc = (PVOID)MakePtr(cachedBase, secHdrSrc[i].VirtualAddress);
		PVOID secAddrDest = (PVOID)MakePtr(imgBase, secHdrSrc[i].VirtualAddress);
		WriteProcessMemory(_hProc, secAddrDest, secAddrSrc, secHdrSrc[i].Misc.VirtualSize, &len);
	}
	
	return true;
}

HMODULE PeLoader::loadDll(HANDLE hProc, LPCTSTR dllPath)
{
	assert(hProc == GetCurrentProcess());
	return LoadLibrary(dllPath);
}

bool PeLoader::loadImport(PVOID cachedBase, PVOID imgBase, PIMAGE_NT_HEADERS cachedNtHdrs, 
	PIMAGE_NT_HEADERS ntHdrs)
{
	PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR )cachedNtHdrs->OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	while (impDesc->Name) {
		
		LPCSTR name = (LPCSTR )MakePtr(cachedBase, impDesc->Name);
		impDesc ++;
	}

	return false;
}

bool PeLoader::loadRelocation(PVOID cachedBase, PVOID imgBase, PIMAGE_NT_HEADERS cachedNtHdrs, 
	PIMAGE_NT_HEADERS ntHdrs)
{
	return false;
}
