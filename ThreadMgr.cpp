#include <Windows.h>
#include "ThreadMgr.h"
#include <tlhelp32.h>
#include "common.h"

ThreadMgr::ThreadMgr()
{
}


ThreadMgr::~ThreadMgr()
{
}

bool ThreadMgr::addAllThreads(DWORD excluded)
{
	MutexGuard guard(&_lock);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(hSnapshot, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {

					if (te.th32ThreadID == excluded)
						continue;
					addThread(te.th32ThreadID);
				}

				te.dwSize = sizeof(te);
			} while (Thread32Next(hSnapshot, &te));
		}

		CloseHandle(hSnapshot);
	}

	return true;
}

void ThreadMgr::clearThreads()
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		CloseHandle(it->second);
	}

	_threads.clear();
}

HANDLE ThreadMgr::addThread(DWORD tid)
{
	HANDLE hThread = openThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (hThread == NULL) {
		MyTrace("%s(): openThread() failed. errno: %x", __FUNCTION__, GetLastError());
		// assert(false);
		hThread = (HANDLE)-1;
	}

	MutexGuard guard(&_lock);
	_threads[tid] = hThread;
	return hThread;
}

bool ThreadMgr::delThread(DWORD tid)
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it = _threads.find(tid);
	if (it == _threads.end()) {
		return false;
	}
	if (it->second && it->second != (HANDLE)-1)
		CloseHandle(it->second);
	_threads.erase(it);
	return true;
}

void ThreadMgr::suspendAll(DWORD excluded)
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		if (it->first == excluded)
			continue;
		suspendThread(it->second);
	}
}

void ThreadMgr::resumeAll(DWORD excluded)
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		if (it->first == excluded)
			continue;
		resumeThread(it->second);
	}
}

HANDLE ThreadMgr::threadIdToHandle(DWORD tid)
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it;
	it = _threads.find(tid);
	if (it == _threads.end())
		return NULL;
	return it->second;
}

DWORD ThreadMgr::threadHandleToId(HANDLE handle)
{
	MutexGuard guard(&_lock);
	std::map<DWORD, HANDLE>::iterator it;
	for (it = _threads.begin(); it != _threads.end(); it++) {
		if (it->second == handle)
			return it->first;
	}

	return 0;
}
