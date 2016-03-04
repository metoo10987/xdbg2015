#include "Lock.h"

Mutex::Mutex()
{
	InitializeCriticalSection(&_cs);
}

Mutex::~Mutex()
{
	DeleteCriticalSection(&_cs);
}

void Mutex::lock()
{
	EnterCriticalSection(&_cs);
}

bool Mutex::trylock()
{
	return TryEnterCriticalSection(&_cs) == TRUE;
}

void Mutex::unlock()
{
	LeaveCriticalSection(&_cs);
}

//////////////////////////////////////////////////////////////////////////

Semaphore::Semaphore(long initVal, long maxVal)
{
	_sema = CreateSemaphore(NULL, initVal, maxVal, NULL);

	if (_sema == NULL) {
		
		throw __FUNCTION__": CreateSemaphore failed";
	}
}

Semaphore::~Semaphore()
{
	if (_sema)
		CloseHandle(_sema);
}

void Semaphore::lock()
{
	WaitForSingleObject(_sema, INFINITE);
}

void Semaphore::unlock()
{
	LONG count;
	::ReleaseSemaphore(_sema, 1, &count);
}

//////////////////////////////////////////////////////////////////////////
// unit testing
#ifdef _UNIT_TEST

static void test()
{
	Mutex lock1, lock2;
	MutexGuard guard(&lock1);
	MMutexGuard guard2(2, &lock1, &lock2);
}

#endif
