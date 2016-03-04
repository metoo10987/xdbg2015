#pragma once

#include <Windows.h>
#include <set>

class Mutex {
public:
	Mutex();
	~Mutex();

	void lock();
	bool trylock();
	void unlock();

protected:
	CRITICAL_SECTION	_cs;
};

class Semaphore {
public:
	Semaphore(long initVal, long maxVal);
	~Semaphore();

	void lock();
	void unlock();

protected:
	HANDLE _sema;
};

class Nonlock {
public:
	void lock() { }
	void unlock() { }
};

template<class LOCK_TYPE>
class LockGuard {
public:
	LockGuard (LOCK_TYPE* lock): _lock(lock)
	{
		lock->lock();
	}

	~LockGuard ()
	{
		_lock->unlock();
	}

protected:
	LOCK_TYPE*	_lock;
};

template<class LOCK_TYPE>
class MultiLockGuard {
public:
	MultiLockGuard (size_t n, ...)
	{
		va_list valist;
		va_start(valist, n);
		for (size_t i = 0; i < n; i ++) {
			LOCK_TYPE* lock = va_arg(valist, LOCK_TYPE* );
			_locks.insert(lock);
		}

		LockSet::iterator it;
		for (it = _locks.begin(); it != _locks.end(); it ++) {
			(*it)->lock();
		}
	}

	~MultiLockGuard ()
	{
		LockSet::iterator it;
		for (it = _locks.begin(); it != _locks.end(); it ++) {
			(*it)->unlock();
		}		
	}

protected:
	typedef std::set<LOCK_TYPE* > LockSet;
	LockSet		_locks;
};

typedef LockGuard<Mutex> MutexGuard;
typedef MultiLockGuard<Mutex> MMutexGuard;

typedef LockGuard<Semaphore> SemaGuard;
