#pragma once

// #include <algorithm>

#ifdef _DEBUG
void _MyTrace(LPCSTR fmt, ...);
#define MyTrace		_MyTrace
#else
#define MyTrace
#endif

#define MakePtr(a, b)    ( ((ULONG_PTR)a ) + ((ULONG_PTR)b ) )

template<typename T>
void* CastProcAddr(T p)
{
	union u {
		T		var;
		void*	f;
	} u1;

	u1.var = p;
	return u1.f;
};

//////////////////////////////////////////////////////////////////////////
#define QUEUE_SIZE 16
static size_t __declspec(thread) __thr_id;

/**
* @return continous thread IDs starting from 0 as opposed to pthread_self().
*/
inline size_t
thr_id()
{
	return __thr_id;
}

inline void
set_thr_id(size_t id)
{
	__thr_id = id;
}

template<class T,
	decltype(thr_id) ThrId = thr_id,
	unsigned long Q_SIZE = QUEUE_SIZE>
class LockFreeQueue {
private:
	static const unsigned long Q_MASK = Q_SIZE - 1;

	struct ThrPos {
		unsigned long head, tail;
	};

public:
	LockFreeQueue(size_t n_producers, size_t n_consumers)
		: n_producers_(n_producers),
		n_consumers_(n_consumers),
		head_(0),
		tail_(0),
		last_head_(0),
		last_tail_(0)
	{
		auto n = max(n_consumers_, n_producers_);
		thr_p_ = (ThrPos *)::_aligned_malloc(sizeof(ThrPos) * n, MEMORY_ALLOCATION_ALIGNMENT);
		assert(thr_p_);
		// Set per thread tail and head to ULONG_MAX.
		::memset((void *)thr_p_, 0xFF, sizeof(ThrPos) * n);

		ptr_array_ = (T **)::_aligned_malloc(Q_SIZE * sizeof(void *), MEMORY_ALLOCATION_ALIGNMENT);

		assert(ptr_array_);
	}

	~LockFreeQueue()
	{
		::free(ptr_array_);
		::free(thr_p_);
	}

	ThrPos&
		thr_pos() const
	{
		assert(ThrId() < max(n_consumers_, n_producers_));
		return thr_p_[ThrId()];
	}

	void
		push(T *ptr)
	{
		/*
		* Request next place to push.
		*
		* Second assignemnt is atomic only for head shift, so there is
		* a time window in which thr_p_[tid].head = ULONG_MAX, and
		* head could be shifted significantly by other threads,
		* so pop() will set last_head_ to head.
		* After that thr_p_[tid].head is setted to old head value
		* (which is stored in local CPU register) and written by @ptr.
		*
		* First assignment guaranties that pop() sees values for
		* head and thr_p_[tid].head not greater that they will be
		* after the second assignment with head shift.
		*
		* Loads and stores are not reordered with locked instructions,
		* se we don't need a memory barrier here.
		*/
		thr_pos().head = head_;
		thr_pos().head = ::InterlockedAdd((volatile LONG_PTR* )&head_, 1);

		/*
		* We do not know when a consumer uses the pop()'ed pointer,
		* se we can not overwrite it and have to wait the lowest tail.
		*/
		while (thr_pos().head >= last_tail_ + Q_SIZE)
		{
			auto min = tail_;

			// Update the last_tail_.
			for (size_t i = 0; i < n_consumers_; ++i) {
				auto tmp_t = thr_p_[i].tail;

				// Force compiler to use tmp_h exactly once.
				MemoryBarrier();

				if (tmp_t < min)
					min = tmp_t;
			}
			last_tail_ = min;

			if (thr_pos().head < last_tail_ + Q_SIZE)
				break;
			_mm_pause();
		}

		ptr_array_[thr_pos().head & Q_MASK] = ptr;

		// Allow consumers eat the item.
		thr_pos().head = ULONG_MAX;
	}

	T *
		pop()
	{
		/*
		* Request next place from which to pop.
		* See comments for push().
		*
		* Loads and stores are not reordered with locked instructions,
		* se we don't need a memory barrier here.
		*/
		thr_pos().tail = tail_;
		thr_pos().tail = ::InterlockedAdd((volatile LONG_PTR*)&tail_, 1);

		/*
		* tid'th place in ptr_array_ is reserved by the thread -
		* this place shall never be rewritten by push() and
		* last_tail_ at push() is a guarantee.
		* last_head_ guaraties that no any consumer eats the item
		* before producer reserved the position writes to it.
		*/
		while (thr_pos().tail >= last_head_)
		{
			auto min = head_;

			// Update the last_head_.
			for (size_t i = 0; i < n_producers_; ++i) {
				auto tmp_h = thr_p_[i].head;

				// Force compiler to use tmp_h exactly once.
				MemoryBarrier();

				if (tmp_h < min)
					min = tmp_h;
			}
			last_head_ = min;

			if (thr_pos().tail < last_head_)
				break;
			_mm_pause();
		}

		T *ret = ptr_array_[thr_pos().tail & Q_MASK];
		// Allow producers rewrite the slot.
		thr_pos().tail = ULONG_MAX;
		return ret;
	}

private:
	/*
	* The most hot members are cacheline aligned to avoid
	* False Sharing.
	*/

	const size_t n_producers_, n_consumers_;
	// currently free position (next to insert)
	volatile ULONG_PTR	head_ ;
	// current tail, next to pop
	volatile ULONG_PTR	tail_;
	// last not-processed producer's pointer
	volatile ULONG_PTR	last_head_;
	// last not-processed consumer's pointer
	volatile ULONG_PTR	last_tail_;
	ThrPos		*thr_p_;
	T		**ptr_array_;
};

//////////////////////////////////////////////////////////////////////////

template <typename T1, typename T2>
inline void copyDbgRegs(T1& dest, const T2& src)
{
	dest.Dr0 = src.Dr0;
	dest.Dr1 = src.Dr1;
	dest.Dr2 = src.Dr2;
	dest.Dr3 = src.Dr3;
	dest.Dr6 = src.Dr6;
	dest.Dr7 = src.Dr7;
}

#ifdef _M_X64
#define CTX_PC_REG(CTX)		(CTX)->Rip
#else
#define CTX_PC_REG(CTX)		(CTX)->Eip
#endif // #ifdef _M_X64

void cloneThreadContext(CONTEXT* dest, const CONTEXT* src, DWORD ContextFlags);

bool LoadRemoteDll(DWORD pid, const char* dllPath);
BOOL injectDllByRemoteThread(DWORD pid, HMODULE hInst);
BOOL injectDllByWinHook(DWORD pid, HMODULE hInst);

typedef struct _UNICODE_STRING {
	USHORT  Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING, *PCUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA, *PCLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED		1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED	2

typedef ULONG KPRIORITY;

typedef struct _CLIENT_ID {
	ULONG_PTR   UniqueProcess;
	ULONG_PTR   UniqueThread;
} CLIENT_ID;
typedef   CLIENT_ID   *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

//////////////////////////////////////////////////////////////////////////
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage; // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags; // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	// PVOID LoadedImports; // seems they are exist only on XP !!!
	// PVOID EntryPointActivationContext; // -same-
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InLoadOrderModuleList
	LIST_ENTRY InMemoryOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList
	LIST_ENTRY InInitializationOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InInitializationOrderModuleList
} PEB_LDR_DATA, *PPEB_LDR_DATA;

#ifdef _M_X64
inline PVOID _GetCurrentPeb()
{
	assert(false);
}

#else
inline PVOID _GetCurrentPeb()
{
	_asm mov eax, fs:[0x30]
}
#endif
//////////////////////////////////////////////////////////////////////////

PVOID WINAPI GetThreadStartAddress(HANDLE hThread);
PVOID WINAPI GetThreadStartAddress(DWORD tid);
DWORD WINAPI GetThreadIdFromHandle(HANDLE hThread, LPDWORD processId = NULL);
_TEB* GetThreadTeb(DWORD tid);
DWORD GetProcessMainThread(DWORD dwProcID);
DWORD WINAPI GetProcessIdFromHandle(HANDLE hProcess);
