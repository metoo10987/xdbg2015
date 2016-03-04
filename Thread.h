#pragma once

class Thread
{
public:
	Thread(void);
	virtual ~Thread(void);

	virtual bool init()
	{
		return true;
	}
	
	virtual long run() = 0;

	virtual void final(int result)
	{

	}

	bool start(size_t stackSize = 0);
	void stop(int exitCode = 0);

	void wait();

	int getId() const
	{
		return _threadId;
	}

protected:
	static DWORD __stdcall threadProc(void* param);

protected:
	DWORD		_threadId;
	HANDLE		_threadHandle;
};
