#include "MemoryHelper.h"
#include "MemoryPool.h"

BOOLEAN __IsLocked;
void EnterResourceLock()
{
	const LONG ThreadIdentity = (LONG)GetCurrentThreadId();      
	

    if (InterlockedCompareExchange(&__Pool->Thread, ThreadIdentity, 0) != ThreadIdentity) {
       
        __IsLocked = TRUE;
        EnterCriticalSection(&__Pool->CriticalSection);
        __Pool->Thread = ThreadIdentity;
    }
    else                                             
        __IsLocked = FALSE;

}

void LeaveResourceLock()
{
    const LONG ThreadIdentity = (LONG)GetCurrentThreadId();
 
    if (__IsLocked) {
        __Pool->Thread = ThreadIdentity;
        LeaveCriticalSection(&__Pool->CriticalSection);
        InterlockedExchange(&__Pool->Thread, 0);
    }

    __IsLocked = FALSE;
}

