#include "MemoryHelper.h"
#include "MemoryPool.h"


void EnterResourceLock(PERESOURCE Resource,KIRQL* Irql)
{
	KeRaiseIrql(APC_LEVEL, Irql);                     
	ExAcquireResourceExclusiveLite(Resource, TRUE);
}

void LeaveResourceLock(PERESOURCE Resource, KIRQL Irql)
{
	ExReleaseResourceLite(Resource);
	KeLowerIrql(Irql);

}

BOOLEAN GetResourceLock(PERESOURCE* Resource, BOOLEAN IsMsg)
{
    *Resource = ExAllocatePoolWithTag(NonPagedPool, sizeof(ERESOURCE), POOL_TAG);
    if (*Resource) {
        ExInitializeResourceLite(*Resource);
        
        
        return TRUE;
    }
    else {
   
        return FALSE;
    }
}
void FreeResourceLock(PERESOURCE* Resource)
{
    if (*Resource) {
        ExDeleteResourceLite(*Resource);
        ExFreePoolWithTag(*Resource, POOL_TAG);
        *Resource = NULL;
    }
}