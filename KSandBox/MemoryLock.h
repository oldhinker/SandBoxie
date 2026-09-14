#pragma once
#include "Common.h"
void EnterResourceLock(PERESOURCE Resource, KIRQL* Irql);
void LeaveResourceLock(PERESOURCE Resource, KIRQL Irql);

BOOLEAN GetResourceLock(PERESOURCE* Resource, BOOLEAN IsMsg);
void FreeResourceLock(PERESOURCE* Resource);