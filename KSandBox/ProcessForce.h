#pragma once
#include "Common.h"
#include "Box.h"




typedef struct _FORCE_BOX {

    NODE Node;
    BOX* Box;
  

} FORCE_BOX;


BOX* GetForcedStartBox(
    HANDLE ProcessIdentity, HANDLE ParentProcessIdentity, const WCHAR* ImagePath, BOOLEAN* IsHostInject, const WCHAR* SidString);


void CreateForceData(
    LIST* Boxes, const WCHAR* SidString, ULONG SessionIdentity);
void DeleteForceData(LIST* Boxes);

BOX* CheckBoxPath(LIST* Boxes, const WCHAR* ImagePath);