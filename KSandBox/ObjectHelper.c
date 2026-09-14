#include "ObjectHelper.h"
#include "SystemHelper.h"
#include "MemoryHelper.h"

LPFN_OBQUERYNAMEINFO __ObQueryNameInfo = NULL;
LPFN_OBGETOBJECTTYPE __ObGetObjectType = NULL;   //内核的导出函数
POBJECT_TYPE*  __ObjectTypes = NULL;   //二维指针   指针数组


static const WCHAR _UnnamedName = L'\0';

const OBJECT_NAME_INFORMATION __UnnamedObject = {
    { 0, 0, (WCHAR*)&_UnnamedName } };




BOOLEAN InitializeObject(void)
{
    if (__OsVersion >= WINDOWS_7) {

     
        /*
        kd> dt _UNICODE_STRING
nt!_UNICODE_STRING
   +0x000 Length           : Uint2B
   +0x002 MaximumLength    : Uint2B
   +0x008 Buffer           : Ptr64 Uint2B
        */

        UNICODE_STRING v1;    //
        void* v5 = NULL;
       
        RtlInitUnicodeString(&v1, L"ObQueryNameInfo");   //0x1000
        v5 = MmGetSystemRoutineAddress(&v1);
        if (!v5) {
          
            return FALSE;
        }

        __ObQueryNameInfo = (LPFN_OBQUERYNAMEINFO)v5;

        //fffff800`04128db0

        RtlInitUnicodeString(&v1, L"ObGetObjectType");
        v5 = MmGetSystemRoutineAddress(&v1);
        if (!v5) {
          
            return FALSE;
        }

        __ObGetObjectType = (LPFN_OBGETOBJECTTYPE)v5;

        //fffff800`04128eb4
    }

    __ObjectTypes = AllocateMemoryEx(
        __Pool, sizeof(POBJECT_TYPE) * 10, TRUE);


    if (!__ObjectTypes)
        return FALSE;
    MemoryZero(__ObjectTypes, sizeof(POBJECT_TYPE) * 10);



    if (!GetObjectTypeEx(L"Job")) // PsJobType
        return FALSE;
    if (!GetObjectTypeEx(L"Event")) // ExEventObjectType
        return FALSE;
    if (!GetObjectTypeEx(L"Mutant")) // ExMutantObjectType - not exported
        return FALSE;
    if (!GetObjectTypeEx(L"Semaphore")) // ExSemaphoreObjectType
        return FALSE;
    if (!GetObjectTypeEx(L"Section")) // MmSectionObjectType
        return FALSE;
#ifdef XP_SUPPORT
    if (__OsVersion < WINDOWS_VISTA) {
        if (!GetObjectTypeEx(L"Port")) // LpcPortObjectType
            return FALSE;
    }
    else
#endif
    {
        if (!GetObjectTypeEx(L"ALPC Port"))  // AlpcPortObjectType - not exported
            return FALSE;
    }
    if (!GetObjectTypeEx(L"SymbolicLink")) // ObpSymbolicLinkObjectType - not exported
        return FALSE;


    return TRUE;
}

OBJECT_TYPE* GetObjectType(const WCHAR* TypeName)
{
    NTSTATUS Status;
    WCHAR v1[64];
    UNICODE_STRING v2;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    OBJECT_TYPE* Object;

    wcscpy(v1, L"\\ObjectTypes\\");  
    wcscat(v1, TypeName);
    RtlInitUnicodeString(&v2, v1);
    InitializeObjectAttributes(&ObjectAttributes,
        &v2, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //
    // Windows 7 requires that we pass ObjectType in the second parameter
    // below, while earlier versions of Windows do not require this.
    // Obj_GetTypeObjectType() returns ObjectType on Windows 7, and
    // NULL on earlier versions of Windows
    //

    //ObjectTypes\Process


    Status = ObOpenObjectByName(
        &ObjectAttributes, GetTypeObjectType(), KernelMode,
        NULL, 0, NULL, &Handle);
    if (!NT_SUCCESS(Status)) {

        return NULL;
    }

    Status = ObReferenceObjectByHandle(
        Handle, 0, NULL, KernelMode, &Object, NULL);

    ZwClose(Handle);

    if (!NT_SUCCESS(Status)) {
    
        return NULL;
    }

    ObDereferenceObject(Object);

    return Object;
}

BOOLEAN GetObjectTypeEx(const WCHAR* TypeName)  
{
    OBJECT_TYPE* ObjectType = NULL ;
    ULONG i;

    ObjectType = GetObjectType(TypeName);
    if (ObjectType == NULL)
        return FALSE;

    for (i = 0; __ObjectTypes[i]; ++i)
    {

    }
    __ObjectTypes[i] = ObjectType;

    return TRUE;
}




#ifdef _M_ARM64
POBJECT_TYPE GetTypeObjectType(void)
{
    static POBJECT_TYPE _TypeObjectType = NULL;

    if (!_TypeObjectType) {

        _TypeObjectType = __ObGetObjectType(*PsProcessType);
    }

    return _TypeObjectType;
}
#else
POBJECT_TYPE GetTypeObjectType(void)
{
    static POBJECT_TYPE _TypeObjectType = NULL;

    //
    // on Windows 7 we need to find ObpTypeObjectType.  it is not
    // exported, but a new Windows 7 exported function, ObGetObjectType,
    // references an object type table with the following instruction:
    //          mov eax,dword ptr [nt!ObTypeIndexTable+eax*4]
    // ObpTypeObjectType is the third pointer in the table

    if ((__OsVersion >= WINDOWS_7) && (!_TypeObjectType)) {

        const ULONG status = STATUS_UNSUCCESSFUL;
        static const WCHAR* TypeName = L"ObjectType";

        POBJECT_TYPE Type;
        UNICODE_STRING* Name;

        //
        // analyze ObGetObjectType to find ObTypeIndexTable
        //

        POBJECT_TYPE* ObTypeIndexTable = NULL;

        UCHAR* v1 = (UCHAR*)__ObGetObjectType;

        /*
        kd> u ObGetObjectType
nt!ObGetObjectType:
fffff800`04128eb4 0fb641e8        movzx   eax,byte ptr [rcx-18h]
fffff800`04128eb8 488d0d c11cf0ff  lea     rcx,[nt!ObTypeIndexTable (fffff800`0402ab80)]
fffff800`04128ebf 488b04c1        mov     rax,qword ptr [rcx+rax*8]

        */



        if (v1) {

            ULONG i;

#ifdef _WIN64
            if (__OsVersion < WINDOWS_10) {
                for (i = 0; i < 16; ++i) {
                    if (v1[i + 0] == 0x48 &&       // lea rcx,nt!ObTypeIndexTable
                        v1[i + 1] == 0x8D &&
                        v1[i + 2] == 0x0D)
                    {

                        //fffff800`04128eb8  +  7 + fff01cc1


                        LONG Offset = *(LONG*)(v1 + i + 3);
                        ObTypeIndexTable =
                            (POBJECT_TYPE*)(v1 + i + 7 + Offset);
                    }
                }
            }
            else 
            {
                for (i = 0x1c; i < 0x2c; ++i) {
                    if (v1[i + 0] == 0x48 &&       // lea rcx,nt!ObTypeIndexTable
                        v1[i + 1] == 0x8D &&
                        v1[i + 2] == 0x0D)
                    {
                        LONG Offset = *(LONG*)(v1 + i + 3);
                        ObTypeIndexTable =
                            (POBJECT_TYPE*)(v1 + i + 7 + Offset);
                    }
                }
            }
#else ! _WIN64
            UCHAR k = 0;
            if (__OsVersion >= WINDOWS_10) {
                k = 0x1c;
            }

            /*
            nt!ObGetObjectType:
84a94b68 8bff            mov     edi,edi
84a94b6a 55              push    ebp
84a94b6b 8bec            mov     ebp,esp
84a94b6d 8b4508          mov     eax,dword ptr [ebp+8]
84a94b70 0fb640f4        movzx   eax,byte ptr [eax-0Ch]
84a94b74 8b048580f59784  mov     eax,dword ptr nt!ObTypeIndexTable (8497f580)[eax*4]       
            */



            for (i = k; i < (ULONG)16 + k; ++i) {
                if (v1[i + 0] == 0x8B &&       // mov eax,[...+eax*4]
                    v1[i + 1] == 0x04 &&
                    v1[i + 2] == 0x85)
                {
                    ULONG_PTR* v4 = (ULONG_PTR*)(v1 + i + 3);
                    ObTypeIndexTable = (POBJECT_TYPE*)*v4;
                }
            }
#endif _WIN64
           
        }

        if (!ObTypeIndexTable) {
           
            return FALSE;
        }

        //
        // make sure ObTypeIndexTable[2] points to the "Type" object type
        //


        Type = ObTypeIndexTable[2];

       /*
       kd> dq fffff800`0402ab80
fffff800`0402ab80  00000000`00000000 00000000`bad0b0b0
fffff800`0402ab90  fffffa80`61066b30 fffffa80`610669e0



       3: kd> dd 8497f580
ReadVirtual: 8497f580 not properly sign extended
8497f580  00000000 bad0b0b0 8784e700 8784e638
8497f590  8784e570 878eef30 878eedf0 878eed28

       
       */

#ifdef _WIN64

        if ((!Type) || ((ULONG_PTR)Type >= 0xFFFFFFFF00000000)) 
        {
           
            return FALSE;
        }

#else ! _WIN64

        if ((!Type) || ((ULONG_PTR)Type >= 0xFFFF0000)) {
          
            return FALSE;
        }

#endif _WIN64

        /*
        kd> dq fffffa80`61066b30 
fffffa80`61066b30  fffffa80`61066ae0 fffffa80`621f0af0
fffffa80`61066b40  00000000`000a0008 fffff8a0`000017c0
fffffa80`61066b50  fffff800`04029220 0000002a`00000002
fffffa80`61066b60  0000002a`00000000 00000000`00000000
fffffa80`61066b70  00000000`00240070 00020000`00000100
fffffa80`61066b80  00020000`00020000 001f0001`000f0001
fffffa80`61066b90  00000000`00000000 00000128`00000000
fffffa80`61066ba0  00000000`00000000 00000000`00000000
kd> db fffff8a0`000017c0
fffff8a0`000017c0  54 00 79 00 70 00 65 00-00 00 00 00 00 00 00 00  T.y.p.e..




        3: kd> dd 8784e700
8784e700  8784e6d8 888ea820 000a0008 8e401b10
8784e710  8497e860 00000002 0000002a 00000000
8784e720  0000002a 00000000 00240050 00000000
8784e730  00000100 00020000 00020000 00020000
8784e740  000f0001 001f0001 00000000 00000000
8784e750  00000000 000000b8 00000000 00000000
8784e760  00000000 00000000 00000000 84aa1936
8784e770  00000000 00000000 00000000 546a624f
3: kd> db 8e401b10
ReadVirtual: 8e401b10 not properly sign extended
8e401b10  54 00 79 00 70 00 65 00-00 00 00 00 00 00 00 00  T.y.p.e.........
8e401b20  03 02 09 06 4f 62 74 62-01 60 8e af 00 00 00 00  ....Obtb.`......

        
        */
        Name = &((OBJECT_TYPE_VISTA_SP1*)Type)->Name;
        if (Name->Length != 8 ||
            Name->Buffer[0] != L'T' || Name->Buffer[1] != L'y' ||
            Name->Buffer[2] != L'p' || Name->Buffer[3] != L'e') {
         
            return FALSE;
        }

        _TypeObjectType = Type;
    }

    return _TypeObjectType;
}
#endif





NTSTATUS GetObjectName(
    POOL* Pool, void* Object,
    OBJECT_NAME_INFORMATION** ObjectNameInfo, ULONG* NameLength)
{
    NTSTATUS Status;
    UCHAR v5[80];
    OBJECT_NAME_INFORMATION* v1;
    ULONG v7;
    OBJECT_NAME_INFORMATION* v9;
    ULONG v10;

    *ObjectNameInfo = NULL;
    *NameLength = 0;

    //
    // invoke ObQueryNameString on the small buffer.  the small buffer
    // must be larger than sizeof(OBJECT_NAME_INFORMATION) even after
    // subtracting PAD_LEN bytes from it.  in other words, keep the
    // small buffer at least around 32 bytes (depending on PAD_LEN)
    //
    // sometimes ObQueryNameString gets confused and returns
    // STATUS_OBJECT_PATH_INVALID, in this case we just call with
    // a slightly smaller buffer
    //

    MemoryZero(v5, sizeof(v5));
    v1 = (OBJECT_NAME_INFORMATION*)v5;

    v7 = 0;        // must be initialized
    Status = ObQueryNameString(
        Object, v1, sizeof(v5) - PAD_LEN, &v7);

    if (Status == STATUS_OBJECT_PATH_INVALID) {

        v7 = 0;        // must be initialized
        Status = ObQueryNameString(
            Object, v1,
            sizeof(v5) - PAD_LEN * 2, &v7);
    }

    if (NT_SUCCESS(Status)) {

        //
        // we got the name completely into the small buffer, so we
        // allocate a pool buffer and copy the name string
        //

        if (v1->Name.Length && v1->Name.Buffer)
        {

            v10 = sizeof(OBJECT_NAME_INFORMATION)
                + v1->Name.Length + PAD_LEN * 2;
            v9 = (OBJECT_NAME_INFORMATION*)AllocateMemoryEx(Pool, v10,FALSE);
            if (!v9)
                return STATUS_INSUFFICIENT_RESOURCES;

            MemoryZero(v9, v10);
            v9->Name.Length = v1->Name.Length;
            v9->Name.MaximumLength = v1->Name.MaximumLength;
            v9->Name.Buffer =
                (WCHAR*)(((UCHAR*)v9) + sizeof(UNICODE_STRING));
            memcpy(v9->Name.Buffer,
                v1->Name.Buffer,
                v1->Name.Length);

        }
        else {

            v9 = NULL;
            v10 = 0;
        }

        goto Exit;
    }

    if (Status != STATUS_INFO_LENGTH_MISMATCH &&
        Status != STATUS_BUFFER_OVERFLOW) {

        return Status;
    }

    //
    // on Windows 2000, we may get STATUS_INFO_LENGTH_MISMATCH but
    // a result length of zero, in this case we must try again
    // with a larger buffer
    //

    v9 = NULL;
    v10 = 0;

    while (!v7) 
    {

        if (v9)
            FreeMemoryEx(v9, v10);
        v10 += 128;
        v9 = (OBJECT_NAME_INFORMATION*)AllocateMemoryEx(Pool, v10,FALSE);
        if (!v9)
            return STATUS_INSUFFICIENT_RESOURCES;

        MemoryZero(v9, v10);
        v7 = 0;        // must be initialized
        Status = ObQueryNameString(
            Object, v9, v10 - PAD_LEN, &v7);

        if (NT_SUCCESS(Status))
            break;

        if (Status == STATUS_OBJECT_PATH_INVALID) {

            v7 = 0;        // must be initialized
            Status = ObQueryNameString(
                Object, v9, v10 - PAD_LEN * 2, &v7);
        }

        if (Status != STATUS_INFO_LENGTH_MISMATCH &&
            Status != STATUS_BUFFER_OVERFLOW) {

            FreeMemoryEx(v9, v10);
            return Status;
        }

        v7 = 0;
    }

    //
    // on Windows XP, we should have gotten a result length, and not
    // went into the loop above, so info is still NULL, and we need
    // to allocate it and query the name again
    //

    if (!v9) {

        v10 = v7 + PAD_LEN * 2;
        v9 = (OBJECT_NAME_INFORMATION*)AllocateMemoryEx(Pool, v10,FALSE);
        if (!v9)
            return STATUS_INSUFFICIENT_RESOURCES;

        MemoryZero(v9, v10);
        v7 = 0;        // must be initialized
        Status = ObQueryNameString(
            Object, v9, v10 - PAD_LEN, &v7);

        if (!NT_SUCCESS(Status)) {
            FreeMemoryEx(v9, v10);
            return Status;
        }
    }

    //
    // finally we only have to make sure that the name isn't empty
    //

Exit:

    if (v9 && v9->Name.Length && v9->Name.Buffer) {

        //
        // On Windows 7, we may get two leading backslashes
        //

        if (__OsVersion >= WINDOWS_7 &&
            v9->Name.Length >= 2 * sizeof(WCHAR) &&
            v9->Name.Buffer[0] == L'\\' &&
            v9->Name.Buffer[1] == L'\\') {

            WCHAR* Buffer = v9->Name.Buffer;
            USHORT Length = v9->Name.Length;

            Length = Length / sizeof(WCHAR) - 1;
            wmemmove(Buffer, Buffer + 1, Length);
            Buffer[Length] = L'\0';

            v9->Name.Length -= sizeof(WCHAR);
            v9->Name.MaximumLength -= sizeof(WCHAR);
        }

        *ObjectNameInfo = v9;
        *NameLength = v10;

    }
    else {

        if (v9)
            FreeMemoryEx(v9, v10);

        *ObjectNameInfo = (OBJECT_NAME_INFORMATION*)&__UnnamedObject;
        *NameLength = 0;
    }

    /*if (0) {
        OBJECT_NAME_INFORMATION *xname = *Name;
        WCHAR *xbuf = xname->Name.Buffer;
        ULONG xlen  = xname->Name.Length / sizeof(WCHAR);
        DbgPrint("Object Name: %*.*S\n", xlen, xlen, xbuf);
    }*/

    return STATUS_SUCCESS;
}