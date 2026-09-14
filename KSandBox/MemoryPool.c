#include "MemoryPool.h"
#include "MemoryHelper.h"
#include "MemoryList.h"
#include "MemoryLock.h"




PPOOL __Pool = NULL;
KIRQL __Irql;

PPOOL CreateMemoryPool(void)
{
    return CreateMemoryPoolWithTagged(POOL_TAG);
}
ULONG DeleteMemoryPool(POOL* Pool)
{
    LARGE_CHUNK* LargeChunk;
    PAGE* Page;
    ULONG v7 = 0;

    // if this pool tracks any allocated large chunks, free them now

    LargeChunk = (LARGE_CHUNK*)GetListHead(&Pool->LargeChunks);
    while (LargeChunk) {
        LARGE_CHUNK* v1 = (LARGE_CHUNK*)GetNextNode(LargeChunk);
        v7 += LargeChunk->ViewSize / POOL_PAGE_SIZE;
        FreeMemory(LargeChunk->VirtualAddress, LargeChunk->EyeCatcher);
        LargeChunk = v1;
    }

    // free pages used by this pool, but make sure not to free the page that
    // contains the pool, until all other pages have been freed

    Page = (PAGE*)GetListHead(&Pool->Pages);
    while (Page) {
        PAGE* v1 = (PAGE*)GetNextNode(Page);
        if (((ULONG_PTR)Pool & POOL_MASK_LEFT) != (ULONG_PTR)Page)
            FreeMemory(Page, Page->EyeCatcher);
        ++v7;
        Page = v1;
    }

    Page = (PAGE*)GetListHead(&Pool->FullPages);
    while (Page) {
        PAGE* v1 = (PAGE*)GetNextNode(Page);
        if (((ULONG_PTR)Pool & POOL_MASK_LEFT) != (ULONG_PTR)Page)
            FreeMemory(Page, Page->EyeCatcher);
        ++v7;
        Page = v1;
    }

#ifdef POOL_USE_CUSTOM_LOCK
#elif defined(KERNEL_MODE)
    ExDeleteResourceLite(Pool->ResourceLock);
    ExFreePoolWithTag(Pool->ResourceLock, Pool->EyeCatcher);
#else /* ! KERNEL_MODE */
    DeleteCriticalSection(&Pool->CriticalSection);
#endif
    //销毁管理员
    Page = (PAGE*)((ULONG_PTR)Pool & POOL_MASK_LEFT);
    FreeMemory(Page, Page->EyeCatcher);

 

    return v7;
}



PPOOL CreateMemoryPoolWithTagged(ULONG Tag)
{
    PPAGE Page;
    UCHAR* Bitmap;
    ULONG i, Offset, Bit;
    POOL* Pool = NULL;

    


    //[] Page   0x1000
    //[]
    //[PAGE_HEADER_SIZE] 
    //[PAGE_BITMAP_SIZE] Bitmap
    //[AAAAAAAAAAAAAAAAA]

    //[]                 Pool   0x5000
    //

    //[0x2000]           new PERESOURCE 
    //[Pages] 0x1000
    //[FullPages]
    //[LargeChunks]   
    //[AAAAAAAAAAAAAAAAA] Bitmap



    Page = AllocateMemoryPage(NULL, Tag);
    if (!Page)
        return NULL;
    Bitmap = (UCHAR*)Page + PAGE_HEADER_SIZE;
    MemoryZero(Bitmap, PAGE_BITMAP_SIZE);//[   Bitmap]
    i = NUM_PAGE_CELLS;
    while (1) {
        Offset = i / 8;
        Bit = 1 << (i & 7);
        if (Offset >= PAGE_BITMAP_SIZE)
            break;
        if (Bit == 1) {
            Bitmap[Offset] = 0xFF;
            i += 8;
        }
        else {
            Bitmap[Offset] |= Bit;
            ++i;
        }
    }
    Pool = (POOL*)((UCHAR*)Page + PAGE_HEADER_SIZE + PAGE_BITMAP_SIZE);

    Page->Pool = Pool;

    Pool->EyeCatcher = Tag;



#ifdef POOL_USE_CUSTOM_LOCK

    Pool->pages_lock = LOCK_FREE;
    Pool->large_chunks_lock = LOCK_FREE;

#elif defined(KERNEL_MODE)

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    Pool->ResourceLock = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(ERESOURCE), Tag);
#else
    Pool->ResourceLock = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(ERESOURCE), Tag);    //动态申请资源锁
#endif
    if (!Pool->ResourceLock) {
        FreeMemory(Page, Tag);   //释放内存
        return NULL;
    }
    ExInitializeResourceLite(Pool->ResourceLock);   //初始化

#else /* ! KERNEL_MODE */

    InterlockedExchange(&Pool->Thread, 0);   //原子锁
    InitializeCriticalSectionAndSpinCount(&Pool->CriticalSection, 1000);   //自旋锁

#endif

    memcpy(Pool->Bitmap, Bitmap, PAGE_BITMAP_SIZE);

    InitializeList(&Pool->Pages);
    InsertBefore(&Pool->Pages, NULL, Page);

    InitializeList(&Pool->FullPages);
    InitializeList(&Pool->LargeChunks);

    // mark in the bitmap, the cells allocated to the pool structure

    i = 0;
    while (i < NUM_CELLS(sizeof(POOL))) {
        Offset = i / 8;
        Bit = 1 << (i & 7);
        Bitmap[Offset] |= Bit;
        ++i;
    }

    return Pool;
}
void* MemoryPoolAllocate(POOL* Pool, ULONG ViewSize)
{
    if (ViewSize >= LARGE_CHUNK_MAXIMUM)
        return NULL;

    void* v5 = NULL;
    if (ViewSize) {

#if POOL_DEBUG
        ULONG v7 = ViewSize;  //10[]
        v7 += sizeof(ULONG);
#endif

        if (ViewSize > LARGE_CHUNK_MINIMUM)
        {
            v5 = AllocateLargeChunk(Pool, ViewSize);
        } 
        else
        {
            v5 = AllocateCells(Pool, NUM_CELLS(ViewSize));
        }
            

#if POOL_DEBUG
        if (v5) 
        {
            *(ULONG*)((UCHAR*)v5 + v7) = ViewSize;
            // printf("put %d (at %08X) for %08X\n", size, (ULONG *)((UCHAR *)ptr + caller_size), ptr);
        }
#endif
    }

#if 0
#if defined(KERNEL_MODE)
#endif
#endif

    return v5;
}
void MemoryPoolFree(void* VirtualAddress, ULONG ViewSize)
{
    if (VirtualAddress && ViewSize) 
    {

#if POOL_DEBUG
        ULONG caller_size = ViewSize;
        size += sizeof(ULONG);
        if (*(ULONG*)((UCHAR*)ptr + caller_size) != size) {
            // printf("got %d (at %08X), expected %d for %08X\n", *(ULONG *)((UCHAR *)ptr + caller_size), (ULONG *)((UCHAR *)ptr + caller_size), size, ptr);
            ABEND(POOL_FREE_SIZE_MISMATCH);
        }
#endif

        // if the pointer is page-aligned, this must be a LARGE_CHUNK
        if (((ULONG_PTR)VirtualAddress & (POOL_PAGE_SIZE - 1)) == 0)
            FreeLargeChunk(VirtualAddress, ViewSize);
        else
            FreeCells(VirtualAddress, NUM_CELLS(ViewSize));

#if 0
#if defined(KERNEL_MODE)
      
#endif
#endif

    }
    else
    {

    }
    
}






PPAGE AllocateMemoryPage(POOL* Pool, ULONG Tag)
{
    PPAGE Page;


    Page = (PAGE*)AllocateMemory(PAGE_SIZE, Tag);
    if (Page) {

        Page->EyeCatcher = Tag;
        Page->Next = NULL;
        Page->Frees = NUM_PAGE_CELLS;   //0xfb 251


        //[               ]0x1000
        if (Pool) 
        {
            int v1 = PAGE_HEADER_SIZE;   //测试
            int v2 = PAGE_BITMAP_SIZE;


            UCHAR* Bitmap = (UCHAR*)Page + PAGE_HEADER_SIZE;
            memcpy(Bitmap, Pool->Bitmap, PAGE_BITMAP_SIZE);
            Page->Pool = Pool;
            InsertBefore(&Pool->Pages, NULL, Page);
        }
    }

    return Page;
}
void* AllocateLargeChunk(POOL* Pool, ULONG ViewSize)
{
  
    ULONG v7;
    void* v5;
    LARGE_CHUNK* LargeChunk;
  
    // pad the requested size to a multiple of POOL_PAGE_SIZE, after
    // adding the size of the (padded) LARGE_CHUNK structure
    v7 = (ViewSize + LARGE_CHUNK_SIZE + POOL_PAGE_SIZE - 1)
        & ~(POOL_PAGE_SIZE - 1);

    v5 = AllocateMemory(v7, Pool->EyeCatcher);   //分配内存
    if (!v5)
        return NULL;




    //[] Page   0x1000
    //[]
    //[PAGE_HEADER_SIZE] 
    //[PAGE_BITMAP_SIZE] Bitmap
    //[AAAAAAAAAAAAAAAAA]

    //[]                 Pool   0x5000
    //

    //[0x2000]           new PERESOURCE 
    //[Pages] 0x1000
    //[FullPages]
    //[LargeChunks]    0x30000
    //[AAAAAAAAAAAAAAAAA] Bitmap




    //[] v5  0x3000
    //[]
    //[]
    //[]
    //[LARGE_CHUNK_SIZE]  LargeChunk   0x30000
    //[EyeCatcher]
    //[Pool]   0x5000
    //[VirtualAddress] 0x3000
    //[ViewSize] v7



    // position the LARGE_CHUNK structure at the end of the last page
    LargeChunk = (LARGE_CHUNK*)
        ((UCHAR*)v5 + v7 - LARGE_CHUNK_SIZE);

    LargeChunk->EyeCatcher = Pool->EyeCatcher;
    LargeChunk->Pool = Pool;
    LargeChunk->VirtualAddress = v5;
    LargeChunk->ViewSize = v7;

    // lock the pool and add the allocated large chunk

    
    EnterResourceLock(Pool->ResourceLock, &__Irql);
    InsertBefore(&Pool->LargeChunks, NULL, LargeChunk);
    LeaveResourceLock(Pool->ResourceLock, __Irql);


    return v5;
}
void* AllocateCells(POOL* Pool, ULONG ViewSize)
{
  
    PAGE* Page = NULL;
    PAGE* Next = NULL;
    UCHAR* Bitmap;
    ULONG Mask;
    UCHAR* v5;
    ULONG Index = -1;


    // look for a page that has enough free cells to satisfy the request


    EnterResourceLock(Pool->ResourceLock, &__Irql);

    Page = (PAGE*)GetListHead(&Pool->Pages);
    while (Page) 
    {
        Next = (PAGE*)GetNextNode(Page);

        if (Page->EyeCatcher != Pool->EyeCatcher)
        {
            LeaveResourceLock(Pool->ResourceLock, __Irql);
            return NULL;   //报错处理
        }

        if (Page->Frees >= ViewSize) 
        {

            // the page says it has at least the number of cells we need.
            // if we find a block of enough free cells, break here

            Index = FindCells(Page, ViewSize);  //?????????????????
            if (Index != -1)
                break;

            // if there were not enough free cells, then adjust the page
            // to say it has at most one less than what we just asked for

            //当前的Page没有Cells
            Page->Frees = (USHORT)(ViewSize - 1);

            // after adjusting, if the page crosses the threshold and has
            // too few free cells to bother with it again, we move it to
            // the list of full pages that are not traversed

            if (Page->Frees < FULL_PAGE_THRESHOLD) {

                RemoveCurrent(&Pool->Pages, Page);
                InsertBefore(&Pool->FullPages, NULL, Page);
            }
        }

        Page = Next;
    }

   

    // if we couldn't find a page, we have to allocate a new page.

    //申请页
    if (!Page) {

        Page = AllocateMemoryPage(Pool, Pool->EyeCatcher);
        if (!Page) {
            LeaveResourceLock(Pool->ResourceLock, __Irql);
            return NULL;
        }

        Index = 0;
    }

    // after allocation, if the page crosses the threshold and has
    // too few free cells to bother with it again, we move it to
    // the list of full pages that are not traversed
    //[]1000


    Page->Frees = (USHORT)(Page->Frees - ViewSize);

    if (Page->Frees < FULL_PAGE_THRESHOLD) {   

        RemoveCurrent(&Pool->Pages, Page);
        InsertBefore(&Pool->FullPages, NULL, Page);
    }

    // we have a block of consecutive free cells of at least 'size' cells,
    // mark it in use (or at least some of it)

 
    // printf("Satisfied request for %d cells ", size);

    Bitmap = (UCHAR*)Page + PAGE_HEADER_SIZE + (Index / 8);
    Mask = 1 << (Index & 7);
    while (ViewSize) 
    {
        if (Mask == 1 && ViewSize > 8) {
            *Bitmap = 0xFF;
            ++Bitmap;
            ViewSize -= 8;
        }
        else {
            *Bitmap |= Mask;
            Mask <<= 1;
            Mask = (Mask & 0xFF) | (Mask >> 8);
            Bitmap += Mask & 1;
            --ViewSize;
        }
    }


    v5 = (UCHAR*)Page + PAGE_HEADER_SIZE + PAGE_BITMAP_SIZE
        + Index * POOL_CELL_SIZE;

    // printf(" at index %d address %08X (pool = %08X)\n", index, ptr, pool);
    // Pool_Print_Page(page);

  
    // unlock and return

    LeaveResourceLock(Pool->ResourceLock, __Irql);

    return v5;
}
ULONG FindCells(PAGE* Page, ULONG ViewSize)
{
    UCHAR* Bitmap = (UCHAR*)Page + PAGE_HEADER_SIZE;
    ULONG Mask = 1;
    ULONG i = 0;
    while (i < NUM_PAGE_CELLS) 
    {
        ULONG Bit = *Bitmap & Mask;
        ULONG j = i + 1;
        Mask <<= 1;
        Mask = (Mask & 0xFF) | (Mask >> 8);
        Bitmap += Mask & 1;
        if (Bit) 
        {
            while (j < NUM_PAGE_CELLS) {
                if (Mask == 1 && *Bitmap == 0xFF) {
                    j += 8;
                    ++Bitmap;
                }
                else {
                    if ((*Bitmap & Mask) == 0)
                        break;
                    ++j;
                    Mask <<= 1;
                    Mask = (Mask & 0xFF) | (Mask >> 8);
                    Bitmap += Mask & 1;
                }
            }
        }
        else {
            while (j < NUM_PAGE_CELLS && j - i < ViewSize) {
                if (Mask == 1 && *Bitmap == 0) {
                    j += 8;
                    ++Bitmap;
                }
                else {
                    if ((*Bitmap & Mask) != 0)
                        break;
                    ++j;
                    Mask <<= 1;
                    Mask = (Mask & 0xFF) | (Mask >> 8);
                    Bitmap += Mask & 1;
                }
            }
            if (j - i >= ViewSize) {
              
                return i;
            }
        }
        i = j;
    }

    return -1;
}


void FreeLargeChunk(void* VirtualAddress, ULONG ViewSize)
{
  
    ULONG v7;
    LARGE_CHUNK* v5;
    POOL* Pool;

    // pad the requested size to a multiple of POOL_PAGE_SIZE, after
    // adding the size of the (padded) LARGE_CHUNK structure
    v7 = (ViewSize + LARGE_CHUNK_SIZE + POOL_PAGE_SIZE - 1)
        & ~(POOL_PAGE_SIZE - 1);

    // LARGE_CHUNK structure is positioned at the end of the last page
    v5 = (LARGE_CHUNK*)
        ((UCHAR*)VirtualAddress + v7 - LARGE_CHUNK_SIZE);

    //if (large_chunk->eyecatcher != POOL_TAG)
    //    ABEND(POOL_FREE_LARGE_CHUNK_FIRST_EYECATCHER_MISMATCH);
    //pool = large_chunk->pool;
    //if (pool->eyecatcher != POOL_TAG)
    //    ABEND(POOL_FREE_LARGE_CHUNK_SECOND_EYECATCHER_MISMATCH);
    Pool = v5->Pool;
    if (v5->EyeCatcher != Pool->EyeCatcher)
    {
        ABEND(FREE_LARGE_CHUNK_EYECATCHER_MISMATCH);
    }
    EnterResourceLock(Pool->ResourceLock, &__Irql);

    RemoveCurrent(&Pool->LargeChunks, v5);

    LeaveResourceLock(Pool->ResourceLock, __Irql);

    FreeMemory(VirtualAddress, v5->EyeCatcher);
}
void FreeCells(void* VirtualAddress, ULONG ViewSize)
{
  
    PAGE* Page = (PAGE*)((ULONG_PTR)VirtualAddress & POOL_MASK_LEFT);
    ULONG Index =
        (((ULONG)(ULONG_PTR)VirtualAddress & POOL_MASK_RIGHT)
            - PAGE_HEADER_SIZE - PAGE_BITMAP_SIZE)
        / POOL_CELL_SIZE;
    UCHAR* Bitmap = (UCHAR*)Page + PAGE_HEADER_SIZE + Index / 8;
    ULONG Mask = 1 << (Index & 7);
    // printf("freeing ptr = %08X idx = %d (%d %d)\n", ptr, index, PAGE_HEADER_SIZE, PAGE_BITMAP_SIZE);

    POOL* Pool = Page->Pool;

    //if ((page->eyecatcher != POOL_TAG) || (pool->eyecatcher != POOL_TAG))
    if (Page->EyeCatcher != Pool->EyeCatcher)
    {
        ABEND(FREE_CELLS_EYECATCHER_MISMATCH);
    }
    EnterResourceLock(Pool->ResourceLock, &__Irql);


    // if after de-allocation, a full page crosses threshold in reverse,
    // we move it to the list of usable pages

    if (Page->Frees < FULL_PAGE_THRESHOLD &&
        Page->Frees + ViewSize >= FULL_PAGE_THRESHOLD) {

        RemoveCurrent(&Pool->FullPages, Page);  
        InsertBefore(&Pool->Pages, NULL, Page);
    }
    //[][][][][][]
    Page->Frees = (USHORT)(Page->Frees + ViewSize);

    // indicate the cells are now free

    while (ViewSize) {
        if (Mask == 1 && ViewSize > 8) {
            *Bitmap = 0;
            ++Bitmap;
            ViewSize -= 8;
        }
        else {
            *Bitmap &= ~Mask;
            Mask <<= 1;
            Mask = (Mask & 0xFF) | (Mask >> 8);
            Bitmap += Mask & 1;
            --ViewSize;
        }
    }

    LeaveResourceLock(Pool->ResourceLock, __Irql);
}