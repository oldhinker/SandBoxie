#pragma once
#include "Common.h"
#include "MemoryList.h"


#define POOL_TAG    'LOOP' 

enum {
    FIRST_ABEND = 0,
    FREE_SIZE_MISMATCH = 1,
    FREE_NULL_PTR_OR_ZERO_SIZE = 2,
    FREE_LARGE_CHUNK_EYECATCHER_MISMATCH = 4,
    FREE_CELLS_EYECATCHER_MISMATCH = 6,
    LAST_ABEND
};


#if defined(KERNEL_MODE) && (POOL_DEBUG == 0)
#define ABEND(why) \
    KeBugCheckEx(DRIVER_CORRUPTED_MMPOOL, (ULONG_PTR)POOL_TAG, why, 0, 0)
#else /* ! KERNEL_MODE || POOL_DEBUG */
#define ABEND(why) { OutputDebugString(L"pool abend " L#why L"\n"); __debugbreak();  }
#endif


typedef struct _PAGE_ PAGE,*PPAGE;
typedef struct _POOL_ POOL,*PPOOL;
typedef struct _LARGE_CHUNK_ LARGE_CHUNK, *PLARGE_CHUNK;



#if defined(KERNEL_MODE)

#define POOL_PAGE_SIZE          4096            // system page size
#define POOL_CELL_SIZE          16
#ifdef _WIN64
#define POOL_MASK_LEFT          0xFFFFFFFFFFFFF000UL
#else
#define POOL_MASK_LEFT          0xFFFFF000UL
#endif
#define POOL_MASK_RIGHT         0xFFF


#else /* ! KERNEL_MODE */

#define POOL_PAGE_SIZE          65536           // VirtualAlloc granularity
#define POOL_CELL_SIZE          128
#ifdef _WIN64
#define POOL_MASK_LEFT          0xFFFFFFFFFFFF0000UL
#else
#define POOL_MASK_LEFT          0xFFFF0000UL
#endif
#define POOL_MASK_RIGHT         0xFFFF
#endif

#define PAD_8(p)        (((p) + 7) & ~7)
#define PAD_CELL(p)     (((p) + POOL_CELL_SIZE - 1) & ~(POOL_CELL_SIZE - 1))
#define NUM_CELLS(n)    (PAD_CELL(n) / POOL_CELL_SIZE)


// size of header part of a pool page, padded to cell size
#define PAGE_HEADER_SIZE    PAD_CELL(sizeof(PAGE))

// calculate how many bytes would be needed for a bitmap,
// if the bitmap itself was not part of the page, padded to cell-size
#define PAGE_BITMAP_SIZE    \
    PAD_CELL(((POOL_PAGE_SIZE - PAGE_HEADER_SIZE) / POOL_CELL_SIZE + 7) / 8)

// number of cells in a single pool page
#define NUM_PAGE_CELLS      \
    ((POOL_PAGE_SIZE - PAGE_HEADER_SIZE - PAGE_BITMAP_SIZE) / POOL_CELL_SIZE)


// size of LARGE_CHUNK structure, padded to 8-bytes
#define LARGE_CHUNK_SIZE    PAD_8(sizeof(LARGE_CHUNK))


// Maximum possible size for a large chunk
#define LARGE_CHUNK_MAXIMUM     (0xFFFFFFFFu - (LARGE_CHUNK_SIZE + POOL_PAGE_SIZE))

#define LARGE_CHUNK_MINIMUM     (POOL_PAGE_SIZE * 3 / 4)
#define FULL_PAGE_THRESHOLD     4

struct _PAGE_
{

    NODE Node;
    PPAGE Next;
    PPOOL Pool;
    ULONG EyeCatcher;
    USHORT Frees;                    // estimated, not accurate
};


struct _POOL_ 
{

    ULONG EyeCatcher;

#ifdef POOL_USE_CUSTOM_LOCK

    LOCK pages_lock;
    LOCK large_chunks_lock;

#elif defined(KERNEL_MODE)

    PERESOURCE ResourceLock;   //资源锁

#else /* ! KERNEL_MODE */

    volatile LONG Thread;
    CRITICAL_SECTION CriticalSection;

#endif

    LIST Pages; //[][]                        // pages searched during allocation
    LIST FullPages;//[]                    // full pages that are not searched
    LIST LargeChunks;

    UCHAR Bitmap[PAGE_BITMAP_SIZE];
};


struct _LARGE_CHUNK_ {

    NODE Node;
    ULONG EyeCatcher;
    POOL* Pool;
    void* VirtualAddress;
    ULONG ViewSize;                         // multiple of POOL_PAGE_SIZE

};




PPOOL CreateMemoryPool(void);    //创建内存管理员
POOL* CreateMemoryPoolWithTagged(ULONG Tag);
ULONG DeleteMemoryPool(POOL* Pool);

PPAGE AllocateMemoryPage(POOL* Pool, ULONG Tag);   //内核的虚拟真正分配
void* MemoryPoolAllocate(POOL* Pool, ULONG ViewSize);
void MemoryPoolFree(void* VirtualAddress, ULONG ViewSize);
void* AllocateLargeChunk(POOL* Pool, ULONG ViewSize);
void FreeLargeChunk(void* VirtualAddress, ULONG ViewSize);
void* AllocateCells(POOL* Pool, ULONG ViewSize);
void FreeCells(void* VirtualAddress, ULONG ViewSize);
ULONG FindCells(PAGE* Page, ULONG ViewSize);
extern PPOOL __Pool;