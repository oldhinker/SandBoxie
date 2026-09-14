#pragma once
#include "Common.h"




typedef struct _NODE_ NODE, *PNODE;
typedef struct _LIST_ LIST, *PLIST;

#ifndef LIST_WITH_MEMORY_MANAGEMENT
#include <memory.h>
/* Initializes list structure */
#define InitializeList(List) (memset((List),0,sizeof(LIST)))
#endif

/* Return head elem of list LIST */
#define GetListHead(List) ((void *)(((LIST *)(List))->Head))

/* Return tail elem of list LIST */
#define GetListTail(List) ((void *)(((LIST *)(List))->Tail))

/* Return count of elems in list LIST */
#define GetListCount(List) (((LIST *)(List))->Count)

/* Return elem next to elem ELEM */
#define GetNextNode(Node) ((void *)(((PNODE)(Node))->Next))

/* Return elem previous to elem ELEM */
#define GetPreviousNode(Node) ((void *)(((PNODE)(Node))->Previous))

// Deletes the pool allocated to a list

struct _NODE_
{
    struct _NODE_* Next;
    struct _NODE_* Previous;
};

struct _LIST_
{
    PNODE Head;
    PNODE Tail;
    int Count;
#ifdef LIST_WITH_MEMORY_MANAGEMENT
    POOL* Pool;
    int elem_len;
#endif
};

void InsertBefore(LIST* List, void* OldElement, void* NewElement);
void InsertAfter(LIST* List, void* OldElement, void* NewElement);
void RemoveCurrent(LIST* List, void* CurrentElement);


