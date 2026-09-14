#include "MemoryList.h"



void InsertBefore(LIST* List, void* OldElement, void* NewElement)
{
    PNODE Current = NULL;
    PNODE Node = NULL;
    PNODE Next = NULL;
    PNODE Previous = NULL;
   
    Current = (PNODE)OldElement;
    Node = (PNODE)NewElement;
    ++List->Count;


    if (Current == List->Head || Current == NULL) {    
        Next = List->Head;
        List->Head = Node;
        Node->Previous = NULL;
        Node->Next = Next;
        if (Next == NULL)                       
            List->Tail = Node;
        else
            Next->Previous = Node;

    }
    else 
    {                                  /* Insert non-head elem */
        Previous = Current->Previous;
        Previous->Next = Node;
        Node->Previous = Previous;
        Current->Previous = Node;
        Node->Next = Current;
    }
}

void InsertAfter(LIST* List, void* OldElement, void* NewElement)
{
       PNODE Previous = NULL;
    PNODE Node = NULL;
    PNODE Next = NULL;
    PNODE Current = NULL;
    Current = (PNODE)OldElement;
    Node = (PNODE)NewElement;
    ++List->Count;

    if (Current == List->Tail || Current == NULL) 
    {
        Previous = List->Tail;
        List->Tail = Node;
        Node->Previous = Previous;
        Node->Next = NULL;
        if (Previous == NULL)
            List->Head = Node;
        else
            Previous->Next = Node;

    }
    else {               
        Next = Current->Next;
        Next->Previous = Node;
        Node->Next = Next;
        Current->Next = Node;
        Node->Previous = Current;
    }
}
void RemoveCurrent(LIST* List, void* CurrentElement)
{
   
    PNODE Current = NULL;
    PNODE Previous = NULL;
    PNODE Next = NULL;
    Current = (PNODE)CurrentElement;
    Previous = Current->Previous;
    Next = Current->Next;
    --List->Count;

    if (Previous == NULL && Next == NULL) {         /* Last elem in list? */
        List->Tail = NULL;
        List->Head = NULL;

    }
    else if (Previous == NULL) {                       /* Elem is head? */
        List->Head = Next;
        Next->Previous = NULL;

    }
    else if (Next == NULL) {                       /* Elem is tail? */
        List->Tail = Previous;
        Previous->Next = NULL;

    }
    else {
        Previous->Next = Next;              /* Elem is non-head, non-tail */
        Next->Previous = Previous;
    }
}
