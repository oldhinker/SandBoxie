#include "_tmain.h"


int _tmain()
{
	//HANDLE  EventHandle = CreateEvent(NULL, FALSE, FALSE, _T("Shine"));
	HANDLE  EventHandle = CreateEvent(NULL, FALSE, FALSE, _T("Shine"));
	if (EventHandle != NULL)
	{
		_tprintf(_T("0x%p\r\n"), EventHandle);
	}
	_tprintf(_T("Input AnyKey To Exit\r\n"));

	_gettchar();
	_gettchar();
	return 0;
}