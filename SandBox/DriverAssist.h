#pragma once
#include "Common.h"
#include "_tWinMain.h"
#include "IoRequest.h"

#define DRIVER_VERSION  0x57010

#define NUMBER_OF_PROCESSORS (__SystemInfo.dwNumberOfProcessors)
#ifdef _WIN64
#define MINIMUM_NUMBER_OF_THREADS 8
#else
#define MINIMUM_NUMBER_OF_THREADS 4
#endif
#define NUMBER_OF_THREADS   \
            ((NUMBER_OF_PROCESSORS * 2) <= MINIMUM_NUMBER_OF_THREADS \
                    ? MINIMUM_NUMBER_OF_THREADS : (NUMBER_OF_PROCESSORS * 2))


enum {
    FIRST_2 = 0x23450000L,

    
    INJECT_PROCESS,
  

    LAST_2
};


class CDriverAssist
{
public:

    static bool Initialize();
private:
    CDriverAssist();
    ~CDriverAssist();
    bool InitializeInjeciton();
    bool InitializePortAndThreads();
   
    
public:
    void ReceiveMessageThread();   //等待Ring0回来的数据
    void HandleMessageThread(void* ParameterData);   //等待Ring0回来的数据
private:


    static CDriverAssist* m_Instance;


    volatile HANDLE m_PortHandle;
    volatile bool m_IsDriverReady;
    HANDLE* m_ThreadHandles;


    static ULONG StartDriverAsync(void* ParameterData);  //向Ring0发送数据
    void   InjectProcessReply(void* MessageData);

    HANDLE OpenProcess(void* MessageData);
};
DWORD WINAPI ReceiveMessageThread(void* ParameterData);
DWORD WINAPI HandleMessageThread(void* ParameterData);