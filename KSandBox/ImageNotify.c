#include "ImageNotify.h"
#include "ProcessHelper.h"
#include "IpcHelper.h"
BOOLEAN __IsImageNotifyProcedure = FALSE;

void ImageNotifyProcedure(
    const UNICODE_STRING* FullImageName,
    HANDLE ProcessIdentity, IMAGE_INFO* ImageInfo)
{
    PROCESS* Process;
    Process = FindProcess(ProcessIdentity, NULL);
    ULONG Fail = 0;

    if ((!Process) || Process->IsInitialized)
    {



        return;
    }


    if (Process->IsTerminated)
        return;


    if (!Process->IsHostInject)
    {


        if (!Fail && !CreateBoxIpcPath(Process))    //¹¹½¨SandBoxÂ·¾¶
        {
            Fail = 0x02;
        }
          
    }



    if (!Fail) 
    {

        Process->IsInitialized = TRUE;

    }
}