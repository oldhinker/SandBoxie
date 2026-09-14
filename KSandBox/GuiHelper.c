#include "GuiHelper.h"
#include "DriverEntry.h"
#include "ProcessHelper.h"
#include "ApiHelper.h"
#include "IoRequest.h"
#include "ProcessNotify.h"

BOOLEAN InitializeGui(void)
{
#ifdef XP_SUPPORT
#ifndef _WIN64

    if (__OsVersion < WINDOWS_VISTA) {

        //
        // on Windows Vista, UIPI reasonably protects use of
        // PostThreadMessage, SendInput, and SetWindowsHookEx because
        // the primary access token of the process will have an
        // untrusted integrity level.
        //
        // but note that UIPI is turned off when UAC is turned off !
        //
        // on Windows XP, we have to hook these functions in win32k
        // to provide adequate protection.
        //

        if (!Gui_Init_XpHook())
            return FALSE;
    }

#endif ! _WIN64
#endif

    SetCommonService(START_PROCESS_NOTIFY, StartProcessNotify);   //FastIoÇëÇó


    return TRUE;
}

