/*
	PatchIAT demo
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/21: Start development
	2008/01/22: Project restructering
	2008/01/23:
	2008/01/28: rename PatchIat -> PatchIAT, DumpIat -> DumpIATs
	2008/01/30: added code for DLL_PROCESS_DETACH
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"
#include "psutils.h"

#define MAX_STRING 256

BOOL g_bHookInstalled = FALSE;

DWORD (*OriginalGetVersion)(void);

DWORD HookGetVersion(void)
{
	return 1+(*OriginalGetVersion)();
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
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "GetVersion", (PVOID) HookGetVersion, (PVOID *) &OriginalGetVersion))
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
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "GetVersion", (PVOID) OriginalGetVersion, NULL))
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
