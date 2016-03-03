/*
	Test code for PatchDIAT with cmd.exe
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/21: start
	2008/01/22:
	2008/01/28: rename PatchIat -> PatchIAT, DumpIat -> DumpIATs
	2008/01/31: added code for DLL_PROCESS_DETACH
*/

#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"
#include "psutils.h"

#define MAX_STRING 256

BOOL g_bHookInstalled = FALSE;

LONG WINAPI (*OriginalRegQueryValueExW)(HKEY hkey, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD count);

LONG WINAPI HookRegQueryValueExW(HKEY hkey, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD count)
{
	if (!_tcsicmp(name, _T("DisableCMD")))
	{
		OutputDebugString(name);
		return ERROR_FILE_NOT_FOUND;
	}
	else
		return (*OriginalRegQueryValueExW)(hkey, name, reserved, type, data, count);
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
		  	if (S_OK == PatchDIAT(GetProcessImageModule(GetCurrentProcessId()), "advapi32.dll", "RegQueryValueExW", (PVOID) HookRegQueryValueExW, (PVOID *) &OriginalRegQueryValueExW))
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
		  	if (S_OK == PatchDIAT(GetProcessImageModule(GetCurrentProcessId()), "advapi32.dll", "RegQueryValueExW", (PVOID) OriginalRegQueryValueExW, NULL))
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
