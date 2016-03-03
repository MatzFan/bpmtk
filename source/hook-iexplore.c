/*
	Test code for hooking iexplorer 6.0
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/06/27: recode
*/

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <wininet.h>

#include "iat.h"
#include "psutils.h"

BOOL g_bHookHttpOpenRequestAInstalled;
BOOL g_bHookInternetConnectAInstalled;
BOOL g_bHookInternetReadFileInstalled;

HINTERNET __stdcall (*OriginalHttpOpenRequestA)(HINTERNET hConnect, LPCTSTR lpszVerb, LPCTSTR lpszObjectName, LPCTSTR lpszVersion, LPCTSTR lpszReferer, LPCTSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET __stdcall HookHttpOpenRequestA(HINTERNET hConnect, LPCTSTR lpszVerb, LPCTSTR lpszObjectName, LPCTSTR lpszVersion, LPCTSTR lpszReferer, LPCTSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	char szDebug[1024];
	
	snprintf(szDebug, 1023, "HookHttpOpenRequestA %08X %s %s", dwFlags, NULL != lpszVerb ? lpszVerb : "NULL", lpszObjectName);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
	return (*OriginalHttpOpenRequestA)(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
}

HINTERNET __stdcall (*OriginalInternetConnectA)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName OPTIONAL, LPCSTR lpszPassword OPTIONAL, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET __stdcall HookInternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,	LPCSTR lpszUserName OPTIONAL,	LPCSTR lpszPassword OPTIONAL, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	char szDebug[1024];
	
	snprintf(szDebug, 1023, "HookInternetConnectA %s %08X", lpszServerName, nServerPort);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
	return (*OriginalInternetConnectA)(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

BOOL __stdcall (*OriginalInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

BOOL __stdcall HookInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	char szDebug[2048];
	char szData[1024];
	BOOL bResult;
	unsigned int uiIter;
	
	snprintf(szDebug, 1023, "HookInternetReadFile dwNumberOfBytesToRead %08X", dwNumberOfBytesToRead);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
	bResult = (*OriginalInternetReadFile)(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	for (uiIter = 0; uiIter < *lpdwNumberOfBytesRead && uiIter < 1024; uiIter++)
	  szData[uiIter] = isprint(((char *)lpBuffer)[uiIter]) ? ((char *)lpBuffer)[uiIter] : '.';
	szData[*lpdwNumberOfBytesRead] = '\0';
	snprintf(szDebug, 1023, "HookInternetReadFile *lpdwNumberOfBytesRead %08X data %s", *lpdwNumberOfBytesRead, szData);
	szDebug[2047] = '\0';
	OutputDebugString(szDebug);
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
			OutputDebugString(_TEXT("Hook WinINet DLL_PROCESS_ATTACH"));
			
      if (FALSE == g_bHookHttpOpenRequestAInstalled)
      {
				if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"),
					"wininet.dll",
					"HttpOpenRequestA",
					(PVOID) HookHttpOpenRequestA,
					(PVOID *) &OriginalHttpOpenRequestA))
					g_bHookHttpOpenRequestAInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking HttpOpenRequestA failed."));
      }

      if (FALSE == g_bHookInternetConnectAInstalled)
      {
				if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"),
					"wininet.dll",
					"InternetConnectA",
					(PVOID) HookInternetConnectA,
					(PVOID *) &OriginalInternetConnectA))
					g_bHookInternetConnectAInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking InternetConnectA failed."));
      }
      
      if (FALSE == g_bHookInternetReadFileInstalled)
      {
				if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"),
					"wininet.dll",
					"InternetReadFile",
					(PVOID) HookInternetReadFile,
					(PVOID *) &OriginalInternetReadFile))
					g_bHookInternetReadFileInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking InternetReadFile failed."));
      }
      
    	break;

	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
		  OutputDebugString(_TEXT("Unhook WinINet DLL_PROCESS_DETACH"));

	  	if (TRUE == g_bHookHttpOpenRequestAInstalled)
	  	{
		  	if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"), "wininet.dll", "HttpOpenRequestA", (PVOID) OriginalHttpOpenRequestA, NULL))
					g_bHookHttpOpenRequestAInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking HttpOpenRequestA failed."));
			}
			
	  	if (TRUE == g_bHookInternetConnectAInstalled)
	  	{
		  	if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"), "wininet.dll", "InternetConnectA", (PVOID) OriginalInternetConnectA, NULL))
					g_bHookInternetConnectAInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking InternetConnectA failed."));
			}
			
	  	if (TRUE == g_bHookInternetReadFileInstalled)
	  	{
		  	if (S_OK == PatchDIAT(GetModuleForProcess(GetCurrentProcessId(), "urlmon.dll"), "wininet.dll", "InternetReadFile", (PVOID) OriginalInternetReadFile, NULL))
					g_bHookInternetReadFileInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking InternetReadFile failed."));
			}
			
      break;
  }
  
  return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
