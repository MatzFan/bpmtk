/*
	Test code for IAT
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/24: start
	2008/01/28: rename PatchIat -> PatchIAT, DumpIat -> DumpIATs
	2008/01/30: added code for DLL_PROCESS_DETACH
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"
#include "psutils.h"

#define MAX_STRING 256

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) 
	{ 
	  case DLL_PROCESS_ATTACH:
	  	OutputDebugString(_TEXT("DLL_PROCESS_ATTACH"));
	  	DumpIATs(GetProcessImageModule(GetCurrentProcessId()));
      break;
	
	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
	  	OutputDebugString(_TEXT("DLL_PROCESS_DETACH"));
      break;
	}
	
	return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
