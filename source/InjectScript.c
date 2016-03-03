/*
	When injected inside a process, this DLL will execute a VBScript
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/13: Start development
	2008/02/14: Refactoring
	2008/02/19: added internal object
	2009/05/31: cleanup
	2009/06/09: SCRIPT_MAX_SIZE 10000*2
*/

#include "scriptengine.h"

#pragma resource "scriptengine.res"

LONG lRuns;

#define SCRIPT_MAX_SIZE 10000*2
#define SCRIPT_TYPE_FILE 1
#define SCRIPT_TYPE_SCRIPT 2

typedef struct
{
	BYTE bType;
	BYTE abData[SCRIPT_MAX_SIZE];
} SCRIPT;

typedef union
{
	SCRIPT script;
	BYTE abDummy[SCRIPT_MAX_SIZE+1];
} USCRIPT;

//USCRIPT Script = {SCRIPT_TYPE_SCRIPT, 'M', 0, 's', 0, 'g', 0, 'B', 0, 'o', 0, 'x', 0, ' ', 0, '"', 0, 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, ' ', 0, 'f', 0, 'r', 0, 'o', 0, 'm', 0, ' ', 0, 'i', 0, 'n', 0, 's', 0, 'i', 0, 'd', 0, 'e', 0, ' ', 0, 'I', 0, 'n', 0, 'j', 0, 'e', 0, 'c', 0, 't', 0, 'S', 0, 'c', 0, 'r', 0, 'i', 0, 'p', 0, 't', 0, '.', 0, 'd', 0, 'l', 0, 'l', 0, '"', 0, 0, 0};
USCRIPT Script = {SCRIPT_TYPE_FILE, 'I', 'n', 'j', 'e', 'c', 't', 'S', 'c', 'r', 'i', 'p', 't', '.', 'v', 'b', 's', 0};

#ifdef __BORLANDC__
#pragma warn -8057
#endif

DWORD WINAPI ExecuteScript(LPVOID lpParam)
{
	switch(Script.script.bType)
	{
		case SCRIPT_TYPE_SCRIPT:
			ExecuteVBScript((LPOLESTR) Script.script.abData);
			break;
			
		case SCRIPT_TYPE_FILE:
			ExecuteVBScript(loadUnicodeScript(Script.script.abData));
			break;
	}
	
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )
{
	DWORD dwThreadId;
	
	switch(fdwReason) 
	{ 
	  case DLL_PROCESS_ATTACH:
			if (1 == InterlockedIncrement(&lRuns))
				CreateThread(NULL, 0, ExecuteScript, NULL, 0, &dwThreadId);
      break;
	
	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
      break;
	}
	
	return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

/*
main()
{
	ExecuteVBScript(L"a = 1+2");
}
*/