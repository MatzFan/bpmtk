/*
	process utilities for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/23: Start development
	2008/01/30: added RejectDLL
	2008/02/03: added PrintProcesses
	2008/02/04: added PrintMemory
	2008/02/06: added GetAppVersion
	2008/02/08: added GetModuleForProcess, added GetModuleVersion
	2008/02/10: added SuspendProcess, ResumeProcess
	2008/02/11: made CurrentProcessAdjustToken
	2008/02/15: added ProcessMemory
	2008/02/17: added ProcessModules
	2008/02/25: added dwProtect to ProcessMemory
	2008/02/27: added GetProcessOwner
	2008/10/15: added InjectCode
	2008/10/18: updated InjectCode
*/

#include <psapi.h>

#define MAXPROCESSES 1024
#define MAXWAIT 1000
#define MAXMODULES 1024

void ConfigVerbose(UINT uiVerbose);
HMODULE GetProcessImageModule(DWORD dwPID);
BOOL GetProcessName(DWORD dwPID, char *szName);
void PrintModules(DWORD dwPID);
DWORD LookupPID(char *szProcessNameArg);
BOOL InjectDLL(DWORD dwPID, char *szDLLName);
BOOL RejectDLL(DWORD dwPID, char *szDLLName);
void PrintProcesses(void);
void PrintMemory(DWORD dwPID);
BOOL GetAppVersion( char *LibName, WORD *MajorVersion, WORD *MinorVersion, WORD *BuildNumber, WORD *RevisionNumber );
HMODULE GetModuleForProcess(DWORD dwPID, char *szModNameArg);
BOOL GetModuleVersion(HANDLE hProcess, LPVOID lpAddress, TCHAR *pszVersion);
void SuspendProcess(DWORD dwPID);
void ResumeProcess(DWORD dwPID);
BOOL CurrentProcessAdjustToken(void);
int ProcessMemory(DWORD dwPID, void (*pfProcess)(HANDLE, LPVOID, SIZE_T, PVOID, void *, unsigned int), void *pvData, unsigned int uiReadOnly, DWORD dwProtect);
int ProcessModules(DWORD dwPID, TCHAR *pszModule, void (*pfProcess)(HANDLE, LPVOID, SIZE_T, PVOID, void *, unsigned int), void *pvData, unsigned int uiReadOnly, HMODULE hmModArg);
int GetProcessOwner(DWORD dwPID, char *pszName, char *pszDomain);
BOOL InjectCode(DWORD dwPID, PBYTE pbCode, long lCodeSize, unsigned int uiMinimumBytesSize, BOOL bExecute);
