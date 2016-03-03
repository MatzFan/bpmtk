/*
	Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	- regex: targets, strings, options like case
	- process-owner
	- variables
	- input function
	- inject dll from memory
	- compare strings in memory and on file: http://www.dcc.uchile.cl/~rbaeza/handbook/algs/3/342.data.c.html
	- processmemory: filter for types of pages, ie only writable pages
	- use dynamic array for kmp
	
	History:
	2008/01/18: Start development
	2008/01/23: Project restructering
	2008/01/24: add config verbose option
	2008/01/30: added command reject_dll
	2008/01/31: code review
	2008/02/02: added ParseFilename
	2008/02/03: added info statement, refactored config parsing
	2008/02/04: added PrintMemory, extended ExecuteInfo
	2008/02/08: added module option to search-and-write, added readonly option, added version option to write
	2008/02/09: added confirm statement, added CreateEXEWithEmbeddedConfig function
	2008/02/10: added suspend statement, added resume statement, updated WorkWithProcessName (* and multiple processes with same name)
							added print statement, added rc
	2008/02/11: add adjust-toke-privileges statement
	2008/02/12: moved parser code to separate parse.[ch] file
	2008/02/15: added strings statement
	2008/02/16: added strings statement options
	2008/02/17: adapted ExecuteSearchAndWrite to work also in memory, added output functions
	2008/02/19: cleanup for version 0.1.1.1
 	2008/02/22: added plugin
	2008/02/23: added plugin, repeat, filter, $date, $time
	2008/02/24: added regex support with pcre.dll
	2008/02/25: added option memory:writable, cleanup for version 0.1.2.0
	2008/02/26: allowed the use of different strings filters
	2008/02/29: added test-function
	2008/03/03: tested search-and-write to change cert check result
	2008/03/04: used VirtualProtectEx to change virtual page protection when write fails in write and search-and-write
  2008/06/24: version 0.1.3.0, added DllMain
	2008/10/15: version 0.1.5.0, added InjectCode
	2008/10/18: Refactor DumpBytes -> OutputDumpBytes, updated InjectCode to support file:filename
*/

#define SECURITY_WIN32

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tchar.h>
#include <security.h>
#include <secext.h>
#include <sys/stat.h>
#include <math.h>

#include "bpmtk.h"
#include "psutils.h"
#include "parser.h"
#include "output.h"
#include "pcre.h"

#pragma comment(lib, "secur32.lib")

#ifdef INCLUDE_RESOURCE
#pragma resource "bpmtk.res"
#endif

#define XSIZE 1024

#define RESOURCE_BPMTK _T("BPMTK")

int *piFound;

HINSTANCE hiPlugin;
typedef __stdcall BOOL (*PluginStringsFilter)(char *);
PluginStringsFilter StringsFilter;

HINSTANCE hiPCRE;
PCRELIB_compile pcrelib_compile;
PCRELIB_exec pcrelib_exec;
PCRELIB_free pcrelib_free;
                   
int compare(char cX, char cY, int iFlagIgnoreCase)
{
	if (iFlagIgnoreCase && isalpha(cX) && isalpha(cY))
		return tolower(cX) == tolower(cY);
	else
		return cX == cY;
}

// Search algorithm: http://www-igm.univ-mlv.fr/~lecroq/string/node8.html#SECTION0080 
void preKmp(char *pcX, int m, int kmpNext[], int iFlagIgnoreCase) {
   int i, j;

   i = 0;
   j = kmpNext[0] = -1;
   while (i < m) {
      while (j > -1 && !compare(pcX[i], pcX[j], iFlagIgnoreCase))
         j = kmpNext[j];
      i++;
      j++;
      if (compare(pcX[i], pcX[j], iFlagIgnoreCase))
         kmpNext[i] = kmpNext[j];
      else
         kmpNext[i] = j;
   }
}

int KMP(char *pcX, int m, char *pcY, int n, int iFlagIgnoreCase) {
   int i, j, kmpNext[XSIZE];
   int iCountFinds = 0;

   /* Preprocessing */
   preKmp(pcX, m, kmpNext, iFlagIgnoreCase);

   /* Searching */
   i = j = 0;
   while (j < n) {
      while (i > -1 && !compare(pcX[i], pcY[j], iFlagIgnoreCase))
         i = kmpNext[i];
      i++;
      j++;
      if (i >= m) {
      	 piFound[iCountFinds++] = j-i;
         i = kmpNext[i];
      }
   }
   return iCountFinds;
}

int LoadPlugin(TCHAR *pszDLL, TCHAR *pszFunction)
{
	if (NULL != pszDLL && NULL == hiPlugin)
	{
		hiPlugin = LoadLibrary(pszDLL);
		if (NULL == hiPlugin)
			return -1;
	}

	if (NULL == pszFunction)
		return 0;
		
	if (NULL == StringsFilter)
	{
		StringsFilter = (PluginStringsFilter) GetProcAddress(hiPlugin, pszFunction);
		if (NULL == StringsFilter)
			return -2;
	}
		
	return 0;
}

int LoadPCRE(void)
{
	hiPCRE = LoadLibrary("pcre.dll");
	if (NULL == hiPCRE)
		return -1;

	pcrelib_compile = (PCRELIB_compile) GetProcAddress(hiPCRE, "pcre_compile");
	if (NULL == pcrelib_compile)
		return -2;

	pcrelib_exec = (PCRELIB_exec) GetProcAddress(hiPCRE, "pcre_exec");
	if (NULL == pcrelib_exec)
		return -3;

	pcrelib_free = (PCRELIB_free) GetProcAddress(hiPCRE, "pcre_free");
	if (NULL == pcrelib_free)
		return -4;

	return 0;
}

void ExecuteWrite(DWORD dwPID, struct CommandWrite *pCW, unsigned int uiReadOnly)
{
  HANDLE hProcess;
  DWORD dwDummy;
  unsigned char *pucBuffer;
	BOOL bRet;
  DWORD dwErr;
	TCHAR szVersion[256];
  DWORD dwOldProtect;

  hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_READ |
                          PROCESS_VM_WRITE |
                          PROCESS_VM_OPERATION,
                          FALSE, dwPID );
  if (NULL == hProcess)
      return;

  Output("Write:\n");
	
	if (pCW->pszVersion != NULL)
	{
		if (GetModuleVersion(hProcess, (LPVOID) pCW->address, szVersion))
		{
			if (!_tcsicmp(pCW->pszVersion, szVersion))	
				Output(" Version %s:\n", szVersion);
			else
			{
				Output(" Different version %s %s:\n", szVersion, pCW->pszVersion);
			  CloseHandle(hProcess);
				return;
			}
		}
		else
		{
			Output(" Unable to read version information\n");
		  CloseHandle(hProcess);
			return;
		}
	}
	
	pucBuffer = malloc(pCW->len);

	bRet = ReadProcessMemory(hProcess, (const void *) pCW->address, pucBuffer, pCW->len, &dwDummy);
	if (bRet == 0)
		return;
  Output("\tread from memory before write:\n");
  OutputDumpBytes("\t\t", pucBuffer, pCW->len, pCW->address);

	if (!uiReadOnly)
	{
		Output("\tbytes to write:\n");
		OutputDumpBytes("\t\t", pCW->bytes, pCW->len, pCW->address);
		
		bRet = WriteProcessMemory(hProcess, (void *) pCW->address, pCW->bytes, pCW->len, &dwDummy);
		dwErr = GetLastError(); 
		if (bRet == 0)
		{
			if (ERROR_NOACCESS == dwErr)
			{
				Output("\tWrite failed, changing virtual page protection\n");
				bRet = VirtualProtectEx(hProcess, (void *) pCW->address, pCW->len, PAGE_READWRITE, &dwOldProtect);
				if (0 == bRet)
				{
					Output("\tError VirtualProtectEx bRet = %d error = %u\n", bRet, GetLastError());
					free(pucBuffer);
					CloseHandle(hProcess);
					return;
				}

				bRet = WriteProcessMemory(hProcess, (void *) pCW->address, pCW->bytes, pCW->len, &dwDummy);
				dwErr = GetLastError();
				if (0 == bRet)
				{
					Output("\tError writing bRet = %d error = %u\n", bRet, dwErr);
					free(pucBuffer);
					CloseHandle(hProcess);
					return;
				}
			}
			else
			{
				Output("\tError writing bRet = %d error = %u\n", bRet, dwErr);
				free(pucBuffer);
				CloseHandle(hProcess);
				return;
			}
		}
			
		bRet = ReadProcessMemory(hProcess, (const void *) pCW->address, pucBuffer, pCW->len, &dwDummy);
		if (bRet == 0)
			return;
		Output("\tread from memory after write:\n");
		OutputDumpBytes("\t\t", pucBuffer, pCW->len, pCW->address);
	}
		
	free (pucBuffer);
  CloseHandle(hProcess);
}

void SearchAndWriteProc(HANDLE hProcess, LPVOID lpBuffer, SIZE_T sSize, PVOID pvAddress, void *pvData, unsigned int uiReadOnly)
{
	struct CommandSearchAndWrite *pCSAW;
  unsigned char *pucBuffer;
  DWORD dwDummy;
	BOOL bRet;
  int iCountFinds;
  DWORD dwAddress;
  int iIter;
  DWORD dwOldProtect;
  DWORD dwErr;
	
	pCSAW = (struct CommandSearchAndWrite *) pvData;

	piFound = (int *) VirtualAlloc(NULL, sSize, MEM_RESERVE|MEM_COMMIT,	PAGE_READWRITE);
	if (NULL == piFound)
		return;

	iCountFinds = KMP(pCSAW->searchBytes, pCSAW->searchLen, lpBuffer, sSize, 0);
	if (iCountFinds > 0)
	{
		pucBuffer = malloc(pCSAW->writeLen);
		if (NULL == pucBuffer)
		{
			VirtualFree(piFound, 0, MEM_RELEASE);
			return;
		}

		for (iIter = 0; iIter < iCountFinds; iIter++)
		{
			dwAddress = piFound[iIter]+(unsigned long)pvAddress;
			Output("\tfound at %08X\n", dwAddress);
			bRet = ReadProcessMemory(hProcess, (const void *) dwAddress, pucBuffer, pCSAW->writeLen, &dwDummy);
			if (0 == bRet)
			{
				free(pucBuffer);
				VirtualFree(piFound, 0, MEM_RELEASE);
				return;
			}
			Output("\tread from memory before write:\n");
  		OutputDumpBytes("\t\t", pucBuffer, pCSAW->writeLen, dwAddress);
			
			if (!uiReadOnly)
			{
				Output("\tbytes to write:\n");
	  		OutputDumpBytes("\t\t", pCSAW->writeBytes, pCSAW->writeLen, dwAddress);
				
				bRet = WriteProcessMemory(hProcess, (void *) dwAddress, pCSAW->writeBytes, pCSAW->writeLen, &dwDummy);
				dwErr = GetLastError();
				if (0 == bRet)
				{
					if (ERROR_NOACCESS == dwErr)
					{
						Output("\tWrite failed, changing virtual page protection\n");
						bRet = VirtualProtectEx(hProcess, (void *) dwAddress, pCSAW->writeLen, PAGE_READWRITE, &dwOldProtect);
						if (0 == bRet)
						{
							Output("\tError VirtualProtectEx bRet = %d error = %u\n", bRet, GetLastError());
							free(pucBuffer);
							VirtualFree(piFound, 0, MEM_RELEASE);
							return;
						}

						bRet = WriteProcessMemory(hProcess, (void *) dwAddress, pCSAW->writeBytes, pCSAW->writeLen, &dwDummy);
						dwErr = GetLastError();
						if (0 == bRet)
						{
							Output("\tError writing bRet = %d error = %u\n", bRet, dwErr);
							free(pucBuffer);
							VirtualFree(piFound, 0, MEM_RELEASE);
							return;
						}
					}
					else
					{
						Output("\tError writing bRet = %d error = %u\n", bRet, dwErr);
						free(pucBuffer);
						VirtualFree(piFound, 0, MEM_RELEASE);
						return;
					}
				}
					
				bRet = ReadProcessMemory(hProcess, (const void *) dwAddress, pucBuffer, pCSAW->writeLen, &dwDummy);
				if (0 == bRet)
				{
					free(pucBuffer);
					VirtualFree(piFound, 0, MEM_RELEASE);
					return;
				}
				Output("\tread from memory after write:\n");
	  		OutputDumpBytes("\t\t", pucBuffer, pCSAW->writeLen, dwAddress);
	  	}
		}
			
		free(pucBuffer);
	}

	VirtualFree(piFound, 0, MEM_RELEASE);
}

void ExecuteSearchAndWrite(DWORD dwPID, struct CommandSearchAndWrite *pCSAW, HMODULE hmModArg, unsigned int uiReadOnly)
{
  Output("search-and-write:\n");
  if (NULL == pCSAW->pszModule)
  	ProcessMemory(dwPID, &SearchAndWriteProc, pCSAW, uiReadOnly, pCSAW->dwMemory);
	else
  	ProcessModules(dwPID, pCSAW->pszModule, &SearchAndWriteProc, pCSAW, uiReadOnly, hmModArg);
}

void ExecuteInjectDLL(DWORD dwPID, struct Command1psz *pC1P, unsigned int uiReadOnly)
{
  Output("inject-dll %s:\n", pC1P->pszArgument);
  if (!uiReadOnly)
  	InjectDLL(dwPID, pC1P->pszArgument);
}

void ExecuteRejectDLL(DWORD dwPID, struct Command1psz *pC1P, unsigned int uiReadOnly)
{
  Output("reject-dll %s:\n", pC1P->pszArgument);
  if (!uiReadOnly)
	  RejectDLL(dwPID, pC1P->pszArgument);
}

void ExecuteDump(DWORD dwPID)
{
  Output("dump %u:\n", dwPID);
  PrintMemory(dwPID);
}

void ExecuteInfo(void)
{
	DWORD dwVersion;
  OSVERSIONINFOEX sOVIE;
	TCHAR szBuffer[MAX_PATH];
  SYSTEM_INFO sSI;
  int iCnf;
  DWORD dwSize;
  MEMORYSTATUSEX sMSE;
  TCHAR szDescription[8][32] = {
	  TEXT("NetBIOS"), 
	  TEXT("DNS hostname"), 
	  TEXT("DNS domain"), 
	  TEXT("DNS fully-qualified"), 
	  TEXT("Physical NetBIOS"), 
	  TEXT("Physical DNS hostname"), 
	  TEXT("Physical DNS domain"), 
	  TEXT("Physical DNS fully-qualified")
	};

	dwVersion = GetVersion();
	Output("Windows version: raw data: %08X parsed: version %d.%d build %d\n", dwVersion, dwVersion & 0xFF, (dwVersion & 0xFF00) >> 8, dwVersion >> 16);
  ZeroMemory(&sOVIE, sizeof(OSVERSIONINFOEX));
  sOVIE.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  GetVersionEx((LPOSVERSIONINFO)&sOVIE);
  Output(TEXT("GetVersionEx:\n"));
  Output(TEXT(" dwMajorVersion: %u\n"), sOVIE.dwMajorVersion);
  Output(TEXT(" dwMinorVersion: %u\n"), sOVIE.dwMinorVersion);
  Output(TEXT(" dwBuildNumber: %u\n"), sOVIE.dwBuildNumber);
  Output(TEXT(" szCSDVersion: %s\n"), sOVIE.szCSDVersion);
  Output(TEXT(" wServicePackMajor: %d\n"), sOVIE.wServicePackMajor);
  Output(TEXT(" wServicePackMinor: %d\n"), sOVIE.wServicePackMinor);
  Output(TEXT(" wSuiteMask: %08X\n"), sOVIE.wSuiteMask);
  Output(TEXT(" wProductType: %08X\n"), sOVIE.wProductType);
  
	if (GetCurrentDirectory(MAX_PATH, szBuffer))
		Output("Current directory: '%s'\n", szBuffer);

	GetSystemInfo(&sSI);
	Output("dwNumberOfProcessors = %u\n", sSI.dwNumberOfProcessors);
	Output("dwActiveProcessorMask = %08X\n", sSI.dwActiveProcessorMask);
	Output("wProcessorArchitecture = %d\n", sSI.wProcessorArchitecture);
	Output("wProcessorLevel = %d\n", sSI.wProcessorLevel);
	Output("wProcessorRevision = %d\n", sSI.wProcessorRevision);

  sMSE.dwLength = sizeof(sMSE);
  GlobalMemoryStatusEx(&sMSE);
  Output(TEXT("Memory:\n"));
  Output(" %u percent of memory in use.\n", sMSE.dwMemoryLoad); 
  Output(" %I64d total Mb of physical memory.\n", sMSE.ullTotalPhys/1024/1024);
  Output(" %I64d free Mb of physical memory.\n", sMSE.ullAvailPhys/1024/1024);
  Output(" %I64d total Mb of paging file.\n", sMSE.ullTotalPageFile/1024/1024);
  Output(" %I64d free Mb of paging file.\n", sMSE.ullAvailPageFile/1024/1024);
  Output(" %I64d total Mb of virtual memory.\n", sMSE.ullTotalVirtual/1024/1024);
  Output(" %I64d free Mb of virtual memory.\n", sMSE.ullAvailVirtual/1024/1024);
  Output(" %I64d free Mb of extended memory.\n", sMSE.ullAvailExtendedVirtual/1024/1024);
          
  Output(TEXT("Computernames:\n"));
  for (iCnf = 0; iCnf < ComputerNameMax; iCnf++)
  {
    dwSize = sizeof(szBuffer);
    if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)iCnf, szBuffer, &dwSize))
      Output(TEXT(" GetComputerNameEx failed (%d)\n"), GetLastError());
    else
    	Output(TEXT(" %s: %s\n"), szDescription[iCnf], szBuffer);
  }
    
  dwSize = sizeof(szBuffer);
  if (!GetUserName(szBuffer, &dwSize))
    Output(TEXT("GetUserName failed (%d)\n"), GetLastError());
  else
  	Output(TEXT("Current username: %s\n"), szBuffer);
  dwSize = sizeof(szBuffer);
  if (!GetUserNameEx(NameFullyQualifiedDN, szBuffer, &dwSize))
    Output(TEXT("GetUserNameEx failed (%d)\n"), GetLastError());
  else
  	Output(TEXT("Current NameFullyQualifiedDN username: %s\n"), szBuffer);
  dwSize = sizeof(szBuffer);
  if (!GetUserNameEx(NameSamCompatible, szBuffer, &dwSize))
    Output(TEXT("GetUserNameEx failed (%d)\n"), GetLastError());
  else
  	Output(TEXT("Current NameSamCompatible username: %s\n"), szBuffer);
  dwSize = sizeof(szBuffer);
  if (!GetUserNameEx(NameUserPrincipal, szBuffer, &dwSize))
    Output(TEXT("GetUserNameEx failed (%d)\n"), GetLastError());
  else
  	Output(TEXT("Current NameUserPrincipal username: %s\n"), szBuffer);

	PrintProcesses();
}

void ExecutePause(void)
{
	Output(_T("Press ENTER to continue...\n"));
	getchar();
}

BOOL ExecuteConfirm(void)
{
	TCHAR szAnswer[256];
	
	Output(_T("Do you want to continue (Y/N)? <Y>"));
	while (NULL != _fgetts(szAnswer, sizeof(szAnswer), stdin))
	{
		Chomp(szAnswer);
		if (!_tcsicmp(szAnswer, _T("y")) || !_tcsicmp(szAnswer, _T("")))
			return TRUE;
		if (!_tcsicmp(szAnswer, _T("n")))
			return FALSE;
		Output(_T("Do you want to continue (Y/N)? <Y>"));
	}
	
	return FALSE;
}

void ExecuteSuspend(DWORD dwPID, unsigned int uiReadOnly)
{
  Output("suspend:\n");
  if (!uiReadOnly)
  	SuspendProcess(dwPID);
}

void ExecuteResume(DWORD dwPID, unsigned int uiReadOnly)
{
  Output("resume:\n");
  if (!uiReadOnly)
  	ResumeProcess(dwPID);
}

void ExecutePrint(struct Command1psz *pC1P)
{
	char *pszIter;
	SYSTEMTIME sST;
		
	if (NULL == pC1P->pszArgument)
	{
		Output("\n");
		return;
	}
	
	if (NULL == strchr(pC1P->pszArgument, '$'))
	{
		Output("%s\n", pC1P->pszArgument);
		return;
	}
	
	GetLocalTime(&sST);
	for (pszIter = pC1P->pszArgument; *pszIter; pszIter++)
		if ('$' != *pszIter)
			Outputchar(*pszIter);
		else if (!strnicmp(pszIter+1, "date", 4))
		{
			Output("%d/%02d/%02d", sST.wYear, sST.wMonth, sST.wDay);
			pszIter += 4;
		}
		else if (!strnicmp(pszIter+1, "time", 4))
		{
			Output("%02d:%02d:%02d", sST.wHour, sST.wMinute, sST.wSecond);
			pszIter += 4;
		}
		else
		Outputchar(*pszIter);
	Output("\n");
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

void ExecuteAdjustTokenPrivileges(DWORD dwPID, unsigned int uiReadOnly)
{
  Output("adjust-token-privileges:\n");
  if (!uiReadOnly)
  	CurrentProcessAdjustToken();
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

BOOL StringsProcRegex(char *pszString, struct CommandStrings *pCS)
{
	int iaOvector[30];

	if (NULL == pCS->pPCRE)
		return NULL != strstr(pszString, pCS->pszRegex);
	
	return pcrelib_exec(pCS->pPCRE, NULL, pszString, strlen(pszString), 0, 0, iaOvector, sizeof(iaOvector)/sizeof(int)) >= 0;
}

void StringsProcSubChar(BYTE *pbString, BYTE *pbIter, PVOID pvAddress, LPVOID lpBuffer, struct CommandStrings *pCS)
{
	BYTE *pbIterCountAlpha;
	int iCountAlpha;
	char *pszBuffer;
	unsigned int uiSize;
	BOOL bRegex;
	BOOL bFilter;

	uiSize = (unsigned int)(pbIter - pbString);
	if (uiSize >= pCS->uiMinimumLength)
	{
		iCountAlpha = 0;
		for (pbIterCountAlpha = pbString; pbIterCountAlpha < pbIter; pbIterCountAlpha++)
			if (isalpha(*pbIterCountAlpha) || isspace(*pbIterCountAlpha))
				iCountAlpha++;
		if (iCountAlpha / (uiSize * 1.0) * 100.0 >= pCS->uiAlphaPercentage)
		{
			pszBuffer = malloc(uiSize + 1);
			if (NULL == pszBuffer)
				return;
			snprintf(pszBuffer, uiSize, "%s", pbString);
			pszBuffer[uiSize] = '\0';
			if (NULL != pCS->pszRegex)
				bRegex = StringsProcRegex(pszBuffer, pCS);
			if (NULL != pCS->pszFilter)
				bFilter = StringsFilter(pszBuffer);
			if (!(NULL != pCS->pszRegex && !bRegex || NULL != pCS->pszFilter && !bFilter))
			{
				if (pCS->bAddress)
					Output("%08X A: ", ((BYTE *) pvAddress) + (pbString - (BYTE *) lpBuffer));
				Output("%s\n", pszBuffer);
			}
			free(pszBuffer);
		}
	}
}

void StringsProcSubWchar(WCHAR *pwcString, WCHAR *pwcIter, PVOID pvAddress, LPVOID lpBuffer, struct CommandStrings *pCS)
{
	WCHAR *pwcIterCountAlpha;
	int iCountAlpha;
	char *pszBuffer;
	unsigned int uiSize;
	BOOL bRegex;
	BOOL bFilter;

	uiSize = (unsigned int)(pwcIter - pwcString);
	if (uiSize >= pCS->uiMinimumLength)
	{
		iCountAlpha = 0;
		for (pwcIterCountAlpha = pwcString; pwcIterCountAlpha < pwcIter; pwcIterCountAlpha++)
			if (iswalpha(*pwcIterCountAlpha) || iswspace(*pwcIterCountAlpha))
				iCountAlpha++;
		if (iCountAlpha / (uiSize * 1.0) * 100.0 >= pCS->uiAlphaPercentage)
		{
			pszBuffer = malloc(uiSize + 1);
			if (NULL == pszBuffer)
				return;
//			snprintf(pszBuffer, uiSize, "%s", pwcString);
			for (pwcIterCountAlpha = pwcString; pwcIterCountAlpha < pwcIter; pwcIterCountAlpha++)
				pszBuffer[pwcIterCountAlpha - pwcString] = (char) *pwcIterCountAlpha;
			pszBuffer[uiSize] = '\0';
			if (NULL != pCS->pszRegex)
				bRegex = StringsProcRegex(pszBuffer, pCS);
			if (NULL != pCS->pszFilter)
				bFilter = StringsFilter(pszBuffer);
			if (!(NULL != pCS->pszRegex && !bRegex || NULL != pCS->pszFilter && !bFilter))
			{
				if (pCS->bAddress)
					Output("%08X U: ", ((WCHAR *) pvAddress) + (pwcString - (WCHAR *) lpBuffer));
				while (pwcString < pwcIter)
					Outputwchar(*pwcString++);
				Outputchar('\n');
	//			puts(pszBuffer);
			}
			free(pszBuffer);
		}
	}
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

void StringsProc(HANDLE hProcess, LPVOID lpBuffer, SIZE_T sSize, PVOID pvAddress, void *pvData, unsigned int uiReadOnly)
{
	BYTE *pbIter;
	BYTE *pbLast;
	BYTE *pbString;
	WCHAR *pwcString;
	BYTE *pbAddress;
	struct CommandStrings *pCS;
	
	pCS = (struct CommandStrings *) pvData;
	pbAddress = (BYTE *) pvAddress;

	if (pbAddress < (BYTE *) pCS->dwStartAddress && pbAddress + sSize - 1 < (BYTE *) pCS->dwStartAddress)
		return;
	if (pbAddress > (BYTE *) pCS->dwEndAddress && pbAddress + sSize - 1 > (BYTE *) pCS->dwEndAddress)
		return;

	pbIter = (BYTE *) lpBuffer;
	pbLast = pbIter + sSize - 1;
	pbString = NULL;
	pwcString = NULL;
	
	for (;pbIter <= pbLast; pbAddress++, pbIter++)
	{
		if (pbAddress < (BYTE *) pCS->dwStartAddress)
		{
			pbString = NULL;
			pwcString = NULL;
			continue;
		}
		
		if (pbAddress > (BYTE *) pCS->dwEndAddress)
			return;

		if (isprint(*pbIter) && isascii(*pbIter))
		{
			if (NULL == pbString)
				pbString = pbIter;
		}
		else if (NULL != pbString)
		{
			StringsProcSubChar(pbString, pbIter, pvAddress, lpBuffer, pCS);
			pbString = NULL;
		}
		
		if (0 == (((unsigned int) pbIter) & 1))
		{
			if (iswprint(*(WCHAR *) pbIter) && iswascii(*(WCHAR *) pbIter))
			{
				if (NULL == pwcString)
					pwcString = (WCHAR *) pbIter;
			}
			else if (NULL != pwcString)
			{
				StringsProcSubWchar(pwcString, (WCHAR *)pbIter, pvAddress, lpBuffer, pCS);
				pwcString = NULL;
			}
		}
	}
	
	if (NULL != pbString)
		StringsProcSubChar(pbString, pbIter, pvAddress, lpBuffer, pCS);
	if (NULL != pwcString)
		StringsProcSubWchar(pwcString, (WCHAR *)pbIter, pvAddress, lpBuffer, pCS);
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

void ExecuteStrings(DWORD dwPID, struct CommandStrings *pCS, HMODULE hmModArg)
{
	const char *pszError;
	int iErrorOffset;

  Output("strings %u:\n", dwPID);
  if (NULL != pCS->pszRegex && NULL == pCS->pPCRE)
  	if (LoadPCRE())
  		Output("Error loading pcre.dll, downgrading regex matching to substring search\n");
  	else
  	{
			pCS->pPCRE = pcrelib_compile(pCS->pszRegex, 0, &pszError, &iErrorOffset, NULL);
			if (NULL == pCS->pPCRE)
		  {
			  Output("PCRE compilation failed at offset %d: %s\n", iErrorOffset, pszError);
			  return;
		  }
  	}
  if (NULL != pCS->pszFilter)
  {
  	StringsFilter = NULL;
  	if (LoadPlugin(NULL, pCS->pszFilter))
  	{
  		Output("Error loading filter %s\n", pCS->pszFilter);
  		return;
  	}
	}
  	
  if (NULL == pCS->pszModule)
  	ProcessMemory(dwPID, &StringsProc, pCS, 0, pCS->dwMemory);
  else
  	ProcessModules(dwPID, pCS->pszModule, &StringsProc, pCS, 0, hmModArg);
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

double CalculateEntropy(BYTE *pbBuffer, SIZE_T sSize, double *pdAverage, double *pdDeltaAverage)
{
	BYTE *pbIter;
	SIZE_T asPrevelance[256];
	double dEntropy;
	double dPrevalence;
	double dAverage;
	double dDeltaAverage;
	int iIter;

	ZeroMemory(asPrevelance, sizeof(asPrevelance));
	dAverage = 0.0;
	dDeltaAverage = 0.0;
	for (pbIter = pbBuffer; pbIter < pbBuffer + sSize; pbIter++)
	{
		asPrevelance[*pbIter]++;
		dAverage += *pbIter;
		if (pbIter != pbBuffer)
			dDeltaAverage += fabs(*pbIter - *(pbIter - 1));
	}
		
	dEntropy = 0.0;
	for (iIter = 0; iIter < sizeof(asPrevelance)/sizeof(asPrevelance[0]); iIter++)
		if (asPrevelance[iIter] > 0)
		{
			dPrevalence = (double) asPrevelance[iIter] / (double) sSize;
			dEntropy += - dPrevalence * log10(dPrevalence) / log10(2.0);
		}
		
	*pdAverage = dAverage / sSize;
	*pdDeltaAverage = dDeltaAverage / (sSize + 1);
	
	return dEntropy;
}

void EntropyProc(HANDLE hProcess, LPVOID lpBuffer, SIZE_T sSize, PVOID pvAddress, void *pvData, unsigned int uiReadOnly)
{
	const int iStep = 4;
	const int iKeySize = 256;
	BYTE *pbIter;
	BYTE *pbLast;
	BYTE *pbAddress;
	double dEntropy;
	double dAverage;
	double dDeltaAverage;
	
	pbAddress = (BYTE *) pvAddress;
	pbIter = (BYTE *) lpBuffer;
	pbLast = pbIter + sSize - 1;
	
	for (;pbIter <= pbLast - iKeySize; pbAddress += iStep, pbIter += iStep)
	{
		dEntropy = CalculateEntropy(pbIter, iKeySize, &dAverage, &dDeltaAverage);
		if (dEntropy >= 7.5)
			Output(" %p: %f %f %f\n", pbAddress, dEntropy, dAverage, dDeltaAverage);
	}
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

void ExecuteTestFunction(DWORD dwPID)
{
  Output("test-function %u:\n", dwPID);
  ProcessMemory(dwPID, &EntropyProc, NULL, 0, PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY);
}

PBYTE File2Bytes(TCHAR *pszFilename, long *plSize)
{
	FILE *fIn;
	PBYTE pbBuffer;
	struct stat statFile;

	if (stat(pszFilename, &statFile))
		return NULL;
	*plSize = statFile.st_size;
	
	pbBuffer = (PBYTE)malloc(*plSize);
	if (NULL == pbBuffer)
		return NULL;

	fIn = fopen(pszFilename, _T("rb"));
	if (NULL == fIn)
	{
		free (pbBuffer);
		return NULL;
	}

	if (fread(pbBuffer, statFile.st_size, 1, fIn) != 1)
	{
		fclose (fIn);
		free (pbBuffer);
		return NULL;
	}
  
	fclose (fIn);
	
	return pbBuffer;
}

void ExecuteInjectCode(DWORD dwPID, struct CommandInjectCode *pCInjectCode, unsigned int uiReadOnly)
{
	PBYTE pbCode;
	long lCodeSize;
	
	if (pCInjectCode->bFilename)
	{
  	Output("inject-code in file %s:\n", (char *)pCInjectCode->pbBytes);
  	pbCode = File2Bytes((char *)pCInjectCode->pbBytes, &lCodeSize);
  	if (NULL == pbCode)
  	{
  		Output("File error\n");
  		return;
  	}
  }
  else
  {
  	Output("inject-code:\n");
  	pbCode = pCInjectCode->pbBytes;
  	lCodeSize = pCInjectCode->lBytesSize;
  }
  if (!uiReadOnly)
  	InjectCode(dwPID, pbCode, lCodeSize, pCInjectCode->uiMinimumBytesSize, pCInjectCode->bExecute);
}

void ExecuteStatements(DWORD dwPID, CONFIG *pConfig, HMODULE hmMod)
{
	STATEMENT *pStatement;
  char szProcessName[MAX_PATH];

	if (dwPID)
		if (GetProcessName(dwPID, szProcessName))
  		Output("Process %s (%u)\n", szProcessName, dwPID);
  	else
  		Output("Process %u\n", dwPID);

	for (pStatement = pConfig->statements; pStatement != NULL; pStatement = pStatement->next)
	{
		switch (pStatement->type)
		{
			case COMMAND_WRITE:
				ExecuteWrite(dwPID, pStatement->command, pConfig->uiReadOnly);
				break;
				
			case COMMAND_SEARCH_AND_WRITE:
				ExecuteSearchAndWrite(dwPID, pStatement->command, hmMod, pConfig->uiReadOnly);
				break;
				
			case COMMAND_PAUSE:
				ExecutePause();
				break;
				
			case COMMAND_CONFIRM:
				if (!ExecuteConfirm())
					return;
				break;
				
			case COMMAND_INJECT_DLL:
				ExecuteInjectDLL(dwPID, pStatement->command, pConfig->uiReadOnly);
				break;
				
			case COMMAND_REJECT_DLL:
				ExecuteRejectDLL(dwPID, pStatement->command, pConfig->uiReadOnly);
				break;
				
			case COMMAND_DUMP:
				ExecuteDump(dwPID);
				break;
				
			case COMMAND_INFO:
				ExecuteInfo();
				break;
				
			case COMMAND_SUSPEND:
				ExecuteSuspend(dwPID, pConfig->uiReadOnly);
				break;
				
			case COMMAND_RESUME:
				ExecuteResume(dwPID, pConfig->uiReadOnly);
				break;
				
			case COMMAND_PRINT:
				ExecutePrint(pStatement->command);
				break;
				
			case COMMAND_ADJUST_TOKE_PRIVILEGES:
				ExecuteAdjustTokenPrivileges(dwPID, pConfig->uiReadOnly);
				break;
				
			case COMMAND_STRINGS:
				ExecuteStrings(dwPID, pStatement->command, hmMod);
				break;
				
			case COMMAND_TEST_FUNCTION:
				ExecuteTestFunction(dwPID);
				break;
				
			case COMMAND_INJECT_CODE:
				ExecuteInjectCode(dwPID, pStatement->command, pConfig->uiReadOnly);
				break;
				
			default:
				break;
		}
	}	

  Output("\n");
}

int WorkWithProcessName(CONFIG *pConfig)
{
	DWORD dwPIDs[MAXPROCESSES];
	DWORD dwBytes;
	unsigned int uiIter;
	char szProcessName[MAX_PATH];
	BOOL bExecute;
	
	Output("Target process name = %s\n", pConfig->szProcessName);

	if (!EnumProcesses(dwPIDs, sizeof(dwPIDs), &dwBytes))
		return 0;

	for (uiIter = 0; uiIter < dwBytes/sizeof(DWORD); uiIter++)
  	if (dwPIDs[uiIter])
		{
			bExecute = FALSE;
			if (!stricmp("*", pConfig->szProcessName))
				bExecute = TRUE;
			else
			{
				if (GetProcessName(dwPIDs[uiIter], szProcessName))
		  		bExecute = !stricmp(szProcessName, pConfig->szProcessName);
			}
  		if (bExecute)
				ExecuteStatements(dwPIDs[uiIter], pConfig, GetProcessImageModule(dwPIDs[uiIter]));
		}
	
	return 1;
}

int WorkWithDLLName(CONFIG *pConfig)
{
	DWORD dwPIDs[MAXPROCESSES];
	DWORD dwBytes;
	unsigned int uiIter;
	HMODULE hmMod;

	Output("Target dll name = %s\n", pConfig->szDLLName);

	if (!EnumProcesses(dwPIDs, sizeof(dwPIDs), &dwBytes))
		return 0;
	
	for (uiIter = 0; uiIter < dwBytes/sizeof(DWORD); uiIter++)
  	if (dwPIDs[uiIter] != 0)
		{
			hmMod = GetModuleForProcess(dwPIDs[uiIter], pConfig->szDLLName);
			if (hmMod != 0)
				ExecuteStatements(dwPIDs[uiIter], pConfig, hmMod);
		}
	
	return 1;
}

int WorkWithPID(CONFIG *pConfig)
{
	Output("Target pid = %u\n", pConfig->dwPID);
	if (pConfig->dwPID != 0)
	{
		ExecuteStatements(pConfig->dwPID, pConfig, GetProcessImageModule(pConfig->dwPID));
		return 1;
	}
	else
		return 0;
}

int WorkWithStart(CONFIG *pConfig)
{
  STARTUPINFO sSI;
  PROCESS_INFORMATION sPI;
	
	Output("Target start = %s\n", pConfig->szStart);

	if (pConfig->uiReadOnly)
		return 1;
		
  ZeroMemory(&sSI, sizeof(sSI));
  sSI.cb = sizeof(sSI);
  ZeroMemory(&sPI, sizeof(sPI));

  if (!CreateProcess(NULL, pConfig->szStart, NULL, NULL, FALSE, CREATE_NEW_CONSOLE|CREATE_SUSPENDED, NULL, NULL, &sSI, &sPI))
  {
	  Output ("CreateProcess failed (%d)\n", GetLastError());
	  return 0;
  }

	//Injecting a DLL that doesn't exists or one that will be loaded, loads all DLLs, works for CMD.exe, not for regedit.exe
	InjectDLL(sPI.dwProcessId, "kernel32.dll");
	PrintModules(sPI.dwProcessId);
	
	ExecuteStatements(sPI.dwProcessId, pConfig, GetProcessImageModule(sPI.dwProcessId));
	
	ResumeThread(sPI.hThread);
	
  //WaitForSingleObject(sPI.hProcess, INFINITE);

  CloseHandle(sPI.hProcess);
  CloseHandle(sPI.hThread);

	return 1;
}

int ExecuteConfig(CONFIG *pConfig)
{
	if (NULL != pConfig->pszPlugin)
		if (LoadPlugin(pConfig->pszPlugin, NULL))
		{
			Output("Error loading plugin %s\n", pConfig->pszPlugin);
			return -1;
		}
	
	if (pConfig->szProcessName != NULL)
		return WorkWithProcessName(pConfig);
	else if (pConfig->szDLLName != NULL)
		return WorkWithDLLName(pConfig);
	else if (pConfig->dwPID != 0)
		return WorkWithPID(pConfig);
	else if (pConfig->szStart != NULL)
		return WorkWithStart(pConfig);
	else
	{
		ExecuteStatements(0, pConfig, NULL);
		return 1;
	}
}

void DisplayUsage(void)
{
	Output(
	  "Usage: bpmtk [configfile [exefile]]\n"\
		" Format configfile:\n"\
		"  dll-name dll_name\n"\
		"  process-name process_name\n"\
		"  pid PID\n"\
		"  start [currentdirectory:]program\n"\
		"\n"\
		"  verbose [0|1]\n"\
		"  readonly\n"\
		"  disable-console-output\n"\
		"  output-to-file [filename]\n"\
		"  plugin dll-filename\n"\
		"  repeat wait [count]\n"\
		"\n"\
		"  write [version:version-number] hex:address [hex|ascii|unicode]:value\n"\
		"  search-and-write [module:module-name|*|.] [memory:writable] [hex|ascii|unicode]:value [hex|ascii|unicode]:value\n"\
		"  inject-dll [currentdirectory:]dll_name\n"\
		"  reject-dll dll_name\n"\
		"  pause\n"\
		"  dump\n"\
		"  info\n"\
		"  confirm\n"\
		"  suspend\n"\
		"  resume\n"\
		"  print [text]\n"\
		"    text can contain placeholders $date and $time\n"\
		"  adjust-token-privileges me\n"\
		"  strings [module:module-name|*|.] [memory:writable] [address:[on|off]] [minimum-length:number] [alpha-percentage:number] [start-address:address] [end-address:address] [regex:expression] [filter:plugin-function]\n"\
		"\n"\
	  "Basic Process Manipulation Tool Kit (BPMTK) V%s\n"\
	  "Source code put in public domain by Didier Stevens, no Copyright\n"\
	  "https://DidierStevens.com\n"\
	  "Use at your own risk\n"\
		, VERSION_STRING);
}

LPSTR File2Str(TCHAR *pszConfigFilename)
{
	FILE *fIn;
	LPSTR pszBuffer;
	struct stat statFile;

	if (stat(pszConfigFilename, &statFile))
	{
		_ftprintf(stderr, _T("Error opening config file %s\n"), pszConfigFilename);
		return NULL;
	}

	pszBuffer = (LPSTR) malloc(statFile.st_size+1);
	if (NULL == pszBuffer)
	{
		_ftprintf (stderr, _T("Error file %s is too large %ld\n"), pszConfigFilename, statFile.st_size);
		return NULL;
	}

	fIn = fopen(pszConfigFilename, _T("rb"));
	if (NULL == fIn)
	{
		fprintf(stderr, _T("Error opening file %s\n"), pszConfigFilename);
		free (pszBuffer);
		return NULL;
	}

	if (fread(pszBuffer, statFile.st_size, 1, fIn) != 1)
	{
		fprintf(stderr, _T("Error reading file %s\n"), pszConfigFilename);
		fclose (fIn);
		free (pszBuffer);
		return NULL;
	}
  ((char *)pszBuffer)[statFile.st_size] = '\0';
  
	fclose (fIn);
	
	return pszBuffer;
}

void CreateEXEWithEmbeddedConfig(TCHAR *pszInputEXE, TCHAR *pszConfigFilename, TCHAR *pszOutputEXE)
{
	CONFIG config;
	HANDLE hUpdate;
	LPSTR pszConfig;
	
	pszConfig = File2Str(pszConfigFilename);
	if (NULL == pszConfig)
		return;
	
	if (ParseConfig(pszConfig, &config))
	{
		_ftprintf(stderr, _T("Error in config file %s\n"), pszConfigFilename);
		return;
	}

	if (CheckConfig(&config))
	{
		_ftprintf(stderr, _T("Error in config file %s\n"), pszConfigFilename);
		return;
	}

	if (!CopyFile(pszInputEXE, pszOutputEXE, FALSE))
	{
		_ftprintf(stderr, _T("Error copying %s to %s\n"), pszInputEXE, pszOutputEXE);
		return;
	}
	
	hUpdate = BeginUpdateResource(pszOutputEXE, FALSE);
	if (NULL == hUpdate)
	{
		_ftprintf(stderr, _T("Error opening resources %u\n"), GetLastError());
		return;
	}
	
	if (!UpdateResource(hUpdate, MAKEINTRESOURCE(RT_RCDATA), RESOURCE_BPMTK, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pszConfig, strlen(pszConfig)+1))
	{
		_ftprintf(stderr, _T("Error storing resource %s\n"), RESOURCE_BPMTK);
		EndUpdateResource(hUpdate, TRUE);
		return;
	}

	if (!EndUpdateResource(hUpdate, FALSE))
	{
		_ftprintf(stderr, _T("Error writing resources\n"));
		return;
	}
	
	free(pszConfig);
}

LPSTR GetConfigFromResources(void)
{
	HRSRC hrConfig;
	HGLOBAL hgConfig;
	LPSTR pszBuffer;

	hrConfig = FindResource(NULL, RESOURCE_BPMTK, MAKEINTRESOURCE(RT_RCDATA));
	if (NULL != hrConfig)
	{
		if (NULL == LockResource(hrConfig))
		{
	  	Output ("LockResource failed (%d)\n", GetLastError());
			return NULL;
		}
		hgConfig = LoadResource(NULL, hrConfig);
		if (NULL != hgConfig)
		{
			pszBuffer = malloc(strlen((LPSTR) hgConfig)+1);
			if (NULL == pszBuffer)
				return NULL;
			CopyMemory(pszBuffer, (LPSTR) hgConfig, strlen((LPSTR) hgConfig)+1);
			return (LPSTR) pszBuffer;
		}
		else
		{
	  	Output ("LoadResource failed (%d)\n", GetLastError());
			return NULL;
		}
	}
	return NULL;
}

main(int argc, char** argv)
{
	CONFIG config;
  char szConfigFilename[MAX_PATH];
	int iRet;
	LPSTR pszConfig;
	unsigned int uiRepeatCountdown;

	switch (argc)
	{
  	int iPos;

		case 1:
			pszConfig = GetConfigFromResources();
			if (NULL == pszConfig)
			{
				strcpy(szConfigFilename, argv[0]);
				iPos = strlen(szConfigFilename)-4;
				if (stricmp(szConfigFilename+iPos, ".exe"))
					return -1;
				strcpy(szConfigFilename+iPos, ".txt");
				pszConfig = File2Str(szConfigFilename);
			}
			break;
			
		case 2:
			pszConfig = File2Str(argv[1]);
			break;
			
		case 3:
			CreateEXEWithEmbeddedConfig(argv[0], argv[1], argv[2]);
			return 0;
			
		default:
			DisplayUsage();
			return -1;
	}
	
	if (NULL == pszConfig)
	{
		_ftprintf(stderr, _T("Error reading config\n"));
		return -1;
	}
		
	if (ParseConfig(pszConfig, &config))
		return -2;
	free(pszConfig);

	if (CheckConfig(&config))
		return -3;

	ConfigVerbose(config.uiVerbose);
	if (config.uiDisableConsoleOutput)
		DisableConsoleOutput();
	OutputToFile(config.pszOutputToFile);

	uiRepeatCountdown = config.uiRepeatCount;
	while (TRUE)
	{
		iRet = ExecuteConfig(&config);
		if (!config.uiRepeatSleep)
			break;
		if (config.uiRepeatCount)
			if (!--uiRepeatCountdown)
				break;
		Sleep(config.uiRepeatSleep*1000);
	}

	OutputFileClose();
	
	return iRet;
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
//	LPSTR pszConfig = "#BPMTK_CONFIG_BEGIN\r\noutput-to-file\r\ndll-name advapi32.dll\r\nsearch-and-write module:. unicode:TransparentEnabled ascii:A\r\nwrite version:5.1.2600.2180 hex:77E463C8 hex:00\r\n                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \r\n#BPMTK_CONFIG_END\r\n";
	LPSTR pszConfig = "#BPMTK_CONFIG_BEGIN\r\ndll-name advapi32.dll\r\nsearch-and-write module:. unicode:TransparentEnabled ascii:A\r\nwrite version:5.1.2600.2180 hex:77E463C8 hex:00\r\n                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \r\n#BPMTK_CONFIG_END\r\n";
	CONFIG config;

	switch(fdwReason) 
	{ 
	  case DLL_PROCESS_ATTACH:
    	if (ParseConfig(pszConfig, &config))
    		return FALSE;
    	if (CheckConfig(&config))
    		return FALSE;
    	ConfigVerbose(config.uiVerbose);
    	DisableConsoleOutput();
    	OutputToFile(config.pszOutputToFile);
    	ExecuteConfig(&config);
			OutputFileClose();
    	return FALSE;
	
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
