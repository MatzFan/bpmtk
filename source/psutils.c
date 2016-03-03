/*
	process utilities for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/23: Start development
	2008/01/30: added RejectDLL
	2008/01/31: code review
	2008/02/03: added PrintProcesses
	2008/02/04: added PrintMemory
	2008/02/05: continued PrintMemory
	2008/02/06: added GetAppVersion
	2008/02/07: updated GetAppVersion
	2008/02/08: code review, added GetModuleForProcess, added GetModuleVersion
	2008/02/10: added SuspendProcess, ResumeProcess, QSort
	2008/02/11: made CurrentProcessAdjustToken
	2008/02/15: added ProcessMemory
	2008/02/17: added ProcessModules
	2008/02/25: added dwProtect to ProcessMemory
	2008/02/27: added GetProcessOwner
	2008/10/15: added InjectCode
	2008/10/18: updated InjectCode
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>

#include "psutils.h"
#include "output.h"

#pragma comment(lib, "psapi.lib")

// global variable for the verbosity level
static UINT g_uiVerbose;

// function to set the verbosity level
void ConfigVerbose(UINT uiVerbose)
{
	g_uiVerbose = uiVerbose;
}

// Returns the handle to the module (HMODULE) of the process with process-id dwPID
// Returns 0 if not found.
HMODULE GetProcessImageModule(DWORD dwPID)
{
  HANDLE hProcess;
  HMODULE hmMod;
	DWORD dwDummy;
	
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPID);
	if (NULL == hProcess)
		return NULL;

  if (!EnumProcessModules(hProcess, &hmMod, sizeof(hmMod), &dwDummy))
	  hmMod = NULL;

  CloseHandle(hProcess);
  
  return hmMod;
}

// Writes the name of process with process-id dwPID into szName (assumes size MAX_PATH)
// The name doesn't include the path
// Returns TRUE on succes, FALSE on failure
// not yet tchar compliant
BOOL GetProcessName(DWORD dwPID, char *szName)
{
	BOOL bRet;
	HANDLE hProcess;
	HMODULE hmMod;
	DWORD dwDummy;
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPID);
	if (NULL == hProcess)
		return FALSE;
	
	if (EnumProcessModules(hProcess, &hmMod, sizeof(hmMod), &dwDummy))
		bRet = (0 != GetModuleBaseName(hProcess, hmMod, szName, MAX_PATH));
	else
		bRet = FALSE;
	
	CloseHandle(hProcess);
	
	return bRet;
}

// Returns the HMODULE for module szModNameArg in the process with process-id dwPID
// Returns NULL when the mudole is not loaded
HMODULE GetModuleForProcess(DWORD dwPID, char *szModNameArg)
{
	HANDLE hProcess;
	HMODULE ahmModules[MAXMODULES];
	DWORD dwBytes;
	unsigned int uiIter;
	TCHAR szModName[MAX_PATH];
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPID);
	if (NULL == hProcess)
		return NULL;
	
	if (EnumProcessModules(hProcess, ahmModules, sizeof(ahmModules), &dwBytes))
    for (uiIter = 0; uiIter < dwBytes/sizeof(HMODULE); uiIter++)
      if (GetModuleBaseName(hProcess, ahmModules[uiIter], szModName, sizeof(szModName)/sizeof(TCHAR)))
      	if (!_tcsicmp(szModName, szModNameArg))
      	{
					CloseHandle(hProcess);
					return ahmModules[uiIter];
      	}
	
	CloseHandle(hProcess);
	
	return NULL;
}

// Print modules of process with process-id dwPID to STDOUT
// not yet tchar compliant
void PrintModules(DWORD dwPID)
{
	HANDLE hProcess;
	HMODULE ahmModules[MAXMODULES];
	DWORD dwBytes;
	unsigned int uiIter;
	MODULEINFO sMI;
  TCHAR szModName[MAX_PATH];

	Output("Process ID: %u\n", dwPID);
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPID);
	if (NULL == hProcess)
	{
		Output("OpenProcess failed\n");
	  return;
	}
	
	if (EnumProcessModules(hProcess, ahmModules, sizeof(ahmModules), &dwBytes))
	{
    for (uiIter = 0; uiIter < dwBytes/sizeof(HMODULE); uiIter++)
      if (GetModuleFileNameEx(hProcess, ahmModules[uiIter], szModName, sizeof(szModName)/sizeof(TCHAR)))
      	if (GetModuleInformation(hProcess, ahmModules[uiIter], &sMI, sizeof(MODULEINFO)))
        	Output(TEXT("\t%s (0x%08X) (0x%08X)\n"), szModName, ahmModules[uiIter], sMI.lpBaseOfDll);
  }
	else
		Output("EnumProcessModules failed %u\n", GetLastError());
	
	CloseHandle(hProcess);
}

// Lookup the process-id for process with name szProcessNameArg
// Return 0 when not found or error occured
// not yet tchar compliant
DWORD LookupPID(char *szProcessNameArg)
{
	DWORD adwPIDs[MAXPROCESSES];
	DWORD dwBytes;
	unsigned int uiIter;
  char szProcessName[MAX_PATH];

	if(!EnumProcesses(adwPIDs, sizeof(adwPIDs), &dwBytes))
		return 0;
	
	for (uiIter = 0; uiIter < dwBytes/sizeof(DWORD); uiIter++)
  	if (adwPIDs[uiIter] != 0)
			if (GetProcessName(adwPIDs[uiIter], szProcessName))
				if (!stricmp(szProcessName, szProcessNameArg))
    			return adwPIDs[uiIter];
    
  return 0;
}

//Adjust token privileges to enable SE_DEBUG_NAME
BOOL CurrentProcessAdjustToken(void)
{
  HANDLE hToken;
  TOKEN_PRIVILEGES sTP;

  if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
  }
	return FALSE;
}

// Inject DLL szDLLName in process with process-id dwPID
// If the DLL is not in the PATH of the process, use a full pathname for szDLLName
// Returns true on succes, false on failure
BOOL InjectDLL(DWORD dwPID, char *szDLLName)
{
  HMODULE hmKernel32;
  FARPROC fpLoadLibraryA;
  HANDLE hProcess;
  LPVOID lpRemoteMemory;
  DWORD dwBytes;
  HANDLE hRemoteThread;
  BOOL bRet;
  
  hmKernel32 = GetModuleHandle("Kernel32");
  if (NULL == hmKernel32)
  	return FALSE;
  	
  fpLoadLibraryA = GetProcAddress(hmKernel32, "LoadLibraryA");
  if (NULL == fpLoadLibraryA)
  	return FALSE;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
  if (NULL == hProcess)
  	return FALSE;
  if (g_uiVerbose)
  	Output("dwPID %u hProcess = %08X\n", dwPID, hProcess);

  lpRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(szDLLName)+1, MEM_COMMIT, PAGE_READWRITE);
  if (NULL == lpRemoteMemory)
  {
  	CloseHandle(hProcess);
  	return FALSE;
  }
  if (g_uiVerbose)
	  Output("lpRemoteMemory = %08X\n", lpRemoteMemory);

  if (g_uiVerbose)
	  Output("szDLLName = '%s'\n", szDLLName);
  if (0 == WriteProcessMemory(hProcess, lpRemoteMemory, szDLLName, strlen(szDLLName)+1, &dwBytes))
  {
	  VirtualFreeEx(hProcess, lpRemoteMemory, strlen(szDLLName)+1, MEM_RELEASE);
	  CloseHandle(hProcess);
  	return FALSE;
  }
  if (g_uiVerbose)
	  Output("dwBytes = %d\n", dwBytes);

  hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpLoadLibraryA, lpRemoteMemory, 0, NULL);
  if (g_uiVerbose)
	  Output("hRemoteThread = %08X\n", hRemoteThread);

  if (0 != hRemoteThread)
  	bRet = WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
  else
  	bRet = FALSE;

  VirtualFreeEx(hProcess, lpRemoteMemory, strlen(szDLLName)+1, MEM_RELEASE);

  CloseHandle(hProcess);

  return bRet;
}

// Remove DLL szDLLName from process with process-id dwPID
// Don't use a full pathname for szDLLName
// Returns true on succes, false on failure
BOOL RejectDLL(DWORD dwPID, char *szDLLName)
{
  HMODULE hmKernel32;
  FARPROC fpFreeLibrary;
  HANDLE hProcess;
  HMODULE hmDLL;
  HANDLE hRemoteThread;
  BOOL bRet;
  
  hmKernel32 = GetModuleHandle("Kernel32");
  if (NULL == hmKernel32)
  	return FALSE;

  fpFreeLibrary = GetProcAddress(hmKernel32, "FreeLibrary");
  if (NULL == fpFreeLibrary)
  	return FALSE;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
  if (NULL == hProcess)
  	return FALSE;
  if (g_uiVerbose)
  	Output("dwPID %u hProcess = %08X\n", dwPID, hProcess);

	hmDLL = GetModuleForProcess(dwPID, szDLLName);
	if (NULL == hmDLL)
	{
  	CloseHandle(hProcess);
  	return FALSE;
	}
	
  hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpFreeLibrary, hmDLL, 0, NULL);
  if (g_uiVerbose)
	  Output("hRemoteThread = %08X\n", hRemoteThread);

  if (0 != hRemoteThread)
  	bRet = WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
  else
  	bRet = FALSE;

  CloseHandle(hProcess);

  return bRet;
}

int QSortCompareDWORD(const void *a, const void *b)
{
  return (*(DWORD *)a - *(DWORD *)b);
}

// Quick sort (ascending) array od DWORDs adwList with iCount DWORDs
void QSort(DWORD *pdwList, int iCount)
{
	qsort(pdwList, iCount, sizeof(DWORD), QSortCompareDWORD);
}

// Print processes to STDOUT
// not yet tchar compliant
void PrintProcesses(void)
{
	DWORD adwPIDs[MAXPROCESSES];
	DWORD dwBytes;
	unsigned int uiIter;
  char szProcessName[MAX_PATH];
  char szUserName[MAX_PATH];
  char szDomainName[MAX_PATH];

	if(!EnumProcesses(adwPIDs, sizeof(adwPIDs), &dwBytes))
		return;
	
	QSort(adwPIDs, dwBytes/sizeof(DWORD));
	Output("%d processes:\n", dwBytes/sizeof(DWORD));
	for (uiIter = 0; uiIter < dwBytes/sizeof(DWORD); uiIter++)
  	if (adwPIDs[uiIter] != 0)
  	{
			Output(" %5u", adwPIDs[uiIter]);
			if (GetProcessName(adwPIDs[uiIter], szProcessName))
				Output(" %s", szProcessName);
			if (!GetProcessOwner(adwPIDs[uiIter], szUserName, szDomainName))
				Output(" %s\\%s", szDomainName, szUserName);
			Output("\n");
		}
    
  return;
}

char *MBIState2Str(DWORD dwState)
{
	static char szReturn[256];
	
	strcpy(szReturn, "");
	
	if (dwState & MEM_COMMIT)
		strcat(szReturn, "C");
	if (dwState & MEM_FREE)
		strcat(szReturn, "F");
	if (dwState & MEM_RESERVE)
		strcat(szReturn, "R");
	
	return szReturn;
}

char *MBIType2Str(DWORD dwType)
{
	switch (dwType)
	{
		case MEM_IMAGE:
			return "Image";
			
		case MEM_MAPPED:
			return "Mapped";
			
		case MEM_PRIVATE:
			return "Private";
			
		default:
			return "?";
	}
}

char *MBIProtect2Str(DWORD dwProtect)
{
	static char szReturn[256];
	
	strcpy(szReturn, "");
	
	if (dwProtect & PAGE_WRITECOMBINE)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "C0");
	}
		
	if (dwProtect & PAGE_NOCACHE)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "NC");
	}
		
	if (dwProtect & PAGE_GUARD)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "G");
	}
		
	if (dwProtect & PAGE_EXECUTE_WRITECOPY)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "EWC");
	}
		
	if (dwProtect & PAGE_EXECUTE_READWRITE)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "ERW");
	}
		
	if (dwProtect & PAGE_EXECUTE_READ)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "ER");
	}
		
	if (dwProtect & PAGE_EXECUTE)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "E");
	}
		
	if (dwProtect & PAGE_WRITECOPY)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "WC");
	}
		
	if (dwProtect & PAGE_READWRITE)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "RW");
	}
		
	if (dwProtect & PAGE_READONLY)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "RO");
	}
		
	if (dwProtect & PAGE_NOACCESS)
	{
		if (strcmp(szReturn, ""))
			strcat(szReturn, " ");
		strcat(szReturn, "NA");
	}

	return szReturn;
}

// Translate path with device name to drive letters.
// http://msdn2.microsoft.com/en-us/library/aa366789(VS.85).aspx      			
BOOL DeviceFilename2DriveFilename(TCHAR *szDeviceFilename, TCHAR *szDriveFilename)
{
  TCHAR szLogicalDrives[512] = _T("");
  TCHAR szName[MAX_PATH];
  TCHAR szDrive[3] = _T(" :");
  BOOL bFound = FALSE;
  TCHAR* p = szLogicalDrives;
  UINT uNameLen;

  if (GetLogicalDriveStrings(sizeof(szLogicalDrives)-1, szLogicalDrives)) 
    do 
    {
      *szDrive = *p;

      if (QueryDosDevice(szDrive, szName, MAX_PATH))
      {
        uNameLen = _tcslen(szName);

        if (uNameLen < MAX_PATH) 
        {
          bFound = 0 == _tcsnicmp(szDeviceFilename, szName, uNameLen);

          if (bFound) 
            _sntprintf(szDriveFilename, MAX_PATH, _T("%s%s"), szDrive, szDeviceFilename+uNameLen);
        }
      }

      while (*p++);
    } while (!bFound && *p);
    
  return bFound;
}

// Print memory of process with process-id dwPID to STDOUT
// not yet tchar compliant
void PrintMemory(DWORD dwPID)
{
	HANDLE hProcess;
	LPVOID lpMem;
  SYSTEM_INFO sSI;
  MEMORY_BASIC_INFORMATION sMBI;
  char szFileMemoryList[MAX_PATH];
  char szFileDump[MAX_PATH];
  char szLine[MAX_PATH];
  HANDLE hFile;
  DWORD dwResult;
	LPVOID lpBuffer;
	SIZE_T stBufferSize;
	FILE *fMemoryList;
  TCHAR szDeviceMappedFile[MAX_PATH];
  TCHAR szDriveMappedFile[MAX_PATH];
	WORD wMajorVersion;
	WORD wMinorVersion;
	WORD wBuildNumber;
	WORD wRevisionNumber;
	TCHAR *pszPrintMappedFile;
	
	Output("Process ID: %u\n", dwPID);
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPID);
	if (NULL == hProcess)
	{
		Output("OpenProcess failed\n");
	  return;
	}
	
	GetSystemInfo(&sSI);

	lpBuffer = NULL;
	stBufferSize = 0;
	
	snprintf(szFileMemoryList, MAX_PATH, "%d-dump.txt", dwPID);
	fMemoryList = fopen(szFileMemoryList, "w");
	if (NULL == fMemoryList)
	{
	  Output("Could not open file %s\n", szFileMemoryList);
	  return;
	}
	
	snprintf(szLine, MAX_PATH, "BaseAddress State RegionSize Protect AllocationBase AllocationProtect Type MappedFile MajorVersion MinorVersion BuildNumber RevisionNumber\n");
	Output(szLine);
	fputs(szLine, fMemoryList);
	
	for (lpMem = 0; lpMem < sSI.lpMaximumApplicationAddress; lpMem = (LPVOID)((DWORD)sMBI.BaseAddress + (DWORD)sMBI.RegionSize))
	{
	    if (!VirtualQueryEx(hProcess, lpMem, &sMBI, sizeof(MEMORY_BASIC_INFORMATION)))
	    	Output("VirtualQueryEx returned 0, lpMem = %08X\n", lpMem);
	    else
	    {
	    	if (MEM_COMMIT == sMBI.State || g_uiVerbose)
	    	{
					wMajorVersion = wMinorVersion = wBuildNumber = wRevisionNumber = 0;
      		pszPrintMappedFile = szDeviceMappedFile;
      		if (!GetMappedFileName(hProcess, lpMem, szDeviceMappedFile, sizeof(szDeviceMappedFile)/sizeof(TCHAR)))
      			_tcscpy(szDeviceMappedFile, "");
      		else
						if (DeviceFilename2DriveFilename(szDeviceMappedFile, szDriveMappedFile))
						{
		      		pszPrintMappedFile = szDriveMappedFile;
	      			if (!GetAppVersion(szDriveMappedFile, &wMajorVersion, &wMinorVersion, &wBuildNumber, &wRevisionNumber))
	    					wMajorVersion = wMinorVersion = wBuildNumber = wRevisionNumber = 0;
	    			}
		    	Output("%08X %-4s %08X %-10s %08X %-10s %-7s \"%s\" %d.%d.%d.%d\n", sMBI.BaseAddress, MBIState2Str(sMBI.State), sMBI.RegionSize, MBIProtect2Str(sMBI.Protect), sMBI.AllocationBase, MBIProtect2Str(sMBI.AllocationProtect), MBIType2Str(sMBI.Type), pszPrintMappedFile, wMajorVersion, wMinorVersion, wBuildNumber, wRevisionNumber);
		    	fprintf(fMemoryList, "%08X %08X %08X %08X %08X %08X %08X \"%s\" %d.%d.%d.%d\n", sMBI.BaseAddress, sMBI.State, sMBI.RegionSize, sMBI.Protect, sMBI.AllocationBase, sMBI.AllocationProtect, sMBI.Type, pszPrintMappedFile, wMajorVersion, wMinorVersion, wBuildNumber, wRevisionNumber);
		    }
	    	if (MEM_COMMIT == sMBI.State)
	    	{
		    	snprintf(szFileDump, MAX_PATH, "%d-%08X.dump", dwPID, sMBI.BaseAddress);
		    	hFile = CreateFile(szFileDump, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hFile == INVALID_HANDLE_VALUE) 
				  { 
				      Output("Could not open file (error %d)\n", GetLastError());
				      return;
				  }

					if (sMBI.RegionSize > stBufferSize)
					{
						if (NULL != lpBuffer)
							if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
							{ 
								Output("Could not free memory (error %d)\n", GetLastError());
								return;
							}
							
						lpBuffer = VirtualAlloc(NULL, sMBI.RegionSize, MEM_RESERVE|MEM_COMMIT,	PAGE_READWRITE);
						if (NULL == lpBuffer) 
					  { 
					      Output("Could not alloc memory (error %d)\n", GetLastError());
					      return;
					  }
					  stBufferSize = sMBI.RegionSize;
					}
					
					if (ReadProcessMemory(hProcess, sMBI.BaseAddress, lpBuffer, sMBI.RegionSize, &dwResult))
					{
					  if(!WriteFile (hFile, lpBuffer, sMBI.RegionSize, &dwResult, NULL))
					  {
					      Output("Could not write to file (error %d)\n", GetLastError());
					      return;
					  }
					}
					else
						Output("Could not read memory (error %d)\n", GetLastError());

			    CloseHandle(hFile);
		    }
		  }
	}
	
	if (NULL != lpBuffer && !VirtualFree(lpBuffer, 0, MEM_RELEASE))
  { 
	  Output("Could not free memory (error %d)\n", GetLastError());
	  return;
  }

	fclose(fMemoryList);
	
	CloseHandle(hProcess);
}

// Get version info for file szFilename
// Returns TRUE for succes, FALSE for failure
BOOL GetAppVersion(TCHAR *szFilename, WORD *wMajorVersion, WORD *wMinorVersion, WORD *wBuildNumber, WORD *wRevisionNumber)
{
	DWORD dwHandle;
	DWORD dwLen;
	UINT uiDummy;
	LPVOID lpData;
	VS_FIXEDFILEINFO *sFFI;
	
	dwLen = GetFileVersionInfoSize(szFilename, &dwHandle);
	if (!dwLen) 
		return FALSE;
	
	lpData = malloc(dwLen);
	if (NULL == lpData) 
		return FALSE;
	
	if(!GetFileVersionInfo(szFilename, dwHandle, dwLen, lpData))
	{
		free(lpData);
		return FALSE;
	}
	
	if(VerQueryValue(lpData, _T("\\"), (LPVOID) &sFFI, &uiDummy)) 
	{
		*wMajorVersion = HIWORD(sFFI->dwFileVersionMS);
		*wMinorVersion = LOWORD(sFFI->dwFileVersionMS);
		*wBuildNumber = HIWORD(sFFI->dwFileVersionLS);
		*wRevisionNumber = LOWORD(sFFI->dwFileVersionLS);
		free(lpData);
		return TRUE;
	}
	
	free(lpData);
	return FALSE;
}

BOOL GetModuleVersion(HANDLE hProcess, LPVOID lpAddress, TCHAR *pszVersion)
{
  TCHAR szDeviceMappedFile[MAX_PATH];
  TCHAR szDriveMappedFile[MAX_PATH];
	WORD wMajorVersion;
	WORD wMinorVersion;
	WORD wBuildNumber;
	WORD wRevisionNumber;

	if (!GetMappedFileName(hProcess, lpAddress, szDeviceMappedFile, sizeof(szDeviceMappedFile)/sizeof(TCHAR)))
		return FALSE;
	else
		if (DeviceFilename2DriveFilename(szDeviceMappedFile, szDriveMappedFile))
		{
			if (GetAppVersion(szDriveMappedFile, &wMajorVersion, &wMinorVersion, &wBuildNumber, &wRevisionNumber))
			{
	    	sprintf(pszVersion, "%d.%d.%d.%d", wMajorVersion, wMinorVersion, wBuildNumber, wRevisionNumber);
	    	return TRUE;
		  }
		  else
		  	return FALSE;
		}
		else
			return FALSE;
}

void SuspendResumeThreads(DWORD dwPID, BOOL bSuspend) 
{ 
	HANDLE hThreadSnap; 
	THREADENTRY32 sTE32 = {0}; 
	BOOL bLoop;
 
  hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
  if (INVALID_HANDLE_VALUE == hThreadSnap) 
      return; 

  sTE32.dwSize = sizeof(sTE32); 

  for (bLoop = Thread32First(hThreadSnap, &sTE32); bLoop; bLoop = Thread32Next(hThreadSnap, &sTE32))
	  if (sTE32.th32OwnerProcessID == dwPID) 
	  {
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, sTE32.th32ThreadID);
			if (hThread != NULL)
			{
				if (bSuspend)
					Output(_T(" suspending thread %08X: %u\n"), sTE32.th32ThreadID, SuspendThread(hThread));
				else
					Output(_T(" resuming thread %08X: %u\n"), sTE32.th32ThreadID, ResumeThread(hThread));
				CloseHandle(hThread);
			}
	  } 

  CloseHandle(hThreadSnap); 

  return; 
} 


void SuspendProcess(DWORD dwPID)
{
	SuspendResumeThreads(dwPID, TRUE);
}

void ResumeProcess(DWORD dwPID)
{
	SuspendResumeThreads(dwPID, FALSE);
}

int ProcessMemory(DWORD dwPID, void (*pfProcess)(HANDLE, LPVOID, SIZE_T, PVOID, void *, unsigned int), void *pvData, unsigned int uiReadOnly, DWORD dwProtect)
{
	HANDLE hProcess;
	LPVOID lpMem;
  SYSTEM_INFO sSI;
	LPVOID lpBuffer;
	SIZE_T stBufferSize;
  MEMORY_BASIC_INFORMATION sMBI;
  DWORD dwResult;
  
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, dwPID);
	if (NULL == hProcess)
	  return -1;
	
	GetSystemInfo(&sSI);
	lpBuffer = NULL;
	stBufferSize = 0;
	for (lpMem = 0; lpMem < sSI.lpMaximumApplicationAddress; lpMem = (LPVOID)((DWORD)sMBI.BaseAddress + (DWORD)sMBI.RegionSize))
    if (VirtualQueryEx(hProcess, lpMem, &sMBI, sizeof(MEMORY_BASIC_INFORMATION)))
    	if (MEM_COMMIT == sMBI.State && (!dwProtect || (sMBI.Protect & dwProtect)))
    	{
				if (sMBI.RegionSize > stBufferSize)
				{
					if (NULL != lpBuffer)
						if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
							return -2;
						
					lpBuffer = VirtualAlloc(NULL, sMBI.RegionSize, MEM_RESERVE|MEM_COMMIT,	PAGE_READWRITE);
					if (NULL == lpBuffer) 
				      return -3;
				  stBufferSize = sMBI.RegionSize;
				}
				if (ReadProcessMemory(hProcess, sMBI.BaseAddress, lpBuffer, sMBI.RegionSize, &dwResult))
					pfProcess(hProcess, lpBuffer, sMBI.RegionSize, sMBI.BaseAddress, pvData, uiReadOnly);
	    }
	
	if (NULL != lpBuffer && !VirtualFree(lpBuffer, 0, MEM_RELEASE))
	  return -4;

	CloseHandle(hProcess);
	
	return 0;
}

int ProcessModules(DWORD dwPID, TCHAR *pszModule, void (*pfProcess)(HANDLE, LPVOID, SIZE_T, PVOID, void *, unsigned int), void *pvData, unsigned int uiReadOnly, HMODULE hmModArg)
{
  HANDLE hProcess;
  HMODULE hmMod;
	HMODULE ahmModules[MAXMODULES];
	DWORD dwBytes;
	unsigned int uiIter;
  MODULEINFO sMI;
	LPVOID lpBuffer;
	SIZE_T stBufferSize;
  DWORD dwResult;

  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, dwPID);
  if (NULL == hProcess)
      return -1;

	lpBuffer = NULL;
	stBufferSize = 0;
	if (!_tcscmp(pszModule, "*"))
	{
		if (EnumProcessModules(hProcess, ahmModules, sizeof(ahmModules), &dwBytes))
		{
			qsort(ahmModules, dwBytes/sizeof(HMODULE), sizeof(HMODULE), QSortCompareDWORD);
	    for (uiIter = 0; uiIter < dwBytes/sizeof(HMODULE); uiIter++)
	    	if (GetModuleInformation(hProcess, ahmModules[uiIter], &sMI, sizeof(MODULEINFO)))
    		{
					if (sMI.SizeOfImage > stBufferSize)
					{
						if (NULL != lpBuffer)
							if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
								return -2;
							
						lpBuffer = VirtualAlloc(NULL, sMI.SizeOfImage, MEM_RESERVE|MEM_COMMIT,	PAGE_READWRITE);
						if (NULL == lpBuffer) 
					      return -3;
					  stBufferSize = sMI.SizeOfImage;
					}

					if (ReadProcessMemory(hProcess, sMI.lpBaseOfDll, lpBuffer, sMI.SizeOfImage, &dwResult))
						pfProcess(hProcess, lpBuffer, sMI.SizeOfImage, sMI.lpBaseOfDll, pvData, uiReadOnly);
    		}


	  }
	}
	else
	{
		if (!_tcscmp(pszModule, "."))
			hmMod = hmModArg;
		else
  		hmMod = GetModuleForProcess(dwPID, pszModule);
  	if (NULL != hmMod)
	    if (GetModuleInformation(hProcess, hmMod, &sMI, sizeof(MODULEINFO)))
  		{
				if (sMI.SizeOfImage > stBufferSize)
				{
					if (NULL != lpBuffer)
						if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
							return -2;
						
					lpBuffer = VirtualAlloc(NULL, sMI.SizeOfImage, MEM_RESERVE|MEM_COMMIT,	PAGE_READWRITE);
					if (NULL == lpBuffer) 
				      return -3;
//				  stBufferSize = sMI.SizeOfImage;
				}

				if (ReadProcessMemory(hProcess, sMI.lpBaseOfDll, lpBuffer, sMI.SizeOfImage, &dwResult))
					pfProcess(hProcess, lpBuffer, sMI.SizeOfImage, sMI.lpBaseOfDll, pvData, uiReadOnly);
  		}
	}

	if (NULL != lpBuffer && !VirtualFree(lpBuffer, 0, MEM_RELEASE))
	  return -4;

	CloseHandle(hProcess);
	
	return 0;
}

int GetProcessOwner(DWORD dwPID, char *pszName, char *pszDomain)
{
	HANDLE hProcess;
	HANDLE hProcessToken;
	DWORD dwProcessTokenInfoAllocSize;
	DWORD dwErr;
	PTOKEN_USER sPTU;
	DWORD dwNameSize;
	DWORD dwDomainSize;
	SID_NAME_USE sSNE;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
	dwErr	=	GetLastError();
	if (NULL == hProcess)
		return dwErr;

	if (!OpenProcessToken(hProcess, TOKEN_READ, &hProcessToken))
	{
		dwErr	=	GetLastError();
		CloseHandle(hProcess);
		return dwErr;
	}
	
	GetTokenInformation(hProcessToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);
	if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		sPTU = (PTOKEN_USER) malloc(dwProcessTokenInfoAllocSize);
    if (sPTU != NULL)
    {
			if (GetTokenInformation(hProcessToken, TokenUser, sPTU, dwProcessTokenInfoAllocSize, &dwProcessTokenInfoAllocSize))
			{
				dwNameSize = MAX_PATH;
				dwDomainSize = MAX_PATH;
				if	(LookupAccountSid(NULL, sPTU->User.Sid, pszName, &dwNameSize, pszDomain, &dwDomainSize, &sSNE))
					dwErr = 0;
				else
					dwErr	=	GetLastError();
			}
    }
    free(sPTU);
	}
   	
	CloseHandle(hProcessToken);
	CloseHandle(hProcess);
	return dwErr;
}

// Inject code pbCode in process with process-id dwPID
// Returns true on succes, false on failure
BOOL InjectCode(DWORD dwPID, PBYTE pbCode, long lCodeSize, unsigned int uiMinimumBytesSize, BOOL bExecute)
{
  HANDLE hProcess;
  LPVOID lpRemoteMemory;
  DWORD dwBytes;
  HANDLE hRemoteThread;
  BOOL bRet;
  long lMemorySize;
  
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
  if (NULL == hProcess)
  	return FALSE;
  if (g_uiVerbose)
  	Output("dwPID %u hProcess = %08X\n", dwPID, hProcess);

	lMemorySize = (long)uiMinimumBytesSize < lCodeSize ? lCodeSize : uiMinimumBytesSize;
  lpRemoteMemory = VirtualAllocEx(hProcess, NULL, lMemorySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (NULL == lpRemoteMemory)
  {
  	CloseHandle(hProcess);
  	return FALSE;
  }
  if (g_uiVerbose)
	  Output("lpRemoteMemory = %08X\nlMemorySize = %08X\n", lpRemoteMemory, lMemorySize);

  if (g_uiVerbose)
	  OutputDumpBytes("\t\t", pbCode, lCodeSize, (DWORD)lpRemoteMemory);
  if (0 == WriteProcessMemory(hProcess, lpRemoteMemory, pbCode, lCodeSize, &dwBytes))
  {
	  VirtualFreeEx(hProcess, lpRemoteMemory, lCodeSize, MEM_RELEASE);
	  CloseHandle(hProcess);
  	return FALSE;
  }

	if (bExecute)
	{
	  hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteMemory, NULL, 0, NULL);
  	if (g_uiVerbose)
	  	Output("hRemoteThread = %08X\n", hRemoteThread);

	  if (0 != hRemoteThread)
  		bRet = WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
	  else
  		bRet = FALSE;

  	VirtualFreeEx(hProcess, lpRemoteMemory, lCodeSize, MEM_RELEASE);
  }

  CloseHandle(hProcess);

  return bRet;
}

