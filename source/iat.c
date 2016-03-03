/*
	IAT functions
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/01/21: Start development
	2008/01/23: Project restructering
	2008/01/24: add DumpIAT
	2008/01/28: rename PatchIat -> PatchIAT, DumpIat -> DumpIATs; added PatchDIAT
*/


/*
delayed IAT
http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v8.doc
http://www.codeguru.com/cpp/w-p/win32/security/article.php/c12253/
http://www.codeguru.com/cpp/w-p/win32/security/article.php/c11393__1/
			
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "iat.h"

#define RVA2PTR(base, rva) (((PBYTE) base) + rva)

#define MAX_STRING 256

//http://jpassing.wordpress.com/2008/01/06/using-import-address-table-hooking-for-testing/
/*++
  Routine Description:
    Replace the function pointer in a module's IAT.

  Parameters:
    hmMod              - Module to use IAT from.
    psImportedModuleName  - Name of imported DLL from which
                          function is imported.
    psImportedProcName    - Name of imported function.
    pvHookingProc       - Function to be written to IAT.
    ppvOriginalProc             - Original function.

  Return Value:
    S_OK on success.
    (any HRESULT) on failure.
--*/
HRESULT PatchIAT(HMODULE hmMod, PSTR psImportedModuleName, PSTR psImportedProcName, PVOID pvHookingProc, PVOID *ppvOriginalProc)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
  UINT uiIter;	

	TCHAR szBuffer[MAX_STRING];
	
	pDOSHeader = (PIMAGE_DOS_HEADER) hmMod;
	pNTHeader = (PIMAGE_NT_HEADERS) RVA2PTR(pDOSHeader, pDOSHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pNTHeader->Signature)
    return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) RVA2PTR(pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Iterate over import descriptors/DLLs.
	for (uiIter = 0; pImportDescriptor[uiIter].Characteristics != 0; uiIter++)
	{
    PIMAGE_THUNK_DATA pFirstThunkIter;
    PIMAGE_THUNK_DATA pOriginalFirstThunkIter;
	  PSTR psDLLName;
	  PIMAGE_IMPORT_BY_NAME pImportByName;
	  
	  psDLLName = (PSTR) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].Name);
	  if (!strcmpi(psDLLName, psImportedModuleName))
	  {
	    if (!pImportDescriptor[uiIter].FirstThunk || !pImportDescriptor[uiIter].OriginalFirstThunk)
	      return E_INVALIDARG;
	      
			pFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].FirstThunk);
	  	pOriginalFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].OriginalFirstThunk);
	
	    for (; pOriginalFirstThunkIter->u1.Function != NULL; pOriginalFirstThunkIter++, pFirstThunkIter++)
	    {
	      if (pOriginalFirstThunkIter->u1.Ordinal & IMAGE_ORDINAL_FLAG) // Ordinal import - we can handle named imports only, so skip it.
	        continue;
	
	      pImportByName = (PIMAGE_IMPORT_BY_NAME) RVA2PTR(pDOSHeader, pOriginalFirstThunkIter->u1.AddressOfData);
			  if (!strcmpi(pImportByName->Name, psImportedProcName))
			  {
          DWORD dwDummy;
          MEMORY_BASIC_INFORMATION memInfoThunk;

					_sntprintf(szBuffer, MAX_STRING, _TEXT("%s %s (%08X) %08X -> %08X"), psDLLName, pImportByName->Name, &(pFirstThunkIter->u1.Function), pFirstThunkIter->u1.Function, pvHookingProc);
					OutputDebugString(szBuffer);

          // Make page writable.
          VirtualQuery(pFirstThunkIter, &memInfoThunk, sizeof(MEMORY_BASIC_INFORMATION));
          if (!VirtualProtect(memInfoThunk.BaseAddress, memInfoThunk.RegionSize, PAGE_READWRITE, &memInfoThunk.Protect))
            return HRESULT_FROM_WIN32(GetLastError());

          // Replace function pointers (non-atomically).
          if (ppvOriginalProc)
            *ppvOriginalProc = (PVOID) (DWORD_PTR) pFirstThunkIter->u1.Function;
          pFirstThunkIter->u1.Function = (DWORD) (DWORD_PTR) pvHookingProc;

          // Restore page protection.
          if (!VirtualProtect(memInfoThunk.BaseAddress, memInfoThunk.RegionSize, memInfoThunk.Protect, &dwDummy))
            return HRESULT_FROM_WIN32(GetLastError());

          return S_OK;					
			  }
	    }
	    return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	  }
  }
  return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR
{
	DWORD grAttrs;
	DWORD szName;
	DWORD phMod;
	DWORD pIAT;
	DWORD pINT;
	DWORD PBountIAT;
	DWORD pUnloadIAT;
	DWORD dwTimeStamp;
} IMAGE_DELAY_IMPORT_DESCRIPTOR;
typedef IMAGE_DELAY_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_DELAY_IMPORT_DESCRIPTOR;

HRESULT DumpIATs(HMODULE hmMod)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
  UINT uiIter;
  PIMAGE_DELAY_IMPORT_DESCRIPTOR pDelayImportDescriptor;

	TCHAR szBuffer[MAX_STRING];
	
	pDOSHeader = (PIMAGE_DOS_HEADER) hmMod;
	pNTHeader = (PIMAGE_NT_HEADERS) RVA2PTR(pDOSHeader, pDOSHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pNTHeader->Signature)
    return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) RVA2PTR(pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	OutputDebugString("Import Table");

	// Iterate over import descriptors/DLLs.
	for (uiIter = 0; pImportDescriptor[uiIter].Characteristics != 0; uiIter++)
	{
    PIMAGE_THUNK_DATA pFirstThunkIter;
    PIMAGE_THUNK_DATA pOriginalFirstThunkIter;
	  PSTR psDLLName;
	  PIMAGE_IMPORT_BY_NAME pImportByName;
	  
	  psDLLName = (PSTR) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].Name);
	  OutputDebugString(psDLLName);
    if (!pImportDescriptor[uiIter].FirstThunk || !pImportDescriptor[uiIter].OriginalFirstThunk)
      return E_INVALIDARG;
      
		pFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].FirstThunk);
  	pOriginalFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pImportDescriptor[uiIter].OriginalFirstThunk);

    for (; pOriginalFirstThunkIter->u1.Function != NULL; pOriginalFirstThunkIter++, pFirstThunkIter++)
    {
      if (pOriginalFirstThunkIter->u1.Ordinal & IMAGE_ORDINAL_FLAG) // Ordinal import - we can handle named imports only, so skip it.
        continue;

      pImportByName = (PIMAGE_IMPORT_BY_NAME) RVA2PTR(pDOSHeader, pOriginalFirstThunkIter->u1.AddressOfData);
			snprintf(szBuffer, MAX_STRING, "%s %s (%08X) %08X", psDLLName, pImportByName->Name, &(pFirstThunkIter->u1.Function), pFirstThunkIter->u1.Function);
			OutputDebugString(szBuffer);
    }
  }
	  
	OutputDebugString("Delay-Load Import Table");
	
	pDelayImportDescriptor = (struct _IMAGE_DELAY_IMPORT_DESCRIPTOR *) RVA2PTR(pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
	// Iterate over import descriptors/DLLs.
	for (uiIter = 0; pDelayImportDescriptor[uiIter].grAttrs != 0; uiIter++)
	{
    PIMAGE_THUNK_DATA pFirstThunkIter;
    PIMAGE_THUNK_DATA pOriginalFirstThunkIter;
	  PSTR psDLLName;
	  PIMAGE_IMPORT_BY_NAME pImportByName;

	  psDLLName = (PSTR) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].szName);
	  OutputDebugString(psDLLName);
    if (!pDelayImportDescriptor[uiIter].pIAT || !pDelayImportDescriptor[uiIter].pINT)
      return E_INVALIDARG;

		pFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].pIAT);
  	pOriginalFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].pINT);

    for (; pOriginalFirstThunkIter->u1.Function != NULL; pOriginalFirstThunkIter++, pFirstThunkIter++)
    {
      if (pOriginalFirstThunkIter->u1.Ordinal & IMAGE_ORDINAL_FLAG) // Ordinal import - we can handle named imports only, so skip it.
        continue;

      pImportByName = (PIMAGE_IMPORT_BY_NAME) RVA2PTR(pDOSHeader, pOriginalFirstThunkIter->u1.AddressOfData);
			snprintf(szBuffer, MAX_STRING, "%s %s (%08X) %08X", psDLLName, pImportByName->Name, &(pFirstThunkIter->u1.Function), pFirstThunkIter->u1.Function);
			OutputDebugString(szBuffer);
    }
  }

  return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

HRESULT PatchDIAT(HMODULE hmMod, PSTR psImportedModuleName, PSTR psImportedProcName, PVOID pvHookingProc, PVOID *ppvOriginalProc)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeader;
  PIMAGE_DELAY_IMPORT_DESCRIPTOR pDelayImportDescriptor;
  UINT uiIter;	

	TCHAR szBuffer[MAX_STRING];
	
	pDOSHeader = (PIMAGE_DOS_HEADER) hmMod;
	pNTHeader = (PIMAGE_NT_HEADERS) RVA2PTR(pDOSHeader, pDOSHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pNTHeader->Signature)
    return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
	pDelayImportDescriptor = (struct _IMAGE_DELAY_IMPORT_DESCRIPTOR *) RVA2PTR(pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

	// Iterate over import descriptors/DLLs.
	for (uiIter = 0; pDelayImportDescriptor[uiIter].grAttrs != 0; uiIter++)
	{
    PIMAGE_THUNK_DATA pFirstThunkIter;
    PIMAGE_THUNK_DATA pOriginalFirstThunkIter;
	  PSTR psDLLName;
	  PIMAGE_IMPORT_BY_NAME pImportByName;
	  
	  psDLLName = (PSTR) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].szName);
	  if (!strcmpi(psDLLName, psImportedModuleName))
	  {
	    if (!pDelayImportDescriptor[uiIter].pIAT || !pDelayImportDescriptor[uiIter].pINT)
	      return E_INVALIDARG;
	      
			pFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].pIAT);
	  	pOriginalFirstThunkIter = (PIMAGE_THUNK_DATA) RVA2PTR(pDOSHeader, pDelayImportDescriptor[uiIter].pINT);
	
	    for (; pOriginalFirstThunkIter->u1.Function != NULL; pOriginalFirstThunkIter++, pFirstThunkIter++)
	    {
	      if (pOriginalFirstThunkIter->u1.Ordinal & IMAGE_ORDINAL_FLAG) // Ordinal import - we can handle named imports only, so skip it.
	        continue;
	
	      pImportByName = (PIMAGE_IMPORT_BY_NAME) RVA2PTR(pDOSHeader, pOriginalFirstThunkIter->u1.AddressOfData);
			  if (!strcmpi(pImportByName->Name, psImportedProcName))
			  {
          DWORD dwDummy;
          MEMORY_BASIC_INFORMATION memInfoThunk;

					_sntprintf(szBuffer, MAX_STRING, _TEXT("%s %s (%08X) %08X -> %08X"), psDLLName, pImportByName->Name, &(pFirstThunkIter->u1.Function), pFirstThunkIter->u1.Function, pvHookingProc);
					OutputDebugString(szBuffer);

          // Make page writable.
          VirtualQuery(pFirstThunkIter, &memInfoThunk, sizeof(MEMORY_BASIC_INFORMATION));
          if (!VirtualProtect(memInfoThunk.BaseAddress, memInfoThunk.RegionSize, PAGE_READWRITE, &memInfoThunk.Protect))
            return HRESULT_FROM_WIN32(GetLastError());

          // Replace function pointers (non-atomically).
          if (ppvOriginalProc)
            *ppvOriginalProc = (PVOID) (DWORD_PTR) pFirstThunkIter->u1.Function;
          pFirstThunkIter->u1.Function = (DWORD) (DWORD_PTR) pvHookingProc;

          // Restore page protection.
          if (!VirtualProtect(memInfoThunk.BaseAddress, memInfoThunk.RegionSize, memInfoThunk.Protect, &dwDummy))
            return HRESULT_FROM_WIN32(GetLastError());

          return S_OK;					
			  }
	    }
	    return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	  }
  }
  return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

