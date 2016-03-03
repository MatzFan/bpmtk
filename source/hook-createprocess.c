/*
	Test code for hooking programs to disable CreateProcess
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2009/09/30: start
	2009/10/03: NtCreateUserProcess
	2009/10/04: Added Dummy export
	2009/11/04: Added hook-createprocess.res
*/

#include <stdio.h>
#include <tchar.h>
#include <windows.h>

#include "iat.h"
#include "psutils.h"

#ifdef INCLUDE_RESOURCE
#pragma resource "hook-createprocess.res"
#endif

BOOL g_bHookNtCreateProcessExInstalled;
BOOL g_bHookNtCreateProcessInstalled;
BOOL g_bHookNtCreateUserProcessInstalled;

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

//NTSYSAPI NTSTATUS NTAPI NtCreateProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ParentProcess, IN BOOLEAN InheritObjectTable, IN HANDLE SectionHandle OPTIONAL, IN HANDLE DebugPort OPTIONAL, IN HANDLE ExceptionPort OPTIONAL );
NTSTATUS NTAPI (*OriginalNtCreateProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);

#ifdef __BORLANDC__
#pragma warn -8057
#endif

NTSTATUS NTAPI HookOriginalNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	char szDebug[1024];
	
	snprintf(szDebug, 1023, "Blocking call to NtCreateProcess (ProcessHandle = %08X)", ProcessHandle);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
	//return (*OriginalNtCreateProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort);
	return -1l;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

//NTSYSAPI NTSTATUS NTAPI HookNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE Unknown);
NTSTATUS NTAPI (*OriginalNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, DWORD InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE Unknown);

#ifdef __BORLANDC__
#pragma warn -8057
#endif

NTSTATUS NTAPI HookOriginalNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, DWORD InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE Unknown)
{
	char szDebug[1024];
	
	snprintf(szDebug, 1023, "Blocking call to NtCreateProcessEx (ProcessHandle = %08X)", ProcessHandle);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
//	wcstombs(szDebug, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
//	OutputDebugString(szDebug);
//	return (*OriginalNtCreateProcessEx)(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort, Unknown);
	return -1l;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif


typedef PVOID PRTL_USER_PROCESS_PARAMETERS;

//NTSTATUS NTAPI NtCreateUserProcess(PHANDLE ProcessHandle, ULONG_PTR Parameter1, ULONG_PTR Parameter2, ULONG_PTR Parameter3, ULONG_PTR ProcessSecurityDescriptor, ULONG_PTR ThreadSecurityDescriptor, ULONG_PTR Parameter6, ULONG_PTR Parameter7, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, ULONG_PTR Parameter9, ULONG_PTR Parameter10);
NTSTATUS NTAPI (*OriginalNtCreateUserProcess)(PHANDLE ProcessHandle, ULONG_PTR Parameter1, ULONG_PTR Parameter2, ULONG_PTR Parameter3, ULONG_PTR ProcessSecurityDescriptor, ULONG_PTR ThreadSecurityDescriptor, ULONG_PTR Parameter6, ULONG_PTR Parameter7, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, ULONG_PTR Parameter9, ULONG_PTR Parameter10);

#ifdef __BORLANDC__
#pragma warn -8057
#endif

NTSTATUS NTAPI HookOriginalNtCreateUserProcess(PHANDLE ProcessHandle, ULONG_PTR Parameter1, ULONG_PTR Parameter2, ULONG_PTR Parameter3, ULONG_PTR ProcessSecurityDescriptor, ULONG_PTR ThreadSecurityDescriptor, ULONG_PTR Parameter6, ULONG_PTR Parameter7, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, ULONG_PTR Parameter9, ULONG_PTR Parameter10)
{
	char szDebug[1024];
	
	snprintf(szDebug, 1023, "Blocking call to NtCreateUserProcess (ProcessHandle = %08X)", ProcessHandle);
	szDebug[1023] = '\0';
	OutputDebugString(szDebug);
//	return (*OriginalNtCreateUserProcess)(ProcessHandle, Parameter1, Parameter2, Parameter3, ProcessSecurityDescriptor, ThreadSecurityDescriptor, Parameter6, Parameter7, ProcessParameters, Parameter9, Parameter10);
	return -1l;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

__declspec(dllexport) void Dummy(void)
{
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
  switch(fdwReason)
  {
    case DLL_PROCESS_ATTACH:
			OutputDebugString(_TEXT("Hook-createprocess.dll DLL_PROCESS_ATTACH"));
			
      if (FALSE == g_bHookNtCreateProcessExInstalled)
      {
				if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateProcessEx", (PVOID) HookOriginalNtCreateProcessEx, (PVOID *) &OriginalNtCreateProcessEx))
					g_bHookNtCreateProcessExInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking NtCreateProcessEx failed."));
      }

      if (FALSE == g_bHookNtCreateProcessInstalled)
      {
				if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateProcess", (PVOID) HookOriginalNtCreateProcess, (PVOID *) &OriginalNtCreateProcess))
					g_bHookNtCreateProcessInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking NtCreateProcess failed."));
      }

      if (FALSE == g_bHookNtCreateUserProcessInstalled)
      {
				if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateUserProcess", (PVOID) HookOriginalNtCreateUserProcess, (PVOID *) &OriginalNtCreateUserProcess))
					g_bHookNtCreateUserProcessInstalled = TRUE;
				else
					OutputDebugString(_TEXT("Hooking NtCreateUserProcess failed."));
      }

    	break;

	  case DLL_THREAD_ATTACH:
      break;
	
	  case DLL_THREAD_DETACH:
      break;
	
	  case DLL_PROCESS_DETACH:
		  OutputDebugString(_TEXT("Hook-createprocess.dll DLL_PROCESS_DETACH"));

	  	if (TRUE == g_bHookNtCreateProcessExInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateProcessEx", (PVOID) OriginalNtCreateProcessEx, NULL))
					g_bHookNtCreateProcessExInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking NtCreateProcessEx failed."));
			}
			
	  	if (TRUE == g_bHookNtCreateProcessInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateProcess", (PVOID) OriginalNtCreateProcess, NULL))
					g_bHookNtCreateProcessInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking NtCreateProcess failed."));
			}
			
	  	if (TRUE == g_bHookNtCreateUserProcessInstalled)
	  	{
		  	if (S_OK == PatchIAT(GetModuleForProcess(GetCurrentProcessId(), "kernel32.dll"), "ntdll.dll", "NtCreateUserProcess", (PVOID) OriginalNtCreateUserProcess, NULL))
					g_bHookNtCreateUserProcessInstalled = FALSE;
				else
		  		OutputDebugString(_TEXT("Unhooking NtCreateUserProcess failed."));
			}
			
      break;
  }
  
  return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
   
