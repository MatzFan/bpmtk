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
	2008/02/20: added GetModuleFromAddress
	2008/02/21: refactoring, new GUIDs, peek & poke
	2008/04/26: code review
	2009/06/06: added exception handling to peek & poke
*/

#include <windows.h>
#include <initguid.h>
#include <activscp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <excpt.h>

#include <stdio.h>

#include "scriptengine.h"

#pragma comment(lib, "psapi.lib")

// GUIDs generated with guidgen.exe
// Our IApp object GUID
const CLSID CLSID_IApp = {0x84450702, 0xf17a, 0x425e, {0x83, 0x80, 0x45, 0xea, 0xa0, 0xd5, 0x88, 0xe4}};

// Our IApp VTable's GUID
const IID IID_IApp = {0x6c3c3617, 0x4ca4, 0x4e67, {0xae, 0xdb, 0xcf, 0x5f, 0xf9, 0xab, 0xa9, 0x60}};

// The name that a script uses to access our application object
#define	MYAPP_OBJECT_NAME L"scriptengine"

IUnknown *getAppObject(void);
HRESULT getAppObjectITypeInfo(ITypeInfo **typeInfo);
void initMyRealIAppObject(void);
void freeMyRealIAppObject(void);

typedef struct
{
	IActiveScriptSite site;
	IActiveScriptSiteWindow siteWnd;
} MyRealIActiveScriptSite;

MyRealIActiveScriptSite MyActiveScriptSite;

static STDMETHODIMP QueryInterface(MyRealIActiveScriptSite *, REFIID, void **);
static STDMETHODIMP_(ULONG) AddRef(MyRealIActiveScriptSite *);
static STDMETHODIMP_(ULONG) Release(MyRealIActiveScriptSite *);
static STDMETHODIMP GetLCID(MyRealIActiveScriptSite *, LCID *);
static STDMETHODIMP GetItemInfo(MyRealIActiveScriptSite *, LPCOLESTR, DWORD, IUnknown **, ITypeInfo **);
static STDMETHODIMP GetDocVersionString(MyRealIActiveScriptSite *, BSTR *);
static STDMETHODIMP OnScriptTerminate(MyRealIActiveScriptSite *, const VARIANT *, const EXCEPINFO *);
static STDMETHODIMP OnStateChange(MyRealIActiveScriptSite *, SCRIPTSTATE);
static STDMETHODIMP OnScriptError(MyRealIActiveScriptSite *, IActiveScriptError *);
static STDMETHODIMP OnEnterScript(MyRealIActiveScriptSite *);
static STDMETHODIMP OnLeaveScript(MyRealIActiveScriptSite *);

#ifdef __BORLANDC__
#pragma warn -8075
#endif

static const IActiveScriptSiteVtbl SiteTable = 
{
	QueryInterface,
	AddRef,
	Release,
	GetLCID,
	GetItemInfo,
	GetDocVersionString,
	OnScriptTerminate,
	OnStateChange,
	OnScriptError,
	OnEnterScript,
	OnLeaveScript
};

#ifdef __BORLANDC__
#pragma warn +8075
#endif

// IActiveScriptSiteWindow VTable
static STDMETHODIMP siteWnd_QueryInterface(IActiveScriptSiteWindow *, REFIID, void **);
static STDMETHODIMP_(ULONG) siteWnd_AddRef(IActiveScriptSiteWindow *);
static STDMETHODIMP_(ULONG) siteWnd_Release(IActiveScriptSiteWindow *);
static STDMETHODIMP GetSiteWindow(IActiveScriptSiteWindow *, HWND *);
static STDMETHODIMP EnableModeless(IActiveScriptSiteWindow *, BOOL);

static const IActiveScriptSiteWindowVtbl SiteWindowTable = 
{
	siteWnd_QueryInterface,
	siteWnd_AddRef,
	siteWnd_Release,
	GetSiteWindow,
	EnableModeless
};

void initIActiveScriptSiteObject(void)
{
	MyActiveScriptSite.site.lpVtbl = (IActiveScriptSiteVtbl *) &SiteTable;
	MyActiveScriptSite.siteWnd.lpVtbl = (IActiveScriptSiteWindowVtbl *) &SiteWindowTable;
}

void ExecuteVBScript(LPOLESTR osScript)
{
	HRESULT hr;
	wchar_t wszBufferGUIDStr[100];
	wchar_t wszBufferGUID[100];
	GUID *guid;
	IActiveScriptParse *activeScriptParse;
	IActiveScript *activeScript;
	
	hr = CoInitialize(0);
	if (hr)
		return;
	
	wcscpy(wszBufferGUIDStr, L"{B54F3741-5B07-11cf-A4B0-00AA004A55E8}");
	if (NOERROR != CLSIDFromString(wszBufferGUIDStr, (GUID *) wszBufferGUID))
		return;
	guid = (GUID *) wszBufferGUID;
		
	initIActiveScriptSiteObject();
	initMyRealIAppObject();
	
	hr = CoCreateInstance(guid, 0, CLSCTX_ALL, &IID_IActiveScript, (void **)&activeScript);
	if (hr)
		return;
		
	hr = activeScript->lpVtbl->QueryInterface(activeScript, &IID_IActiveScriptParse, (void **)&activeScriptParse);
	if (hr)
		return;

	hr = activeScriptParse->lpVtbl->InitNew(activeScriptParse);
	if (hr)
		return;

	hr = activeScript->lpVtbl->SetScriptSite(activeScript, (IActiveScriptSite *)&MyActiveScriptSite);
	if (hr)
		return;

	hr = activeScript->lpVtbl->AddNamedItem(activeScript, MYAPP_OBJECT_NAME, SCRIPTITEM_ISVISIBLE|SCRIPTITEM_NOCODE);
	if (hr)
		return;
	
	hr = activeScriptParse->lpVtbl->ParseScriptText(activeScriptParse, osScript, 0, 0, 0, 0, 0, 0, 0, 0);
	if (hr)
		return;

	hr = activeScript->lpVtbl->SetScriptState(activeScript, SCRIPTSTATE_CONNECTED);
	if (hr)
		return;

	activeScriptParse->lpVtbl->Release(activeScriptParse);
	activeScript->lpVtbl->Close(activeScript);
	activeScript->lpVtbl->Release(activeScript);
	MyActiveScriptSite.site.lpVtbl->Release((IActiveScriptSite *)&MyActiveScriptSite);
	freeMyRealIAppObject();
	CoUninitialize();
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP QueryInterface(MyRealIActiveScriptSite *this, REFIID riid, void **ppv)
{
	if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IActiveScriptSite))
		*ppv = this;
	else if (IsEqualIID(riid, &IID_IActiveScriptSiteWindow))
		*ppv = ((unsigned char *)this + offsetof(MyRealIActiveScriptSite, siteWnd)); 
	else
	{
		*ppv = 0;
		return E_NOINTERFACE;
	}
	AddRef(this);
	return S_OK;
}

static STDMETHODIMP_(ULONG) AddRef(MyRealIActiveScriptSite *this)
{
	return 1;
}

static STDMETHODIMP_(ULONG) Release(MyRealIActiveScriptSite *this)
{
	return 1;
}

// Called when the script engine wants to know what language ID our
// program is using.
static STDMETHODIMP GetLCID(MyRealIActiveScriptSite *this, LCID *psLCID)
{
	*psLCID = LOCALE_USER_DEFAULT;
	return S_OK;
}

// Called by the script engine to get any pointers to our own host-defined
// objects whose functions a script may directly call. We don't implement
// any such objects here, so this is just a stub.
static STDMETHODIMP GetItemInfo(MyRealIActiveScriptSite *this, LPCOLESTR objectName, DWORD dwReturnMask, IUnknown **objPtr, ITypeInfo **typeInfo)
{
	HRESULT hr;

	hr = E_FAIL;
	if (dwReturnMask & SCRIPTINFO_IUNKNOWN)
		*objPtr = 0;
	if (dwReturnMask & SCRIPTINFO_ITYPEINFO)
		*typeInfo = 0;

	if (!lstrcmpiW(objectName, MYAPP_OBJECT_NAME))
	{
		hr = S_OK;

		if (dwReturnMask & SCRIPTINFO_IUNKNOWN)
			*objPtr = getAppObject();

		if (dwReturnMask & SCRIPTINFO_ITYPEINFO)
		{
			hr = getAppObjectITypeInfo(typeInfo);
			if (hr)
				hr = E_FAIL;
		}
	}

	return hr;
}

static STDMETHODIMP GetDocVersionString(MyRealIActiveScriptSite *this, BSTR *version) 
{
	*version = 0;
	
	return S_OK;
}

static STDMETHODIMP OnScriptTerminate(MyRealIActiveScriptSite *this, const VARIANT *pvr, const EXCEPINFO *pei)
{
	return S_OK;
}

static STDMETHODIMP OnStateChange(MyRealIActiveScriptSite *this, SCRIPTSTATE state)
{
	return S_OK;
}

static STDMETHODIMP OnEnterScript(MyRealIActiveScriptSite *this)
{
	return S_OK;
}

static STDMETHODIMP OnLeaveScript(MyRealIActiveScriptSite *this) 
{
	return S_OK;
}

static STDMETHODIMP OnScriptError(MyRealIActiveScriptSite *this, IActiveScriptError *scriptError)
{
	ULONG		lineNumber;
	BSTR		desc;
	EXCEPINFO	ei;
	OLECHAR		wszOutput[1024];

	scriptError->lpVtbl->GetSourcePosition(scriptError, 0, &lineNumber, 0);
	desc = 0;
	scriptError->lpVtbl->GetSourceLineText(scriptError, &desc);
	scriptError->lpVtbl->GetExceptionInfo(scriptError, &ei);
	wsprintfW(&wszOutput[0], L"ScriptEngine error %s - Line %u: %s - %s", ei.bstrSource, lineNumber + 1, ei.bstrDescription, desc ? desc : L"");
	SysFreeString(desc);
	SysFreeString(ei.bstrSource);
	SysFreeString(ei.bstrDescription);
	SysFreeString(ei.bstrHelpFile);
 
	return S_OK;
}

static STDMETHODIMP siteWnd_QueryInterface(IActiveScriptSiteWindow *this, REFIID riid, void **ppv)
{
	this = (IActiveScriptSiteWindow *) ((unsigned char *) this - offsetof(MyRealIActiveScriptSite, siteWnd));
	return QueryInterface((MyRealIActiveScriptSite *)this, riid, ppv);
}

static STDMETHODIMP_(ULONG) siteWnd_AddRef(IActiveScriptSiteWindow *this)
{
	this = (IActiveScriptSiteWindow *) ((unsigned char *) this - offsetof(MyRealIActiveScriptSite, siteWnd));
	return AddRef((MyRealIActiveScriptSite *)this);
}

static STDMETHODIMP_(ULONG) siteWnd_Release(IActiveScriptSiteWindow *this)
{
	this = (IActiveScriptSiteWindow *) ((unsigned char *) this - offsetof(MyRealIActiveScriptSite, siteWnd));
	return Release((MyRealIActiveScriptSite *)this);
}

static STDMETHODIMP GetSiteWindow(IActiveScriptSiteWindow *this, HWND *phwnd)
{
	*phwnd = NULL;
	return S_OK;
}

static STDMETHODIMP EnableModeless(IActiveScriptSiteWindow *this, BOOL enable)
{
	return S_OK;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

OLECHAR *loadUnicodeScript(LPCTSTR fn)
{
	OLECHAR	*script;
	HANDLE hFile;

	script = 0;

	if ((hFile = CreateFile(fn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) != INVALID_HANDLE_VALUE)
	{
		DWORD	filesize;
		char	*psz;

		filesize = GetFileSize(hFile, 0);
		psz = (char *)GlobalAlloc(GMEM_FIXED, filesize + 1);
		if (psz)
 		{
			DWORD	read;

			ReadFile(hFile, psz, filesize, &read, 0);

			script = (OLECHAR *)GlobalAlloc(GMEM_FIXED, (filesize + 1) * sizeof(OLECHAR));
			if (script)
			{
				MultiByteToWideChar(CP_ACP, 0, psz, filesize, script, filesize + 1);
				script[filesize] = 0;
			}

			GlobalFree(psz);
		}

		CloseHandle(hFile);
	}

	return script;
}

HMODULE GetModuleFromAddress(LPVOID lpAddress)
{
	HMODULE ahmModules[1024];
	DWORD dwBytes;
	unsigned int uiIter;
	MODULEINFO sMI;

	if (EnumProcessModules(GetCurrentProcess(), ahmModules, sizeof(ahmModules), &dwBytes))
    for (uiIter = 0; uiIter < dwBytes/sizeof(HMODULE); uiIter++)
    	if (GetModuleInformation(GetCurrentProcess(), ahmModules[uiIter], &sMI, sizeof(MODULEINFO)))
    		if (sMI.lpBaseOfDll <= lpAddress && (BYTE *) lpAddress <= (BYTE *) sMI.lpBaseOfDll + sMI.SizeOfImage)
    			return ahmModules[uiIter];
  
  return NULL;
}

HRESULT getITypeInfoFromExe(const GUID *guid, ITypeInfo **iTypeInfo) 
{
	wchar_t				fileName[MAX_PATH];
	ITypeLib			*typeLib;
	HRESULT	hr;

	*iTypeInfo = 0;

	GetModuleFileNameW(GetModuleFromAddress(&getITypeInfoFromExe), &fileName[0], MAX_PATH);
	if (!(hr = LoadTypeLib(&fileName[0], &typeLib)))
	{
		hr = typeLib->lpVtbl->GetTypeInfoOfGuid(typeLib, guid, iTypeInfo);

		typeLib->lpVtbl->Release(typeLib);
	}

	return hr;
}

#undef  INTERFACE
#define INTERFACE IApp
DECLARE_INTERFACE_ (INTERFACE, IDispatch)
{
	// IUnknown functions
	STDMETHOD  (QueryInterface)		(THIS_ REFIID, void **) PURE;
	STDMETHOD_ (ULONG, AddRef)		(THIS) PURE;
	STDMETHOD_ (ULONG, Release)		(THIS) PURE;
	// IDispatch functions
	STDMETHOD_ (ULONG, GetTypeInfoCount)(THIS_ UINT *) PURE;
	STDMETHOD_ (ULONG, GetTypeInfo)		(THIS_ UINT, LCID, ITypeInfo **) PURE;
	STDMETHOD_ (ULONG, GetIDsOfNames)	(THIS_ REFIID, LPOLESTR *, UINT, LCID, DISPID *) PURE;
	STDMETHOD_ (ULONG, Invoke)			(THIS_ DISPID, REFIID, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *) PURE;
	// Extra functions
	STDMETHOD  (Output)		(THIS_ BSTR) PURE;
	STDMETHOD	 (Peek)     (THIS_ long, VARIANT *) PURE;
	STDMETHOD	 (Poke)     (THIS_ long, BYTE) PURE;
	STDMETHOD	 (Suspend)     (THIS_ long) PURE;
	STDMETHOD	 (Resume)     (THIS_ long) PURE;
};

typedef struct {
	IApp						iApp;			// NOTE: Our IApp must be the base object.
	IProvideMultipleClassInfo	classInfo;		// Our IProvideMultipleClassInfo sub-object
} MyRealIApp;

static STDMETHODIMP QueryInterface_CInfo(IProvideMultipleClassInfo *, REFIID, void **);
static STDMETHODIMP_(ULONG) AddRef_CInfo(IProvideMultipleClassInfo *);
static STDMETHODIMP_(ULONG) Release_CInfo(IProvideMultipleClassInfo *);
static STDMETHODIMP GetClassInfo_CInfo(IProvideMultipleClassInfo *, ITypeInfo **);
static STDMETHODIMP GetGUID_CInfo(IProvideMultipleClassInfo *, DWORD, GUID *);
static STDMETHODIMP GetMultiTypeInfoCount_CInfo(IProvideMultipleClassInfo *, ULONG *);
static STDMETHODIMP GetInfoOfIndex_CInfo(IProvideMultipleClassInfo *, ULONG, DWORD, ITypeInfo **, DWORD *, ULONG *, GUID *, GUID *);

static const IProvideMultipleClassInfoVtbl IProvideMultipleClassInfoTable = {
	QueryInterface_CInfo,
	AddRef_CInfo,
	Release_CInfo,
	GetClassInfo_CInfo,
	GetGUID_CInfo,
	GetMultiTypeInfoCount_CInfo,
	GetInfoOfIndex_CInfo};

static STDMETHODIMP QueryInterface_App(MyRealIApp *, REFIID, void **);
static STDMETHODIMP_(ULONG) AddRef_App(MyRealIApp *);
static STDMETHODIMP_(ULONG) Release_App(MyRealIApp *);
static STDMETHODIMP GetTypeInfoCount(MyRealIApp *, UINT *);
static STDMETHODIMP GetTypeInfo(MyRealIApp *, UINT , LCID , ITypeInfo **);
static STDMETHODIMP GetIDsOfNames(MyRealIApp *, REFIID, OLECHAR **, UINT, LCID, DISPID *);
static STDMETHODIMP Invoke(MyRealIApp *, DISPID, REFIID, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
static STDMETHODIMP Output(MyRealIApp *, BSTR);
static STDMETHODIMP Peek(MyRealIApp *, long, VARIANT *);
static STDMETHODIMP Poke(MyRealIApp *, long, BYTE);
static STDMETHODIMP Suspend(MyRealIApp *);
static STDMETHODIMP Resume(MyRealIApp *);

#ifdef __BORLANDC__
#pragma warn -8075
#endif

static const IAppVtbl IAppTable = {
	QueryInterface_App,
	AddRef_App,
	Release_App,
	GetTypeInfoCount,
	GetTypeInfo,
	GetIDsOfNames,
	Invoke,
	Output,
	Peek,
	Poke,
	Suspend,
	Resume};

#ifdef __BORLANDC__
#pragma warn +8075
#endif

static MyRealIApp				MyIApp;

static ITypeInfo				*IAppObjectTypeInfo;

static ITypeInfo				*IAppVTableTypeInfo;

HRESULT getAppObjectITypeInfo(ITypeInfo **typeInfo)
{
	HRESULT	hr;

	hr = S_OK;

	if (!IAppObjectTypeInfo)
	{
		hr = getITypeInfoFromExe(&CLSID_IApp, &IAppObjectTypeInfo);
		if (hr)
			return hr;

		IAppObjectTypeInfo->lpVtbl->AddRef(IAppObjectTypeInfo);
	}

	*typeInfo = IAppObjectTypeInfo;

	return hr;
}

IUnknown * getAppObject(void)
{
	return (IUnknown *) &MyIApp;
}

void initMyRealIAppObject(void)
{
	MyIApp.iApp.lpVtbl = (IAppVtbl *)&IAppTable;
	MyIApp.classInfo.lpVtbl = (IProvideMultipleClassInfoVtbl *)&IProvideMultipleClassInfoTable;
	IAppObjectTypeInfo = IAppVTableTypeInfo = 0;
}

void freeMyRealIAppObject(void)
{
	if (IAppVTableTypeInfo) IAppVTableTypeInfo->lpVtbl->Release(IAppVTableTypeInfo);
	if (IAppObjectTypeInfo) IAppObjectTypeInfo->lpVtbl->Release(IAppObjectTypeInfo);
}

static STDMETHODIMP QueryInterface_App(MyRealIApp *this, REFIID vTableGuid, void **ppv) 
{
	if (IsEqualIID(vTableGuid, &IID_IUnknown) || IsEqualIID(vTableGuid, &IID_IDispatch))
		*ppv = this;
	else if (IsEqualIID(vTableGuid, &IID_IProvideMultipleClassInfo) || IsEqualIID(vTableGuid, &IID_IProvideClassInfo2) || IsEqualIID(vTableGuid, &IID_IProvideClassInfo))
		*ppv = ((char *)this + offsetof(MyRealIApp, classInfo));
	else
	{
		*ppv = 0;
		return E_NOINTERFACE;
	}
 
	return S_OK;
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP_(ULONG) AddRef_App(MyRealIApp *this)
{
	return 1;
}
 
#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP_(ULONG) Release_App(MyRealIApp *this)
{
	return 1;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetTypeInfoCount(MyRealIApp *this, UINT *pctinfo)
{
	*pctinfo = 1;
	return S_OK;
}
 
#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetTypeInfo(MyRealIApp *this, UINT ctinfo, LCID lcid, ITypeInfo **typeInfo)
{
	HRESULT	hr;

	if (!IAppVTableTypeInfo)
	{
		hr = getITypeInfoFromExe(&IID_IApp, &IAppVTableTypeInfo);
		if (hr)
			return hr;
	}

	*typeInfo = IAppVTableTypeInfo;

	IAppVTableTypeInfo->lpVtbl->AddRef(IAppVTableTypeInfo);

	return S_OK;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetIDsOfNames(MyRealIApp *this, REFIID riid, OLECHAR **rgszNames, UINT cNames, LCID lcid, DISPID *rgdispid)
{
	HRESULT	hr;

	if (!IAppVTableTypeInfo)
	{
		hr = getITypeInfoFromExe(&IID_IApp, &IAppVTableTypeInfo);
		if (hr)
			return hr;
	}

	return IAppVTableTypeInfo->lpVtbl->GetIDsOfNames(IAppVTableTypeInfo, rgszNames, cNames, rgdispid);
}
 
#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP Invoke(MyRealIApp *this, DISPID id, REFIID riid, LCID lcid, WORD flag, DISPPARAMS *params, VARIANT *ret, EXCEPINFO *pei, UINT *pu)
{
	HRESULT	hr;

	if (!IAppVTableTypeInfo)
	{
		hr = getITypeInfoFromExe(&IID_IApp, &IAppVTableTypeInfo);
		if (hr)
			return hr;
	}

	return IAppVTableTypeInfo->lpVtbl->Invoke(IAppVTableTypeInfo, this, id, flag, params, ret, pei, pu);
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP Output(MyRealIApp *this, BSTR bstr)
{
	WCHAR	*ptr;
	
	ptr = bstr;
	if (ptr)
	{
		ptr = GlobalAlloc(GMEM_FIXED, SysStringByteLen(bstr) + sizeof(WCHAR));
		if (!ptr)
			return E_OUTOFMEMORY;
		lstrcpyW(ptr, bstr);
	}
	OutputDebugStringW(ptr);
	return S_OK;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

static STDMETHODIMP QueryInterface_CInfo(IProvideMultipleClassInfo *this, REFIID vTableGuid, void **ppv)
{
	return QueryInterface_App((MyRealIApp *)((char *)this - offsetof(MyRealIApp, classInfo)), vTableGuid, ppv);
}

static STDMETHODIMP_(ULONG) AddRef_CInfo(IProvideMultipleClassInfo *this)
{
	return AddRef_App((MyRealIApp *)((char *)this - offsetof(MyRealIApp, classInfo)));
}

static STDMETHODIMP_(ULONG) Release_CInfo(IProvideMultipleClassInfo *this)
{
	return Release_App((MyRealIApp *)((char *)this - offsetof(MyRealIApp, classInfo)));
}

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetClassInfo_CInfo(IProvideMultipleClassInfo *this, ITypeInfo **classITypeInfo)
{
	HRESULT	hr;

	if (!(hr = getAppObjectITypeInfo(classITypeInfo)))
		(*classITypeInfo)->lpVtbl->AddRef(*classITypeInfo);

	return hr;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetGUID_CInfo(IProvideMultipleClassInfo *this, DWORD guidType, GUID *guid)
{
	if (guidType == GUIDKIND_DEFAULT_SOURCE_DISP_IID)
		return E_NOTIMPL;
	return E_INVALIDARG;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetMultiTypeInfoCount_CInfo(IProvideMultipleClassInfo *this, ULONG *count)
{
	*count = 1;
	return S_OK;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP GetInfoOfIndex_CInfo(IProvideMultipleClassInfo *this, ULONG objNum, DWORD flags,
								   ITypeInfo **classITypeInfo, DWORD *retFlags, ULONG *reservedIds,
								   GUID *defVTableGuid, GUID *defSrcVTableGuid)
{
	HRESULT	hr;

	hr = S_OK;

	*retFlags = 0;

	if (flags & MULTICLASSINFO_GETNUMRESERVEDDISPIDS)
	{
		*reservedIds = 2;		// Set this to the highest DISPID our [default] VTable uses
		*retFlags = MULTICLASSINFO_GETNUMRESERVEDDISPIDS;
	}

	if (flags & MULTICLASSINFO_GETIIDPRIMARY)
	{
		CopyMemory(defVTableGuid, &IID_IApp, sizeof(GUID));
		*retFlags |= MULTICLASSINFO_GETIIDPRIMARY;
	}

	if (flags & MULTICLASSINFO_GETTYPEINFO)
	{
		hr = getAppObjectITypeInfo(classITypeInfo);
		if (hr)
			return hr;

		(*classITypeInfo)->lpVtbl->AddRef(*classITypeInfo);

		*retFlags |= MULTICLASSINFO_GETTYPEINFO;
	}

	return hr;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

STDMETHODIMP Peek(MyRealIApp *this, long lIndex, VARIANT *ret)
{
	VARIANTARG V1;
	BYTE *pbAddress;

	pbAddress = (BYTE *) lIndex;
	V_VT(&V1) = VT_I2;
	__try
	{
		V_I2(&V1) = *pbAddress;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		V_I2(&V1) = -1;
	}
	
	return VariantCopy(ret, &V1);
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

STDMETHODIMP Poke(MyRealIApp *this, long lIndex, BYTE bIn)
{
	BYTE *pbAddress;

	pbAddress = (BYTE *) lIndex;
	__try
	{
		*pbAddress = bIn;
	}	
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	
	return S_OK;	
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

void SuspendResumeThreadsExceptMe(BOOL bSuspend) 
{ 
	HANDLE hThreadSnap; 
	THREADENTRY32 sTE32 = {0}; 
	BOOL bLoop;
	char szTemp[256];
 
  hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
  if (INVALID_HANDLE_VALUE == hThreadSnap) 
      return; 

  sTE32.dwSize = sizeof(sTE32); 

  for (bLoop = Thread32First(hThreadSnap, &sTE32); bLoop; bLoop = Thread32Next(hThreadSnap, &sTE32))
	  if (sTE32.th32OwnerProcessID == GetCurrentProcessId() && sTE32.th32ThreadID != GetCurrentThreadId())
	  {
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, sTE32.th32ThreadID);
			if (hThread != NULL)
			{
				snprintf(szTemp, sizeof(szTemp), "sTE32.th32OwnerProcessID = %d GetCurrentProcessId() = %d sTE32.th32ThreadID = %d GetCurrentThreadId() = %d", sTE32.th32OwnerProcessID, GetCurrentProcessId(), sTE32.th32ThreadID, GetCurrentThreadId());
				OutputDebugString(szTemp);

				if (bSuspend)
					SuspendThread(hThread);
				else
					ResumeThread(hThread);

				CloseHandle(hThread);
			}
	  } 

  CloseHandle(hThreadSnap); 

  return; 
} 

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP Suspend(MyRealIApp *this)
{
	SuspendResumeThreadsExceptMe(TRUE);
	
	return S_OK;	
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

#ifdef __BORLANDC__
#pragma warn -8057
#endif

static STDMETHODIMP Resume(MyRealIApp *this)
{
	SuspendResumeThreadsExceptMe(FALSE);
	
	return S_OK;	
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
