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


HRESULT PatchIAT(HMODULE hmMod, PSTR psImportedModuleName, PSTR psImportedProcName, PVOID pvHookingProc, PVOID *ppvOriginalProc);
HRESULT DumpIATs(HMODULE hmMod);
HRESULT PatchDIAT(HMODULE hmMod, PSTR psImportedModuleName, PSTR psImportedProcName, PVOID pvHookingProc, PVOID *ppvOriginalProc);
