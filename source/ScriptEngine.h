/*
	When injected inside a process, this DLL will execute a VBScript
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/13: Start development
	2008/02/14: Refactoring
*/

#include <activscp.h>

void ExecuteVBScript(LPOLESTR fn);
OLECHAR *loadUnicodeScript(LPCTSTR fn);