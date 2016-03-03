/*
	output functions for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/17: Start development
	2008/06/24: Added OutputFileClose
	2008/10/18: Refactor DumpBytes -> OutputDumpBytes, updated InjectCode
*/

void Output(const char *pszFormat, ...);
void Outputchar(char cIn);
void Outputwchar(wchar_t wcIn);
void OutputDumpBytes(char *szIndent, unsigned char *pucBuffer, int iLen, DWORD dwAddress);
void DisableConsoleOutput(void);
void OutputToFile(char *pszFilenameArg);
void OutputFileClose(void);
