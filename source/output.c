/*
	output functions for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/17: Start development
	2008/06/24: Added OutputFileClose
	2008/10/18: Refactor DumpBytes -> OutputDumpBytes
*/

#include <stdio.h>
#include <stdarg.h>
#include <windows.h>

#define BYTES_PER_DUMP_LINE 8

static int iDisableOutput;
static char *pszFilename;
static FILE *fOut;
char szFilename[256];

void Output(const char *pszFormat, ...)
{
	va_list ap;
	
	va_start(ap, pszFormat);
	if (!iDisableOutput)
		vprintf(pszFormat, ap);
	if (fOut)
		vfprintf(fOut, pszFormat, ap);
	va_end(ap);
}

void Outputchar(const char cIn)
{
	if (!iDisableOutput)
		putchar(cIn);
	if (fOut)
		fputc(cIn, fOut);
}

void Outputwchar(const wchar_t wcIn)
{
	if (!iDisableOutput)
		putwchar(wcIn);
	if (fOut)
		fputwc(wcIn, fOut);
}

void OutputDumpBytes(char *szIndent, unsigned char *pucBuffer, int iLen, DWORD dwAddress)
{
  int iIter;
  int iCntCharactersPerLine;
  char szPrintable[256];

	iCntCharactersPerLine = 0;
	for (iIter=0; iIter<iLen; iIter++)
	{
		if (!iCntCharactersPerLine)
		{
			Output("%s%08X:", szIndent, dwAddress+iIter);
			strcpy(szPrintable, "");
		}
		Output(" %02X", pucBuffer[iIter]);
		szPrintable[iCntCharactersPerLine] = isprint(pucBuffer[iIter]) ? pucBuffer[iIter] : '.';
		szPrintable[++iCntCharactersPerLine] = '\0';
		if (BYTES_PER_DUMP_LINE == iCntCharactersPerLine)
		{
			Output(" %s\n", szPrintable);
			iCntCharactersPerLine = 0;
		}
	}
	if (iCntCharactersPerLine > 0)
	{
		for (iIter=iCntCharactersPerLine; iIter<BYTES_PER_DUMP_LINE; iIter++)
			Output("   ");
		Output(" %s\n", szPrintable);
	}
}

void DisableConsoleOutput(void)
{
	iDisableOutput = 1;
}

void OutputToFile(char *pszFilenameArg)
{
	SYSTEMTIME sST;
	
	pszFilename = pszFilenameArg;
	if (NULL == pszFilename)
		return;
	if (!strcmp(pszFilename, ""))
	{
		GetLocalTime(&sST);
		snprintf(szFilename, sizeof(szFilename)-1, "bpmtk-%d%02d%02d-%02d%02d%02d.txt", sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);
		pszFilename = szFilename;
	}
	fOut = fopen(pszFilename, "w");
	if (NULL == fOut)
		printf("Error opening output file %s\n", pszFilename);
}

void OutputFileClose()
{
	if (fOut)
	{
	  fclose(fOut);
	  fOut = NULL;
	}
}
