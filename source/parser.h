/*
	parser for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/12: refactoring
	2008/02/15: added strings statement
	2008/02/16: added strings statement options
	2008/02/17: added Output support
	2008/02/23: added plugin, repeat
	2008/02/24: added pcre
	2008/02/25: added option memory
	2008/02/29: added test-function
	2008/10/15: added InjectCode
	2008/10/18: updated InjectCode
*/

#include <windows.h>

#include "pcre.h"

enum {COMMAND_NONE, COMMAND_READ, COMMAND_WRITE, COMMAND_SEARCH_AND_WRITE, COMMAND_PAUSE, COMMAND_INJECT_DLL, COMMAND_DUMP, COMMAND_REJECT_DLL, COMMAND_INFO, COMMAND_CONFIRM, COMMAND_SUSPEND, COMMAND_RESUME, COMMAND_PRINT, COMMAND_ADJUST_TOKE_PRIVILEGES, COMMAND_STRINGS, COMMAND_TEST_FUNCTION, COMMAND_INJECT_CODE};

struct CommandRead
{
	DWORD address;
	int len;	
};

struct CommandWrite
{
	DWORD address;
	int len;	
	unsigned char *bytes;
	TCHAR *pszVersion;
};

struct CommandSearchAndWrite
{
	int searchLen;	
	unsigned char *searchBytes;
	int writeLen;	
	unsigned char *writeBytes;
	char *pszModule;
	DWORD dwMemory;
};

struct Command1psz
{
	char *pszArgument;
};

struct CommandStrings
{
	BOOL bAddress;
  unsigned int uiMinimumLength;
  DWORD dwStartAddress;
  DWORD dwEndAddress;
  unsigned int uiAlphaPercentage;
	char *pszModule;
	char *pszRegex;
	pcre *pPCRE;
	char *pszFilter;
	DWORD dwMemory;
};

struct CommandInjectCode
{
	BYTE *pbBytes;
	long lBytesSize;
	BOOL bFilename;
	unsigned int uiMinimumBytesSize;
	BOOL bExecute;
};

struct Statement
{
	int type;
	void *command;
	struct Statement *next;
};

typedef struct Statement STATEMENT;

typedef struct
{
	DWORD dwPID;
	char *szProcessName;
	char *szDLLName;
	char *szStart;
	UINT uiVerbose;
	UINT uiReadOnly;
	UINT uiDisableConsoleOutput;
	char *pszOutputToFile;
	char *pszPlugin;
	UINT uiRepeatSleep;
	UINT uiRepeatCount;
	STATEMENT *statements;
} CONFIG;

TCHAR *Chomp(TCHAR *pszLine);
int ParseConfig(LPSTR pszConfig, CONFIG *pConfig);
int CheckConfig(CONFIG *pConfig);
