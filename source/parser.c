/*
	parser for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	Free memory when parser detects syntax errors (e.g. strings pointed to in options structure)
	
	History:
	2008/02/12: refactoring
	2008/02/13: refactoring
	2008/02/15: added strings statement
	2008/02/16: added strings statement options
	2008/02/17: added Output support
	2008/02/23: added plugin, repeat, filter, $date, $time
	2008/02/25: added option memory
	2008/02/26: excluded simultaneous use of module and memory option
	2008/02/29: added test-function
	2008/03/06: replaced str2heap with _tcsdup, added support for double quoted strings
	2008/03/07: refactoring GetToken
	2008/10/15: added InjectCode
	2008/10/18: updated InjectCode, update ParseArgument to accept TOK_FILE (file:filename)
*/

#include <stdio.h>
#include <tchar.h>

#include "parser.h"

#define TCHAR_NEWLINE _T('\n')
#define TCHAR_NULL _T('\0')
#define TCHAR_COLON _T(':')
#define TCHAR_SHARP _T('#')
#define TCHAR_DOUBLEQUOTE _T('"')

enum {TOK_NOT_FOUND=-1, TOK_DLL_NAME, TOK_PROCESS_NAME, TOK_PID, TOK_START, TOK_WRITE, TOK_SEARCH_AND_WRITE, TOK_PAUSE, TOK_INJECT_DLL, TOK_VERBOSE, TOK_DUMP, TOK_REJECT_DLL, TOK_INFO, TOK_READONLY, TOK_CONFIRM, TOK_SUSPEND, TOK_RESUME, TOK_PRINT, TOK_ADJUST_TOKE_PRIVILEGES, TOK_ME, TOK_HEX, TOK_UNICODE, TOK_ASCII, TOK_CURRENTDIRECTORY, TOK_STRINGS, TOK_ON, TOK_OFF, TOK_DISABLE_CONSOLE_OUTPUT, TOK_OUTPUT_TO_FILE, TOK_PLUGIN, TOK_REPEAT, TOK_WRITABLE, TOK_TEST_FUNCTION, TOK_INJECT_CODE, TOK_FILE, TOK_YES, TOK_NO};
TCHAR *apszTokens[] = {_T("dll-name"), _T("process-name"), _T("pid"), _T("start"), _T("write"), _T("search-and-write"), _T("pause"), _T("inject-dll"), _T("verbose"), _T("dump"), _T("reject-dll"), _T("info"), _T("readonly"), _T("confirm"), _T("suspend"), _T("resume"), _T("print"), _T("adjust-token-privileges"), _T("me"), _T("hex"), _T("unicode"), _T("ascii"), _T("currentdirectory"), _T("strings"), _T("on"), _T("off"), _T("disable-console-output"), _T("output-to-file"), _T("plugin"), _T("repeat"), _T("writable"), _T("test-function"), _T("inject-code"), _T("file"), _T("yes"), _T("no")};

enum {OPTION_ERROR=-4, OPTION_NO_COLON=-3, OPTION_NO_VALUE=-2, OPTION_UNKNOWN=-1, OPTION_MODULE, OPTION_VERSION, OPTION_ADDRESS, OPTION_MINIMUM_LENGTH, OPTION_START_ADDRESS, OPTION_END_ADDRESS, OPTION_ALPHA_PERCENTAGE, OPTION_REGEX, OPTION_FILTER, OPTION_MEMORY, OPTION_EXECUTE};
TCHAR *apszOptions[] = {_T("module"), _T("version"), _T("address"), _T("minimum-length"), _T("start-address"), _T("end-address"), _T("alpha-percentage"), _T("regex"), _T("filter"), _T("memory"), _T("execute")};

typedef struct 
{
  BOOL bModule;
  TCHAR *pszModule;
  BOOL bVersion;
  TCHAR *pszVersion;
  BOOL bAddress;
  TCHAR *pszAddress;
  BOOL bMinimumLength;
  TCHAR *pszMinimumLength;
  BOOL bStartAddress;
  TCHAR *pszStartAddress;
  BOOL bEndAddress;
  TCHAR *pszEndAddress;
  BOOL bAlphaPercentage;
  TCHAR *pszAlphaPercentage;
  BOOL bRegex;
  TCHAR *pszRegex;
  BOOL bFilter;
  TCHAR *pszFilter;
  BOOL bMemory;
  TCHAR *pszMemory;
  BOOL bExecute;
  TCHAR *pszExecute;
} OPTIONS;

TCHAR *Str2HeapLen(TCHAR *pszValue, int iLen)
{
	TCHAR *pszReturn;
	
	pszReturn = (TCHAR *) malloc((iLen+1)*sizeof(TCHAR));
	if (NULL == pszReturn)
		return NULL;
	_tcsncpy(pszReturn, pszValue, iLen);
	pszReturn[iLen] = TCHAR_NULL;
	return pszReturn;
}

int AddStatement(CONFIG *pConfig, int commandType, void *pCommand)
{
	STATEMENT *pStatement;
	STATEMENT *pIter;
	
	pStatement = malloc(sizeof(STATEMENT));
	if (pStatement == NULL)
		return -1;
	pStatement->type = commandType;
	pStatement->command = pCommand;
	pStatement->next = NULL;
	
	if (pConfig->statements == NULL)
	{
		pConfig->statements = pStatement;
		return 0;
	}
	pIter = pConfig->statements;
	while (pIter->next != NULL)
		pIter = pIter->next;
	pIter->next = pStatement;
	return 0;
}

TCHAR *Chomp(TCHAR *pszLine)
{
	int iLen;
	
	iLen = _tcslen(pszLine);
	if (TCHAR_NEWLINE == pszLine[iLen-1])
		pszLine[iLen-1] = TCHAR_NULL;
	
	return pszLine;
}

TCHAR *TrimDoubleQuotes(TCHAR *pszString)
{
  TCHAR *pszReturn;
  
  pszReturn = _tcsdup(TCHAR_DOUBLEQUOTE == *pszString ? pszString+1 : pszString);
	if (NULL == pszReturn)
    return NULL;

  if (TCHAR_DOUBLEQUOTE == pszReturn[_tcslen(pszReturn)-1])
		pszReturn[_tcslen(pszReturn)-1] = TCHAR_NULL;

	return pszReturn;
}

int GetToken(int iStart, char *pszLine, int *piLen, TCHAR **ppszToken)
{
	int iIter;
	int iStartOfToken = -1;
	int iCountDoubleQuotes = 0;
	
	for (iIter = iStart; pszLine[iIter] != TCHAR_NULL; iIter++)
	{
		// skip whitespace before we find the start of a token
		if (-1 == iStartOfToken && isspace(pszLine[iIter]))
			continue;
		// if we have a token without double quotes, and we find a space, we consider this as the end of the token
		if (-1 != iStartOfToken && 0 == iCountDoubleQuotes && isspace(pszLine[iIter]))
		{
			*piLen = iIter - iStartOfToken;
		  if (NULL != ppszToken)
		    *ppszToken = Str2HeapLen(pszLine+iStartOfToken, *piLen);
			return iStartOfToken;
		}
		// if we have a token with double quotes, and we find a double quote, we consider this as the end of the token
		if (-1 != iStartOfToken && 0 != iCountDoubleQuotes && TCHAR_DOUBLEQUOTE == pszLine[iIter])
		{
			*piLen = iIter - iStartOfToken + 1;
		  if (NULL != ppszToken)
		    *ppszToken = Str2HeapLen(pszLine+iStartOfToken, *piLen);
			return iStartOfToken;
		}
		// if we have a token without double quotes, # indicates the start of a line comment, which we ignore
		if (0 == iCountDoubleQuotes && TCHAR_SHARP == pszLine[iIter])
		{
			*piLen = iIter - iStartOfToken;
		  if (-1 != iStartOfToken && NULL != ppszToken)
		    *ppszToken = Str2HeapLen(pszLine+iStartOfToken, *piLen);
			return iStartOfToken;
		}
		if (TCHAR_DOUBLEQUOTE == pszLine[iIter])
			iCountDoubleQuotes++;
		if (-1 == iStartOfToken)
			iStartOfToken = iIter;
	}
	*piLen = iIter - iStartOfToken;
  if (-1 != iStartOfToken && NULL != ppszToken)
    *ppszToken = Str2HeapLen(pszLine+iStartOfToken, *piLen);
	return iStartOfToken;
}

int NoRemainingTokens(TCHAR *pszLine)
{
  int iLen;
  
	return -1 == GetToken(0, pszLine, &iLen, NULL);
}

int OneRemainingToken(TCHAR *pszLine, TCHAR **ppszToken)
{
  int iStart;
  int iLen;
  int iRet;
  
	iStart = GetToken(0, pszLine, &iLen, ppszToken);
	if (-1 == iStart)
    return 0;
    
	iRet = NoRemainingTokens(pszLine+iStart+iLen);
	if (!iRet && NULL != ppszToken)
    free(*ppszToken);
    
	return iRet;
}

int TwoRemainingTokens(TCHAR *pszLine, TCHAR **ppszToken1, TCHAR **ppszToken2)
{
  int iStart;
  int iLen;
  int iRet;
  
	iStart = GetToken(0, pszLine, &iLen, ppszToken1);
	if (-1 == iStart)
    return 0;
    
	iStart = GetToken(iStart+iLen, pszLine, &iLen, ppszToken2);
	if (-1 == iStart)
	{
    free(*ppszToken1);
    return 0;
  }
    
	iRet = NoRemainingTokens(pszLine+iStart+iLen);
	if (!iRet && NULL != ppszToken1)
    free(*ppszToken1);
	if (!iRet && NULL != ppszToken2)
    free(*ppszToken2);
    
	return iRet;
}

int OneOptionalRemainingToken(TCHAR *pszLine, TCHAR **ppszToken)
{
  int iStart;
  int iLen;
  int iRet;
  
	iStart = GetToken(0, pszLine, &iLen, ppszToken);
	if (-1 == iStart)
    return 0;
    
	iRet = NoRemainingTokens(pszLine+iStart+iLen);
	if (!iRet && NULL != ppszToken)
    free(*ppszToken);
    
	return 1 == iRet ? 1 : -1;
}

int LookupToken(TCHAR *pszToken)
{
  int iIter;
  
	for (iIter = 0; iIter < sizeof(apszTokens)/sizeof(char *); iIter++)
		if (!_tcsicmp(pszToken, apszTokens[iIter]))
			return iIter;
	
	return -1;
}

int ParseUnsignedNumber(TCHAR *pszNumber, unsigned int *puiNumber)
{
	unsigned int uiParse;
	
	if (TCHAR_NULL == *pszNumber)
		return -1;
	
	uiParse = 0;
	
	while (_istdigit(*pszNumber))
		uiParse = uiParse*10 + *pszNumber++ - _T('0');
	
	if (TCHAR_NULL != *pszNumber)
		return -2;

	*puiNumber = uiParse;
	
	return 0;
}

int ParseStringColonString(TCHAR *pszToken, TCHAR **ppszLeft, TCHAR **ppszRight)
{
  TCHAR *pszColon;
  
	pszColon = _tcschr(pszToken, TCHAR_COLON);
	if (NULL == pszColon)
		return -1;
	
	*ppszLeft = Str2HeapLen(pszToken, pszColon - pszToken);
	if (NULL == *ppszLeft)
    return -2;

	*ppszRight = TrimDoubleQuotes(pszColon+1);
	if (NULL == *ppszRight)
	{
    free(*ppszLeft);
    *ppszLeft = NULL;
    return -3;
  }

	return 0;	
}

int ParseArgument(TCHAR *pszToken, unsigned char **ppucBuffer, int *piSize)
{
	TCHAR *pszPrefix;
	TCHAR *pszValue;
	int iToken;
	int iIter;
	int iByte;
	char szByte[3];

  if (ParseStringColonString(pszToken, &pszPrefix, &pszValue))
    return 0;

  iToken = LookupToken(pszPrefix);
  free(pszPrefix);
  switch(iToken)
  {
    case TOK_HEX:
  		*piSize = _tcslen(pszValue)/sizeof(TCHAR)/2;
  		*ppucBuffer = malloc(*piSize);
  		if (*ppucBuffer == NULL)
  		{
  		  free(pszValue);
  			return 0;
      }
  		szByte[2] = TCHAR_NULL;
  		for (iIter=0; iIter<*piSize; iIter++)
  		{
  			szByte[0] = pszValue[iIter*2];
  			szByte[1] = pszValue[iIter*2+1];
  			sscanf(szByte, "%2x", &iByte);				
  			(*ppucBuffer)[iIter] = (unsigned char) iByte;
  		}
      break;
    
    case TOK_UNICODE:
  		*piSize = _tcslen(pszValue)/sizeof(TCHAR)*2;
  		*ppucBuffer = malloc(*piSize);
  		if (*ppucBuffer == NULL)
  		{
  		  free(pszValue);
  			return 0;
      }
  		for (iIter=0; iIter<*piSize/2; iIter++)
  		{
  			(*ppucBuffer)[iIter*2] = (unsigned char) pszValue[iIter];
  			(*ppucBuffer)[iIter*2+1] = '\0';
  		}
      break;
      
    case TOK_ASCII:
  		*piSize = _tcslen(pszValue)/sizeof(TCHAR);
  		*ppucBuffer = malloc(*piSize);
  		if (*ppucBuffer == NULL)
  			return 0;
  		_tcsncpy(*ppucBuffer, pszValue, *piSize);
      break;
    
    case TOK_FILE:
  		*piSize = _tcslen(pszValue)/sizeof(TCHAR) + 1;
  		*ppucBuffer = pszValue;
      break;
    
    default:
      iToken = 0;
  }
			
	return iToken;
}

DWORD ParseAddress(TCHAR *pszAddress)
{
	DWORD dwAddress;
	TCHAR *pszPrefix;
	TCHAR *pszValue;

  if (ParseStringColonString(pszAddress, &pszPrefix, &pszValue))
    return 0;
	if (TOK_HEX == LookupToken(pszPrefix))
		sscanf(pszValue, "%8x", &dwAddress); //a// check hex
	else
		dwAddress = 0;
		
	free(pszPrefix);
	free(pszValue);

	return dwAddress;
}

TCHAR *ParseFilename(TCHAR *pszToken)
{
	TCHAR *pszPrefix;
	TCHAR *pszValue;
	TCHAR *pszCurrentDirectory;
	TCHAR *pszResult;
	int iLen;

  if (ParseStringColonString(pszToken, &pszPrefix, &pszValue))
    return _tcsdup(pszToken);
	
	if (TOK_CURRENTDIRECTORY != LookupToken(pszPrefix))
	{
    free(pszPrefix);
    free(pszValue);
    return _tcsdup(pszToken);
  }
  
  free(pszPrefix);
	pszCurrentDirectory = malloc(MAX_PATH);
	if (NULL == pszCurrentDirectory)
	{
    free(pszValue);
		return NULL;
	}
	if (!GetCurrentDirectory(MAX_PATH, pszCurrentDirectory))
	{
		free(pszCurrentDirectory);
    free(pszValue);
		return NULL;
	}
	iLen = (_tcslen(pszCurrentDirectory)+1+_tcslen(pszValue)+1)*sizeof(TCHAR);
	pszResult = malloc(iLen);
	if (NULL == pszResult)
	{
		free(pszCurrentDirectory);
    free(pszValue);
		return NULL;
	}
	_sntprintf(pszResult, iLen, "%s\\%s", pszCurrentDirectory, pszValue);
	return pszResult;
}

int ParseOption(TCHAR *pszToken, TCHAR **pszOption)
{
	TCHAR *pszBuffer;
	TCHAR *pszColon;
	int iIter;
	
	pszBuffer = _tcsdup(pszToken);
	if (NULL == pszBuffer)
		return OPTION_ERROR;
	pszColon = _tcschr(pszBuffer, TCHAR_COLON);
	if (NULL == pszColon)
	{
		free(pszBuffer);
		return OPTION_NO_COLON;
	}
	*pszColon = TCHAR_NULL;
	for (iIter =0; iIter < sizeof(apszOptions)/sizeof(TCHAR *); iIter++)
		if (!_tcsicmp(pszBuffer, apszOptions[iIter]))
		{
			if (0 == _tcslen(pszColon+1))
			{
				free(pszBuffer);
				return OPTION_NO_VALUE;
			}
			*pszOption = _tcsdup(pszColon+1);
			free(pszBuffer);
			return iIter;
		}
	
	free(pszBuffer);
	
	return OPTION_UNKNOWN;
}

int ParseOptions(TCHAR *pszLine, OPTIONS *psO)
{
  TCHAR *pszToken;
  TCHAR *pszValue;
  int iStart;
  int iLen;
  int iPrefix;  
  
  iStart = iLen = 0;
	while (TRUE)
	{
    iStart = GetToken(iStart+iLen, pszLine, &iLen, &pszToken);
    if (-1 == iStart)
      return -1;
      
    iPrefix = ParseOption(pszToken, &pszValue);
    free(pszToken); 
		switch(iPrefix)
		{
			case OPTION_ERROR:
			case OPTION_NO_VALUE:
				return -2;
			
			case OPTION_VERSION:
        if (!psO->bVersion || NULL != psO->pszVersion)
        {
          free(pszValue);
          return -3;
        }
        psO->pszVersion = pszValue;
				break;
	
			case OPTION_MODULE:
        if (!psO->bModule || NULL != psO->pszModule)
        {
          free(pszValue);
          return -4;
        }
        psO->pszModule = pszValue;
				break;
	
			case OPTION_ADDRESS:
        if (!psO->bAddress || NULL != psO->pszAddress)
        {
          free(pszValue);
          return -4;
        }
        psO->pszAddress = pszValue;
				break;
	
			case OPTION_MINIMUM_LENGTH:
        if (!psO->bMinimumLength || NULL != psO->pszMinimumLength)
        {
          free(pszValue);
          return -4;
        }
        psO->pszMinimumLength = pszValue;
				break;
	
			case OPTION_START_ADDRESS:
        if (!psO->bStartAddress || NULL != psO->pszStartAddress)
        {
          free(pszValue);
          return -4;
        }
        psO->pszStartAddress = pszValue;
				break;
	
			case OPTION_END_ADDRESS:
        if (!psO->bEndAddress || NULL != psO->pszEndAddress)
        {
          free(pszValue);
          return -4;
        }
        psO->pszEndAddress = pszValue;
				break;
	
			case OPTION_ALPHA_PERCENTAGE:
        if (!psO->bAlphaPercentage || NULL != psO->pszAlphaPercentage)
        {
          free(pszValue);
          return -4;
        }
        psO->pszAlphaPercentage = pszValue;
				break;
	
			case OPTION_REGEX:
        if (!psO->bRegex || NULL != psO->pszRegex)
        {
          free(pszValue);
          return -4;
        }
        psO->pszRegex = TrimDoubleQuotes(pszValue);
        free(pszValue);
				break;
	
			case OPTION_FILTER:
        if (!psO->bFilter || NULL != psO->pszFilter)
        {
          free(pszValue);
          return -4;
        }
        psO->pszFilter = pszValue;
				break;
	
			case OPTION_MEMORY:
        if (!psO->bMemory || NULL != psO->pszMemory)
        {
          free(pszValue);
          return -4;
        }
        psO->pszMemory = pszValue;
				break;
	
			case OPTION_EXECUTE:
        if (!psO->bExecute || NULL != psO->pszExecute)
        {
          free(pszValue);
          return -4;
        }
        psO->pszExecute = pszValue;
				break;
	
			case OPTION_UNKNOWN:
			case OPTION_NO_COLON:
        return iStart;

			default:
        free(pszValue);
        return -5;
		}
  }
}

int ParseConfigVerbose(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszSetting;
	int iRet;
	
	if (!OneRemainingToken(pszLine, &pszSetting))
    return -1;
  
  iRet = ParseUnsignedNumber(pszSetting, &(pConfig->uiVerbose));
  	
	free(pszSetting);
	
	return iRet;
}

int ParseConfigReadOnly(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
	{
		pConfig->uiReadOnly = 1;	
		return 0;
	}
	else
		return -1;
}

int ParseConfigPause(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_PAUSE, NULL);
	else
		return -1;
}

int ParseConfigInfo(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_INFO, NULL);
	else
		return -1;
}

int ParseConfigDump(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_DUMP, NULL);
	else
		return -1;
}

int ParseConfigStart(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	
	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;
	
	pConfig->szStart = ParseFilename(pszToken);
	
	free(pszToken);
	
	return NULL == pConfig->szStart ? -2 : 0;
}

int ParseConfigInjectDLL(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	TCHAR *pszFilename;
	struct Command1psz *pC1P;

	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;

	pszFilename = ParseFilename(pszToken);
	if (NULL == pszFilename)
	{
		free(pszToken);
		return -2;
	}
	
	free(pszToken);

	pC1P = malloc(sizeof(struct Command1psz));
	if (NULL == pC1P)
	{
		free(pszFilename);
		return -3;
	}
	pC1P->pszArgument = pszFilename;
	return AddStatement(pConfig, COMMAND_INJECT_DLL, pC1P);
}

int ParseConfigRejectDLL(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	struct Command1psz *pC1P;

	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;
	
	pC1P = malloc(sizeof(struct Command1psz));
	if (NULL == pC1P)
	{
		free(pszToken);
		return -2;
	}
	pC1P->pszArgument = pszToken;
	return AddStatement(pConfig, COMMAND_REJECT_DLL, pC1P);
}

int ParseConfigDLLName(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	
	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;
	
	pConfig->szDLLName = pszToken;
	
	return NULL == pConfig->szDLLName ? -2 : 0;
}

int ParseConfigProcessName(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	
	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;
	
	pConfig->szProcessName = pszToken;
	
	return NULL == pConfig->szProcessName ? -2 : 0;
}

int ParseConfigPID(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszSetting;
	int iRet;
	unsigned int uiPID;
	
	if (!OneRemainingToken(pszLine, &pszSetting))
    return -1;
  
  iRet = ParseUnsignedNumber(pszSetting, &uiPID);
  pConfig->dwPID = uiPID;
  
	free(pszSetting);
	
	return iRet;
}

int ParseConfigWrite(TCHAR *pszLine, CONFIG *pConfig)
{
	int iStart;
	int iLen;
	OPTIONS sO;
	TCHAR *pszAddress;
	TCHAR *pszData;
	struct CommandWrite *pCW;
	DWORD dwAddress;
	unsigned char *pucBytes;
	int iBytes;
	int iTokenArgument;
	
	iStart = GetToken(0, pszLine, &iLen, NULL);
	if (-1 == iStart)
		return -1;

  ZeroMemory(&sO, sizeof(OPTIONS));
  sO.bVersion = TRUE;
  iStart = ParseOptions(pszLine+iStart, &sO);
	if (-1 == iStart)
		return -1;

	if (!TwoRemainingTokens(pszLine+iStart, &pszAddress, &pszData))
		return -1;
	dwAddress = ParseAddress(pszAddress);
	free(pszAddress);
	iTokenArgument = ParseArgument(pszData, &pucBytes, &iBytes);
	free(pszData);
	if (0 == dwAddress || 0 == iBytes || (TOK_HEX != iTokenArgument && TOK_ASCII != iTokenArgument && TOK_UNICODE != iTokenArgument))
		return -1;
		
	pCW = malloc(sizeof(struct CommandWrite));
	if (NULL == pCW)
		return -1;
	pCW->address = dwAddress;
	pCW->len = iBytes;
	pCW->bytes = pucBytes;
	pCW->pszVersion = sO.pszVersion;
	return AddStatement(pConfig, COMMAND_WRITE, pCW);
}

int ParseConfigSearchAndWrite(TCHAR *pszLine, CONFIG *pConfig)
{
	int iStart;
	int iLen;
	OPTIONS sO;
	TCHAR *pszSearch;
	TCHAR *pszWrite;
	unsigned char *pucArgumentSearch;
	int iBytesSearch;
	unsigned char *pucArgumentWrite;
	int iBytesWrite;
	struct CommandSearchAndWrite *pCSAW;
	int iTokenArgument;
	
	iStart = GetToken(0, pszLine, &iLen, NULL);
	if (-1 == iStart)
		return -1;

  ZeroMemory(&sO, sizeof(OPTIONS));
  sO.bModule = TRUE;
  sO.bMemory = TRUE;
  iStart = ParseOptions(pszLine+iStart, &sO);
	if (-1 == iStart)
		return -1;

	if (NULL != sO.pszModule && NULL != sO.pszMemory)
		return -1;
		
	if (!TwoRemainingTokens(pszLine+iStart, &pszSearch, &pszWrite))
		return -1;
	iTokenArgument = ParseArgument(pszSearch, &pucArgumentSearch, &iBytesSearch);
	free(pszSearch);
	if (0 == iBytesSearch || (TOK_HEX != iTokenArgument && TOK_ASCII != iTokenArgument && TOK_UNICODE != iTokenArgument))
		return -1;
	iTokenArgument = ParseArgument(pszWrite, &pucArgumentWrite, &iBytesWrite);
	free(pszWrite);
	if (0 == iBytesWrite || (TOK_HEX != iTokenArgument && TOK_ASCII != iTokenArgument && TOK_UNICODE != iTokenArgument))
		return -1;

	pCSAW = malloc(sizeof(struct CommandSearchAndWrite));
	if (NULL == pCSAW)
    return -1;
	pCSAW->searchLen = iBytesSearch;
	pCSAW->searchBytes = pucArgumentSearch;
	pCSAW->writeLen = iBytesWrite;
	pCSAW->writeBytes = pucArgumentWrite;
	pCSAW->pszModule = sO.pszModule;
	if (NULL != sO.pszMemory)
		if (TOK_WRITABLE == LookupToken(sO.pszMemory))
			pCSAW->dwMemory = PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY;
		else
				return -1;
	else
		pCSAW->dwMemory = 0;
	return AddStatement(pConfig, COMMAND_SEARCH_AND_WRITE, pCSAW);
}

int ParseConfigConfirm(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_CONFIRM, NULL);
	else
		return -1;
}

int ParseConfigSuspend(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_SUSPEND, NULL);
	else
		return -1;
}

int ParseConfigResume(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_RESUME, NULL);
	else
		return -1;
}

int ParseConfigPrint(TCHAR *pszLine, CONFIG *pConfig)
{
	int iStart;
	int iLen;
	TCHAR *pszArgument;
	struct Command1psz *pC1P;
	
	iStart = GetToken(0, pszLine, &iLen, NULL);
	pC1P = malloc(sizeof(struct Command1psz));
	if (NULL == pC1P)
    return -1;
	if (-1 == iStart)
		pszArgument = NULL;
	else
		pszArgument = _tcsdup(pszLine+iStart);
	pC1P->pszArgument = pszArgument;
	return AddStatement(pConfig, COMMAND_PRINT, pC1P);
}

int ParseConfigAdjustTokenPrivileges(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	int iToken;
	
	if (!OneRemainingToken(pszLine, &pszToken))
    return -1;

  iToken = LookupToken(pszToken);
  free(pszToken);
  if (TOK_ME != iToken)
    return -2;

	return AddStatement(pConfig, COMMAND_ADJUST_TOKE_PRIVILEGES, NULL);
}

//a// Release Memory!
int ParseConfigStrings(TCHAR *pszLine, CONFIG *pConfig)
{
	OPTIONS sO;
	int iStart;
	struct CommandStrings *pCS;

  ZeroMemory(&sO, sizeof(OPTIONS));
  sO.bModule = TRUE;
  sO.bAddress = TRUE;
  sO.bMinimumLength = TRUE;
  sO.bStartAddress = TRUE;
  sO.bEndAddress = TRUE;
  sO.bAlphaPercentage = TRUE;
  sO.bRegex = TRUE;
  sO.bFilter = TRUE;
  sO.bMemory = TRUE;
  iStart = ParseOptions(pszLine, &sO);
	if (iStart != -1)
		return -1;

	if (NULL != sO.pszModule && NULL != sO.pszMemory)
		return -7;
		
	pCS = malloc(sizeof(struct CommandStrings));
	if (NULL == pCS)
    return -1;

	pCS->pszModule = sO.pszModule;
	
	if (NULL != sO.pszAddress)
		switch(LookupToken(sO.pszAddress))
		{
			case TOK_ON:
				pCS->bAddress = TRUE;
				break;
				
			case TOK_OFF:
				pCS->bAddress = FALSE;
				break;

			default:
				return -2;
		}
	else
		pCS->bAddress = FALSE;
		
	if (NULL != sO.pszMinimumLength)
	{
		if (ParseUnsignedNumber(sO.pszMinimumLength, &(pCS->uiMinimumLength)) < 0)
			return -3;
	}
	else
		pCS->uiMinimumLength = 4;
		
	if (NULL != sO.pszStartAddress)
	{
		sscanf(sO.pszStartAddress, "%8x", &(pCS->dwStartAddress)); //a// check hex
	}
	else
		pCS->dwStartAddress = 0;
		
	if (NULL != sO.pszEndAddress)
	{
		sscanf(sO.pszEndAddress, "%8x", &(pCS->dwEndAddress)); //a// check hex
	}
	else
		pCS->dwEndAddress = 0xFFFFFFFF;
		
	if (NULL != sO.pszAlphaPercentage)
	{
		if (ParseUnsignedNumber(sO.pszAlphaPercentage, &(pCS->uiAlphaPercentage)) < 0)
			return -4;
		if (pCS->uiAlphaPercentage > 100)
			return -5;
	}
	else
		pCS->uiAlphaPercentage = 0;

	pCS->pszRegex = sO.pszRegex;
	pCS->pPCRE = NULL;
	
	pCS->pszFilter = sO.pszFilter;

	if (NULL != sO.pszMemory)
		if (TOK_WRITABLE == LookupToken(sO.pszMemory))
			pCS->dwMemory = PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY;
		else
				return -6;
	else
		pCS->dwMemory = 0;
		
	return AddStatement(pConfig, COMMAND_STRINGS, pCS);
}

int ParseConfigDisableConsoleOutput(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
	{
		pConfig->uiDisableConsoleOutput = 1;	
		return 0;
	}
	else
		return -1;
}

int ParseConfigOutputToFile(TCHAR *pszLine, CONFIG *pConfig)
{
	char *pszFilename;
	
	pszFilename = NULL;
	
	switch(OneOptionalRemainingToken(pszLine, &pszFilename))
	{
		case 0:
			pConfig->pszOutputToFile = "";	
			return 0;
		
		case 1:
			pConfig->pszOutputToFile = pszFilename;
			return 0;
			
		case -1:
		default:
			return -1;
	}
}

int ParseConfigPlugin(TCHAR *pszLine, CONFIG *pConfig)
{
	return !OneRemainingToken(pszLine, &(pConfig->pszPlugin)) ? -1 : 0;
}

int ParseConfigRepeat(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszSleep;
	TCHAR *pszCount;
	int iRet1;
	int iRet2;
	
	if (OneRemainingToken(pszLine, &pszSleep))
	{
	  iRet1 = ParseUnsignedNumber(pszSleep, &(pConfig->uiRepeatSleep));
		free(pszSleep);
		if (0 == pConfig->uiRepeatSleep)
			return -1;
		else
			return iRet1;
	}
	
	if (TwoRemainingTokens(pszLine, &pszSleep, &pszCount))
	{
	  iRet1 = ParseUnsignedNumber(pszSleep, &(pConfig->uiRepeatSleep));
		free(pszSleep);
	  iRet2 = ParseUnsignedNumber(pszCount, &(pConfig->uiRepeatCount));
		free(pszCount);
		if (0 == iRet1 && 0 == pConfig->uiRepeatSleep)
			return -1;
		if (0 == iRet2 && 0 == pConfig->uiRepeatCount)
			return -2;
		if (0 == iRet1)
			return iRet2;
		else
			return iRet1;
	}
	else
		return -4;
}

int ParseConfigTestFunction(TCHAR *pszLine, CONFIG *pConfig)
{
	if (NoRemainingTokens(pszLine))
		return AddStatement(pConfig, COMMAND_TEST_FUNCTION, NULL);
	else
		return -1;
}

int ParseConfigInjectCode(TCHAR *pszLine, CONFIG *pConfig)
{
	TCHAR *pszToken;
	struct CommandInjectCode *pCInjectCode;
	unsigned char *pucBytes;
	int iBytes;
	OPTIONS sO;
	int iStart;
	int iTokenArgument;

  ZeroMemory(&sO, sizeof(OPTIONS));
  sO.bMinimumLength = TRUE;
  sO.bExecute = TRUE;
  iStart = ParseOptions(pszLine, &sO);
	if (iStart < 0)
		return -1;

	if (!OneRemainingToken(pszLine+iStart, &pszToken))
    return -2;

	iTokenArgument = ParseArgument(pszToken, &pucBytes, &iBytes);
	free(pszToken);
	if (0 == iBytes || (TOK_HEX != iTokenArgument && TOK_ASCII != iTokenArgument && TOK_UNICODE != iTokenArgument && TOK_FILE != iTokenArgument))
	{
		free(pucBytes);
		return -3;
	}
	
	pCInjectCode = malloc(sizeof(struct CommandInjectCode));
	if (NULL == pCInjectCode)
	{
		free(pucBytes);
		return -4;
	}
	pCInjectCode->pbBytes = pucBytes;
	pCInjectCode->lBytesSize = iBytes;
	pCInjectCode->bFilename = TOK_FILE == iTokenArgument;
	if (NULL != sO.pszMinimumLength)
	{
		if (ParseUnsignedNumber(sO.pszMinimumLength, &(pCInjectCode->uiMinimumBytesSize)) < 0)
			return -5;
	}
	else
		pCInjectCode->uiMinimumBytesSize = 0;
	if (NULL != sO.pszExecute)
		switch(LookupToken(sO.pszExecute))
		{
			case TOK_YES:
				pCInjectCode->bExecute = TRUE;
				break;
				
			case TOK_NO:
				pCInjectCode->bExecute = FALSE;
				break;

			default:
				return -2;
		}
	else
		pCInjectCode->bExecute = TRUE;
		

	return AddStatement(pConfig, COMMAND_INJECT_CODE, pCInjectCode);
}

int ParseLine(TCHAR *pszLine, CONFIG *pConfig)
{
	int len;
	int start;
	TCHAR *pszToken;
	int iToken;

	Chomp(pszLine);

	start = GetToken(0, pszLine, &len, &pszToken);
	if (start == -1) // empty line or comment line
		return 0;

  iToken = LookupToken(pszToken);
  free(pszToken);
	switch (iToken)
	{
		case TOK_DLL_NAME:
			return ParseConfigDLLName(pszLine+start+len, pConfig);
			
		case TOK_PROCESS_NAME:
			return ParseConfigProcessName(pszLine+start+len, pConfig);

		case TOK_PID:
			return ParseConfigPID(pszLine+start+len, pConfig);
			
		case TOK_VERBOSE:
			return ParseConfigVerbose(pszLine+start+len, pConfig);
			
		case TOK_START:
			return ParseConfigStart(pszLine+start+len, pConfig);

		case TOK_WRITE:
			return ParseConfigWrite(pszLine+start+len, pConfig);

		case TOK_SEARCH_AND_WRITE:
			return ParseConfigSearchAndWrite(pszLine+start+len, pConfig);

		case TOK_PAUSE:
			return ParseConfigPause(pszLine+start+len, pConfig);

		case TOK_CONFIRM:
			return ParseConfigConfirm(pszLine+start+len, pConfig);

		case TOK_DUMP:
			return ParseConfigDump(pszLine+start+len, pConfig);

		case TOK_INJECT_DLL:
			return ParseConfigInjectDLL(pszLine+start+len, pConfig);

		case TOK_REJECT_DLL:
			return ParseConfigRejectDLL(pszLine+start+len, pConfig);

		case TOK_INFO:
			return ParseConfigInfo(pszLine+start+len, pConfig);

		case TOK_READONLY:
			return ParseConfigReadOnly(pszLine+start+len, pConfig);

		case TOK_SUSPEND:
			return ParseConfigSuspend(pszLine+start+len, pConfig);

		case TOK_RESUME:
			return ParseConfigResume(pszLine+start+len, pConfig);

		case TOK_PRINT:
			return ParseConfigPrint(pszLine+start+len, pConfig);

		case TOK_ADJUST_TOKE_PRIVILEGES:
			return ParseConfigAdjustTokenPrivileges(pszLine+start+len, pConfig);

		case TOK_STRINGS:
			return ParseConfigStrings(pszLine+start+len, pConfig);

		case TOK_DISABLE_CONSOLE_OUTPUT:
			return ParseConfigDisableConsoleOutput(pszLine+start+len, pConfig);

		case TOK_OUTPUT_TO_FILE:
			return ParseConfigOutputToFile(pszLine+start+len, pConfig);

		case TOK_PLUGIN:
			return ParseConfigPlugin(pszLine+start+len, pConfig);

		case TOK_REPEAT:
			return ParseConfigRepeat(pszLine+start+len, pConfig);

		case TOK_TEST_FUNCTION:
			return ParseConfigTestFunction(pszLine+start+len, pConfig);

		case TOK_INJECT_CODE:
			return ParseConfigInjectCode(pszLine+start+len, pConfig);
	}

	return -1;
}

LPSTR ExtractLine(LPSTR pszLines)
{
	static LPSTR pszLineEndSave;
	LPSTR pszLineEnd;
	LPSTR pszLineReturn;
	
	if (NULL == pszLines)
	{
		if (NULL == pszLineEndSave)
			return NULL;
		*pszLineEndSave = '\r';
		pszLineEnd = strstr(pszLineEndSave+2, "\r");
		if (NULL != pszLineEnd)
		{
			*pszLineEnd = '\0';
			pszLineReturn = pszLineEndSave+2;
			pszLineEndSave = pszLineEnd;
			return pszLineReturn;
		}
		else
		{
			pszLineReturn = pszLineEndSave+2;
			pszLineEndSave = NULL;
			return pszLineReturn;
		}
	}
	else
	{
		pszLineEndSave = pszLineEnd = strstr(pszLines, "\r");
		if (NULL != pszLineEnd)
			*pszLineEnd = '\0';
		return pszLines;
	}
}

int ParseConfig(LPSTR pszConfig, CONFIG *pConfig)
{
	int iCntLines;
	int iRet;
	int iRCParseLine;
	LPSTR pszLine;

  ZeroMemory(pConfig, sizeof(CONFIG));

	iCntLines = 0;
	iRet = 0;
	pszLine = ExtractLine(pszConfig);
	while (NULL != pszLine)
	{
		iCntLines++;
		iRCParseLine = ParseLine(pszLine, pConfig);
		if (iRCParseLine)
		{
			printf("Config error code %d line %d: %s\n", iRCParseLine, iCntLines, pszLine);
			iRet = -2;
		}
		pszLine = ExtractLine(NULL);
	}
	
	free(pszLine);
	
	return iRet;
}

int CheckConfig(CONFIG *pConfig)
{
	STATEMENT *pStatement;
	int iCntProcessStatements;
	int iCntGeneralStatements;
	int iCntTargets;

	iCntProcessStatements = 0;
	iCntGeneralStatements = 0;
	iCntTargets = 0;
	
	for (pStatement = pConfig->statements; pStatement != NULL; pStatement = pStatement->next)
		switch (pStatement->type)
		{
			case COMMAND_WRITE:
			case COMMAND_SEARCH_AND_WRITE:
			case COMMAND_INJECT_DLL:
			case COMMAND_REJECT_DLL:
			case COMMAND_DUMP:
			case COMMAND_SUSPEND:
			case COMMAND_RESUME:
			case COMMAND_ADJUST_TOKE_PRIVILEGES:
			case COMMAND_STRINGS:
			case COMMAND_INJECT_CODE:
				iCntProcessStatements++;
				break;
				
			case COMMAND_PAUSE:
			case COMMAND_INFO:
			case COMMAND_CONFIRM:
			case COMMAND_PRINT:
				iCntGeneralStatements++;
				break;
				
			default:
				break;
		}
		
	if (iCntProcessStatements + iCntGeneralStatements == 0)
	{
		printf("Config error: no statements\n");
		return -1;
	}

	if (pConfig->szProcessName == NULL && pConfig->szDLLName == NULL && pConfig->szStart == NULL && pConfig->dwPID == 0 && iCntGeneralStatements == 0)
	{
		printf("Config error: no target(s)\n");
		return -2;
	}
	
	if (pConfig->szProcessName == NULL && pConfig->szDLLName == NULL && pConfig->szStart == NULL && pConfig->dwPID == 0 && iCntGeneralStatements > 0 && iCntProcessStatements == 0)
		return 0;

	if (pConfig->szProcessName != NULL)
		iCntTargets++;
	if (pConfig->szDLLName != NULL)
		iCntTargets++;
	if (pConfig->szStart != NULL)
		iCntTargets++;
	if (pConfig->dwPID != 0)
		iCntTargets++;

	if (iCntTargets > 1)
	{
		printf("Config error: more than 1 target\n");
		return -3;
	}
		
	return 0;
}

