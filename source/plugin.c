/*
	plugin for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/22: Start development
	2008/02/23: type change
	2008/02/25: start using circular buffer
*/

#include <windows.h>
#include <math.h>
 
#define NUMBER_OF_DIGITS 12

#ifdef __BORLANDC__
#pragma warn -8057
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	return TRUE;
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif

BOOL CheckBankAccountNumber(char *pszCircularBuffer, int iPositionInBuffer)
{
	double d10;
	double d2;
	int iIter;
	
	for (iIter = 1; iIter <= 10; iIter++)
	{
		d10 = d10*10.0 + pszCircularBuffer[iPositionInBuffer] - '0';
		iPositionInBuffer = (iPositionInBuffer + 1) % NUMBER_OF_DIGITS;
	}

	for (iIter = 1; iIter <= 2; iIter++)
	{
		d2 = d2*10.0 + pszCircularBuffer[iPositionInBuffer] - '0';
		iPositionInBuffer = (iPositionInBuffer + 1) % NUMBER_OF_DIGITS;
	}
	
	if (fabs(d10) < 0.00001)
		return FALSE;
		
	return fabs(fmod(d10, 97.0) - d2) < 0.00001;
}

__declspec(dllexport) __stdcall BOOL BankAccount(char *pszString)
{
	char *pszIter;
	char acCircularBuffer[NUMBER_OF_DIGITS];
	int iPositionInBuffer;
	int iDigitsInBuffer;
	
	iPositionInBuffer = 0;
	iDigitsInBuffer = 0;
	for (pszIter = pszString; '\0' != *pszIter; pszIter++)
		if (isdigit(*pszIter))
		{
			acCircularBuffer[iPositionInBuffer] = *pszIter;
			iPositionInBuffer = (iPositionInBuffer + 1) % NUMBER_OF_DIGITS;
			if (NUMBER_OF_DIGITS == ++iDigitsInBuffer)
				if (CheckBankAccountNumber(acCircularBuffer, iPositionInBuffer))
					return TRUE;
				else
					iDigitsInBuffer--;
		}
		else if (isalpha(*pszIter))
			if (iDigitsInBuffer > 0)
			{
				iPositionInBuffer = 0;
				iDigitsInBuffer = 0;
			}

	return FALSE;
}
