#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#ifdef __BORLANDC__
#pragma warn -8057
#endif

main(int argc, char** argv)
{
	while (1)
	{
		printf("Hello World %08X\n", GetVersion());
		Sleep(1000);
	}
}

#ifdef __BORLANDC__
#pragma warn +8057
#endif
