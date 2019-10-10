#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "functions.h"

int main(int argc, char *argv[])
{
	// must supply proper amount of args
	if (argc != 2)
	{
		printf("[!] Must supply path to PE file!\n");
		printUsage();
		exit(1);
	}

	FILE *peFilePtr;
	char *pePath = (char *)malloc(0);
	strcpy(pePath, argv[1]);

	// attempt to open PE file in read mode
	peFilePtr = fopen(pePath, "r+");
	if (peFilePtr == NULL)
	{
		printf("[-] Error opening '%s'\n", pePath);
		printUsage();
		exit(1);
	}
	checkPE(peFilePtr);
	parseImageFileHeader(peFilePtr);
	parseImageOptionalHeader(peFilePtr);
	parseDataDirectories(peFilePtr);
	parseSectionTable(peFilePtr);

	return 0;
}