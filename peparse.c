#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void printUsage()
{
	printf("[!] Usage:\n");
	printf("\tpeparse.exe /path/to/pefile\n");
}

// check valid PE signature, magic bytes must be MZ for
// a valid DOS image
void checkPE(FILE *peFilePtr)
{
	char *twoBytes = malloc(2);
	size_t result = fread(twoBytes, 1, 2, peFilePtr);

	if (twoBytes[0] == 'M' && twoBytes[1] == 'Z')
		printf("[+] First two bytes: %c%c\n", twoBytes[0], twoBytes[1]);
	else
	{
		printf("[-] Invalid PE signature '%c%c'\n", twoBytes[0], twoBytes[1]);
		exit(1);
	}
}

void parseImageFileHeader(FILE *peFilePtr)
{
	int signature;							// 4 bytes
	unsigned short Machine;					// 2 bytes
	unsigned short NumberOfSections;		// 2 bytes
	int TimeDateStamp;						// 4 bytes
	int PtrToSymbolTable;					// 4 bytes
	int NumberOfSymbols;					// 4 bytes
	unsigned short SizeOfOptionalHeader;	// 2 bytes
	unsigned short Characteristics;			// 2 bytes
											// 24 total bytes
	// get to header
	fseek(peFilePtr, 0x3c, SEEK_SET);
	int elfanew;
	fread(&elfanew, sizeof(int), 1, peFilePtr);
	printf("[!] elfanew: 0x%08x\n", elfanew);
	fseek(peFilePtr, elfanew, SEEK_SET);

	int pos;
	
	printf("[!] IMAGE_FILE_HEADER\n");
	
	// PE section signature
	fread(&signature, 4, 1, peFilePtr);
	printf("\t[+] PE Signature: 0x%4x\n", signature);
	if (signature != 0x4550)
		printf("\t\t[?] Non-standard, should be 0x4550\n");
	
	// machine type
	fread(&Machine, 2, 1, peFilePtr);
	printf("\t[+] Machine: %x\n", Machine);
	
	// number of sections
	fread(&NumberOfSections, 2, 1, peFilePtr);
	printf("\t[+] # of Sections: %d\n", NumberOfSections);
	
	// timestamp
	fread(&TimeDateStamp, sizeof(int), 1, peFilePtr);
	time_t t = TimeDateStamp;
	printf("\t[+] Compiled: %s", ctime(&t));
	
	// pointer to symbol table
	fread(&PtrToSymbolTable, 4, 1, peFilePtr);
	printf("\t[+] Symbol Table Offset: 0x%08x\n", PtrToSymbolTable);
	
	// number of symbols
	fread(&NumberOfSymbols, 4, 1, peFilePtr);
	printf("\t[+] # of Symbols: %d\n", NumberOfSymbols);
	
	// SizeOfOptional Header
	fread(&SizeOfOptionalHeader, 2, 1, peFilePtr);
	printf("\t[+] Optional Header Size: 0x%x (%d bytes)\n", SizeOfOptionalHeader, SizeOfOptionalHeader);
	
	// flags for image chars
	fread(&Characteristics, 2, 1, peFilePtr);
	printf("\t[+] Characteristics: 0x%04x\n", Characteristics);
}

void parseImageOptionalHeader(FILE *peFilePtr)
{
	unsigned short Magic;							// 2 bytes
	unsigned char MajorLinkerVersion;				// 1 byte
	unsigned char MinorLinkerVersion;				// 1 byte
	unsigned int SizeOfCode;						// 4 bytes
	unsigned int SizeOfInitializedData;				// 4 bytes
	unsigned int SizeOfUninitializedData;			// 4 bytes
	unsigned int AddressOfEntryPoint;				// 4 bytes
	unsigned int BaseOfCode;						// 4 bytes
	unsigned int BaseOfData;						// 4 bytes
	unsigned int ImageBase;							// 4 bytes
	unsigned int SectionAlignment;					// 4 bytes
	unsigned int FileAlignment;						// 4 bytes
	unsigned short MajorOperatingSystemVersion;		// 2 bytes
	unsigned short MinorOperatingSystemVersion;		// 2 bytes
	unsigned short MajorImageVersion;				// 2 bytes
	unsigned short MinorImageVersion;				// 2 bytes
	unsigned short MajorSubsystemVersion;			// 2 bytes
	unsigned short MinorSubsystemVersion;			// 2 bytes
	unsigned int Win32VersionValue;					// 4 bytes
	unsigned int SizeOfImage;						// 4 bytes
	unsigned int SizeOfHeaders;						// 4 bytes
	unsigned int CheckSum;							// 4 Bytes
	unsigned short Subsystem;						// 2 bytes
	unsigned short DllCharacteristics;				// 2 bytes
	unsigned int SizeOfStackReserve;				// 4 bytes
	unsigned int SizeOfStackCommit;					// 4 bytes
	unsigned int SizeOfHeapReserve;					// 4 bytes
	unsigned int SizeOfHeapCommit;					// 4 bytes
	unsigned int LoaderFlags;						// 4 bytes
	unsigned int NumberOfRvaAndSizes;				// 4 bytes

	printf("[!] IMAGE_OPTIONAL_HEADER\n");
	
	// magic bytes for Optional header, typically 0x10b
	fread(&Magic, sizeof(unsigned short), 1, peFilePtr);
	printf("\t[+] Magic bytes: 0x%x\n", Magic);

	// MajorLinkerVersion & MinorLinkerVersion
	fread(&MajorLinkerVersion, 1, 1, peFilePtr);
	fread(&MinorLinkerVersion, 1, 1, peFilePtr);
	printf("\t[+] Linker version: %d.%d\n", MajorLinkerVersion, MinorLinkerVersion);

	// size of .text section
	fread(&SizeOfCode, 4, 1, peFilePtr);
	printf("\t[+] .text section: 0x%x (%d bytes)\n", SizeOfCode, SizeOfCode);

	// size of intialized data
	fread(&SizeOfInitializedData, 4, 1, peFilePtr);
	printf("\t[+] Intialized data: 0x%x (%d bytes)\n", SizeOfInitializedData, SizeOfInitializedData);

	// size of .bss
	fread(&SizeOfUninitializedData, 4, 1, peFilePtr);
	printf("\t[+] .bss section: 0x%x (%d bytes)\n", SizeOfUninitializedData, SizeOfUninitializedData);

	// address of entry point
	fread(&AddressOfEntryPoint, 4, 1, peFilePtr);
	printf("\t[+] Entry point: 0x%08x\n", AddressOfEntryPoint);

	// base of code
	fread(&BaseOfCode, 4, 1, peFilePtr);
	printf("\t[+] Base of code: 0x%08x\n", BaseOfCode);

	// base of data
	fread(&BaseOfData, 4, 1, peFilePtr);
	printf("\t[+] Base of data: 0x%08x\n", BaseOfData);

	// image base
	fread(&ImageBase, 4, 1, peFilePtr);
	printf("\t[+] Image Base: 0x%08x\n", ImageBase);

	// Section Alignment (page size)
	fread(&SectionAlignment, 4, 1, peFilePtr);
	printf("\t[+] Page Size: 0x%x (%d bytes)\n", SectionAlignment, SectionAlignment);


	// File Alignment
	fread(&FileAlignment, 4, 1, peFilePtr);
	printf("\t[+] File Alignment: 0x%x (%d bytes)\n", FileAlignment, FileAlignment);
	if (FileAlignment >= SectionAlignment)
		printf("\t\t[!] File Alignment can't be larger than page size!\n");

	// OS Version
	fread(&MajorOperatingSystemVersion, 2, 1, peFilePtr);
	fread(&MinorOperatingSystemVersion, 2, 1, peFilePtr);
	printf("\t[+] OS version: %d.%d\n", MajorOperatingSystemVersion, MinorOperatingSystemVersion);

	// Image Version
	fread(&MajorImageVersion, 2, 1, peFilePtr);
	fread(&MinorImageVersion, 2, 1, peFilePtr);
	printf("\t[+] Image version: %d.%d\n", MajorImageVersion, MinorImageVersion);

	// Subsystem Version
	fread(&MajorSubsystemVersion, 2, 1, peFilePtr);
	fread(&MinorSubsystemVersion, 2, 1, peFilePtr);
	printf("\t[+] Subsystem version: %d.%d\n", MajorSubsystemVersion, MinorSubsystemVersion);

	// Win32Version must be 0
	fread(&Win32VersionValue, 4, 1, peFilePtr);
	printf("\t[+] Win32Version: %d\n", Win32VersionValue);
	if (Win32VersionValue != 0)
		printf("\t\t[!] Win32VersionValue must be 0\n");

	// Size of image
	fread(&SizeOfImage, 4, 1, peFilePtr);
	printf("\t[+] Image Size: 0x%x (%d bytes)\n", SizeOfImage, SizeOfImage);

	// Size of headers
	fread(&SizeOfHeaders, 4, 1, peFilePtr);
	printf("\t[+] Headers Size: 0x%x (%d bytes)\n", SizeOfHeaders, SizeOfHeaders);

	// CheckSum
	fread(&CheckSum, 4, 1, peFilePtr);
	printf("\t[+] CheckSum: 0x%x\n", CheckSum);

	// Subsystem required to run this image
	fread(&Subsystem, 2, 1, peFilePtr);
	printf("\t[+] Subsystem: %d\n", Subsystem);

	//DLL Chars
	fread(&DllCharacteristics, 2, 1, peFilePtr);
	printf("\t[+] DLL Chars: 0x%x\n", DllCharacteristics);

	// Size of Stack Reserve
	fread(&SizeOfStackReserve, 4, 1, peFilePtr);
	printf("\t[+] Stack Reserve: 0x%x (%d bytes)\n", SizeOfStackReserve, SizeOfStackReserve);

	// Stack Commit
	fread(&SizeOfStackCommit, 4, 1, peFilePtr);
	printf("\t[+] Stack Commit: 0x%x (%d bytes)\n", SizeOfStackCommit, SizeOfStackCommit);

	// Heap Reserve
	fread(&SizeOfHeapReserve, 4, 1, peFilePtr);
	printf("\t[+] Heap Reserve: 0x%x (%d bytes)\n", SizeOfHeapReserve, SizeOfHeapReserve);

	// Heap Commit
	fread(&SizeOfHeapCommit, 4, 1, peFilePtr);
	printf("\t[+] Heap Commit: 0x%x (%d bytes)\n", SizeOfHeapCommit, SizeOfHeapCommit);

	// Loader flags
	fread(&LoaderFlags, 4, 1, peFilePtr);
	printf("\t[+] Loader Flags: %d\n", LoaderFlags);
	if (LoaderFlags != 0)
		printf("\t\t[!] LoaderFlags must be 0\n");

	// NumberRvaAndSizes
	fread(&NumberOfRvaAndSizes, 4, 1, peFilePtr);
	printf("\t[+] # RVA & Sizes: %d\n", NumberOfRvaAndSizes);
}	

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

	return 0;
}