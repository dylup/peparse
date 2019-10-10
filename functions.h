unsigned short sections;
unsigned int elfaNew;
unsigned int importTableRVA;
unsigned int sizeOfImportTable;
unsigned int imageBase;

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
	unsigned int signature;					// 4 bytes
	unsigned short Machine;					// 2 bytes
	unsigned short NumberOfSections;		// 2 bytes
	unsigned int TimeDateStamp;				// 4 bytes
	unsigned int PtrToSymbolTable;			// 4 bytes
	unsigned int NumberOfSymbols;			// 4 bytes
	unsigned short SizeOfOptionalHeader;	// 2 bytes
	unsigned short Characteristics;			// 2 bytes
											// 24 total bytes
	
	printf("[!] IMAGE_FILE_HEADER\n");

	// get to header
	fseek(peFilePtr, 0x3c, SEEK_SET);
	unsigned int elfanew;
	fread(&elfanew, sizeof(int), 1, peFilePtr);
	printf("[!] elfanew: 0x%08x\n", elfanew);
	fseek(peFilePtr, elfanew, SEEK_SET);
	elfaNew = elfanew;
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
	sections = NumberOfSections;
	
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
	unsigned int NumberOfRVAAndSizes;				// 4 bytes

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
	imageBase = ImageBase;

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

	// NumberRVAAndSizes
	fread(&NumberOfRVAAndSizes, 4, 1, peFilePtr);
	printf("\t[+] # RVA & Sizes: %d\n", NumberOfRVAAndSizes);
}	

void parseDataDirectories(FILE *peFilePtr)
{
	unsigned int ExportTableRVA;					// 4 bytes
	unsigned int SizeOfExportDirectory;				// 4 bytes
	unsigned int ImportTableRVA;					// 4 bytes
	unsigned int SizeOfImportDirectory;				// 4 bytes
	unsigned int ResourceTableRVA;					// 4 bytes
	unsigned int SizeOfResourceDirectory;			// 4 bytes
	unsigned int ExceptionTableRVA;					// 4 bytes
	unsigned int SizeOfExceptionDirectory;			// 4 bytes
	unsigned int CertificateTableAddr;				// 4 bytes
	unsigned int SizeOfSecurityDirectory;			// 4 bytes
	unsigned int BaseRelocationTableRVA;			// 4 bytes
	unsigned int SizeOfBaseRelocationDirectory;		// 4 bytes
	unsigned int DebugRVA;							// 4 bytes
	unsigned int SizeOfDebugDirectory;				// 4 bytes
	unsigned int CopyrightNoteRVA;					// 4 bytes
	unsigned int SizeOfCopyRightNote;				// 4 bytes
	unsigned int GlobalPtrRVA;						// 4 bytes
	unsigned int Unused;							// 4 bytes
	unsigned int TLSTableRVA;						// 4 bytes
	unsigned int SizeOfTLSDirectory;				// 4 bytes
	unsigned int LoadConfigTableRVA;				// 4 bytes
	unsigned int SizeOfLoadConfigDirectory;			// 4 bytes
	unsigned int BoundImportRVA;					// 4 bytes
	unsigned int SizeOfBoundImportDirectory;		// 4 bytes
	unsigned int ImportAddressTableRVA;				// 4 bytes
	unsigned int SizeOfImportAddressDirectory;		// 4 bytes
	unsigned int DelayImportDescriptorRVA;			// 4 bytes
	unsigned int SizeOfDelayImportDirectory;		// 4 bytes
	unsigned int CLRRuntimeHeaderRVA;				// 4 bytes
	unsigned int SizeOfCOMHeader;					// 4 bytes
	unsigned int Zero1;								// 4 bytes
	unsigned int Zero2;								// 4 bytes

	printf("[!] Data Directories:\n");
	
	fread(&ExportTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Export Table RVA: 0x%08x\n", ExportTableRVA);

	fread(&SizeOfExportDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Export Directory: 0x%x (%d bytes)\n", SizeOfExportDirectory, SizeOfExportDirectory);

	fread(&ImportTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Import Table RVA: 0x%08x\n", ImportTableRVA);
	importTableRVA = ImportTableRVA;

	fread(&SizeOfImportDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Import Directory: 0x%x (%d bytes)\n", SizeOfImportDirectory, SizeOfImportDirectory);
	sizeOfImportTable = SizeOfImportDirectory;

	fread(&ResourceTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Resource Table RVA: 0x%08x\n", ResourceTableRVA);

	fread(&SizeOfResourceDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Resource Directory: 0x%x (%d bytes)\n", SizeOfResourceDirectory, SizeOfResourceDirectory);

	fread(&ExceptionTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Exception Table RVA: 0x%08x\n", ExceptionTableRVA);

	fread(&SizeOfExceptionDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Exception Directory: 0x%x (%d bytes)\n", SizeOfExceptionDirectory, SizeOfExceptionDirectory);

	fread(&CertificateTableAddr, 4, 1, peFilePtr);
	printf("\t[+] Certificate Table Address: 0x%08x\n", CertificateTableAddr);

	fread(&SizeOfSecurityDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Security Directory: 0x%x (%d bytes)\n", SizeOfSecurityDirectory, SizeOfSecurityDirectory);

	fread(&BaseRelocationTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Base Relocation Table RVA: 0x%08x\n", BaseRelocationTableRVA);

	fread(&SizeOfBaseRelocationDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Base Relocation Directory: 0x%x (%d bytes)\n", SizeOfBaseRelocationDirectory, SizeOfBaseRelocationDirectory);

	fread(&DebugRVA, 4, 1, peFilePtr);
	printf("\t[+] Debug RVA: 0x%08x\n", DebugRVA);

	fread(&SizeOfDebugDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Debug Directory: 0x%x (%d bytes)\n", SizeOfDebugDirectory, SizeOfDebugDirectory);

	fread(&CopyrightNoteRVA, 4, 1, peFilePtr);
	printf("\t[+] Copyright Note RVA: 0x%08x\n", CopyrightNoteRVA);

	fread(&SizeOfCopyRightNote, 4, 1, peFilePtr);
	printf("\t[+] Size of Copyright Note: 0x%x (%d bytes)\n", SizeOfCopyRightNote, SizeOfCopyRightNote);

	fread(&GlobalPtrRVA, 4, 1, peFilePtr);
	printf("\t[+] Global Pointer RVA: 0x%08x\n", GlobalPtrRVA);

	fread(&Unused, 4, 1, peFilePtr);
	printf("\t[+] Unused: 0x%04x\n", Unused);
	if (Unused != 0)
		printf("\t\t[?] Field is normally unused\n");

	fread(&TLSTableRVA, 4, 1, peFilePtr);
	printf("\t[+] TLS Table RVA: 0x%08x\n", TLSTableRVA);

	fread(&SizeOfTLSDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of TLS Directory: 0x%x (%d bytes)\n", SizeOfTLSDirectory, SizeOfTLSDirectory);

	fread(&LoadConfigTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Load Config Table RVA: 0x%08x\n", LoadConfigTableRVA);

	fread(&SizeOfLoadConfigDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Load Config Directory: 0x%x (%d bytes)\n", SizeOfLoadConfigDirectory, SizeOfLoadConfigDirectory);

	fread(&BoundImportRVA, 4, 1, peFilePtr);
	printf("\t[+] Bound Import RVA: 0x%08x\n", BoundImportRVA);

	fread(&SizeOfBoundImportDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Bound Import Directory: 0x%x (%d bytes)\n", SizeOfBoundImportDirectory, SizeOfBoundImportDirectory);

	fread(&ImportAddressTableRVA, 4, 1, peFilePtr);
	printf("\t[+] Import Address Table RVA: 0x%08x\n", ImportAddressTableRVA);

	fread(&SizeOfImportAddressDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Import Address Directory: 0x%x (%d bytes)\n", SizeOfImportAddressDirectory, SizeOfImportAddressDirectory);

	fread(&DelayImportDescriptorRVA, 4, 1, peFilePtr);
	printf("\t[+] Delay Import Descriptor RVA: 0x%08x\n", DelayImportDescriptorRVA);

	fread(&SizeOfDelayImportDirectory, 4, 1, peFilePtr);
	printf("\t[+] Size of Delay Import Directory: 0x%x (%d bytes)\n", SizeOfDelayImportDirectory, SizeOfDelayImportDirectory);

	fread(&CLRRuntimeHeaderRVA, 4, 1, peFilePtr);
	printf("\t[+] CLR Runtime RVA: 0x%08x\n", CLRRuntimeHeaderRVA);

	fread(&SizeOfCOMHeader, 4, 1, peFilePtr);
	printf("\t[+] Size of COM Header: 0x%x (%d bytes)\n", SizeOfCOMHeader, SizeOfCOMHeader);

	fread(&Zero1, 4, 1, peFilePtr);
	printf("\t[+] Reserved 1: 0x%04x\n", Zero1);

	fread(&Zero2, 4, 1, peFilePtr);
	printf("\t[+] Reserved 2: 0x%04x\n", Zero2);
}

void parseSectionTable(FILE *peFilePtr)
{
	char name[8] = {'\0'};					// 8 bytes
	unsigned int VirtualSize;				// 4 bytes
	unsigned int VirtualAddress;			// 4 bytes
	unsigned int SizeOfRawData;				// 4 bytes
	unsigned int PointerToRawData;			// 4 bytes
	unsigned int PointerToRelocations;		// 4 bytes
	unsigned int PointerToLineNumbers;		// 4 bytes
	unsigned short NumberOfRelocations;		// 2 bytes
	unsigned short NumberOfLineNumbers;		// 2 bytes
	unsigned int Characteristics;			// 4 bytes
											// 40 bytes

	int i;
	printf("[!] SECTION_TABLE:\n");

	//fseek(peFilePtr, 0x80, SEEK_CUR);
	for (i = 0;  i < sections; i++)
	{
		// first section at 0xf8
		fread(name, 8, 1, peFilePtr);
		printf("\t[+] %s Section:\n", name);

		fread(&VirtualSize, 4, 1, peFilePtr);
		printf("\t\t[+] Virtual Size: 0x%x (%d bytes)\n", VirtualSize, VirtualSize);

		fread(&VirtualAddress, 4, 1, peFilePtr);
		printf("\t\t[+] Virtual Address: 0x%08x\n", VirtualAddress);

		fread(&SizeOfRawData, 4, 1, peFilePtr);
		printf("\t\t[+] Size of Raw Data: 0x%x (%d bytes)\n", SizeOfRawData, SizeOfRawData);

		fread(&PointerToRawData, 4, 1, peFilePtr);
		printf("\t\t[+] Pointer to Raw Data: 0x%08x\n", PointerToRawData);

		fread(&PointerToRelocations, 4, 1, peFilePtr);
		printf("\t\t[+] Pointer to Relocations: 0x%08x\n", PointerToRelocations);

		fread(&PointerToLineNumbers, 4, 1, peFilePtr);
		printf("\t\t[+] Pointer to Line Numbers: 0x%08x\n", PointerToLineNumbers);

		fread(&NumberOfRelocations, 2, 1, peFilePtr);
		printf("\t\t[+] Number of Relocations: %d\n", NumberOfRelocations);

		fread(&NumberOfLineNumbers, 2, 1, peFilePtr);
		printf("\t\t[+] Number of Line Numbers: %d\n", NumberOfLineNumbers);

		fread(&Characteristics, 4, 1, peFilePtr);
		printf("\t\t[+] Characteristics: 0x%x\n", Characteristics);
	}

}