#pragma once

#include "FileMap.h"
#include <Windows.h>

typedef struct _PE_FILE
{
	PBYTE pData;
	DWORD bcSize;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors; //will hold pointer to the first import descriptor
} 
PE_FILE, *PPE_FILE;

DWORD
FaFromRva(
	_In_ PPE_FILE	pPeFile,
	_In_ DWORD		rvaAddress
);

PBYTE
OffsetFromRva(
	_In_ PPE_FILE	pPeFile,
	_In_ DWORD		rvaAddress
);

DWORD
PeFileInit(
	_Out_	PPE_FILE	pPeFile, 
	_In_	PBYTE		pData, 
	_In_	DWORD		cbSize
);
DWORD processFileHeader(
	_In_ PPE_FILE pPeFile
	);

DWORD processOptionalHeader(
	_In_ PPE_FILE pPeFile
	);
DWORD processSectionHeaders(
	_In_ PPE_FILE pPeFile
	);

DWORD
processExportDirectory(
_In_ PPE_FILE pPeFile
);

static
DWORD loadExportDirectory(
_In_ PPE_FILE pPeFile
);
DWORD
processImportDirectory(
_In_ PPE_FILE pPeFile
);
static
DWORD
loadImportDirectory
(
_In_ PPE_FILE pPeFile
);

DWORD
processPeFile
(
_In_ PPE_FILE pPeFile
);