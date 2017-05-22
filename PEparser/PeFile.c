#include "PeFile.h"
#include<stdio.h>
#include<stdlib.h>

#define MZ	0x5a4d
#define PE	0x4550

#define ERROR_INVALID_MZ		0x40001
#define ERROR_INVALID_PE		0x40002
#define ERROR_OUT_OF_FILE		0x40003
#define ERROR_INVALID_FORMAT	0x40004
#define ERROR_MALLOC_FAIL		0x40005
//static BOOL


static DWORD
LoadDosHeader(
	_Out_	PPE_FILE	pPeFile)
{
	pPeFile->pDosHeader = (PIMAGE_DOS_HEADER)pPeFile->pData;
	if (pPeFile->pDosHeader->e_magic != MZ)
	{
		return ERROR_INVALID_MZ;
	}
	return 0;
}

static DWORD
LoadNtHeader(
	_Out_	PPE_FILE	pPeFile)
{
	if ((DWORD)pPeFile->pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)> pPeFile->bcSize ||
		pPeFile->pDosHeader->e_lfanew < 0)
	{
		return ERROR_OUT_OF_FILE;
	}
	pPeFile->pNtHeaders = (PIMAGE_NT_HEADERS)(pPeFile->pData + pPeFile->pDosHeader->e_lfanew);

	

	if (pPeFile->pNtHeaders->Signature != PE)
	{
		return ERROR_INVALID_PE;
	}

	


	return 0;
}
//todo check, lots of check
static DWORD 
LoadSectionHeaders(
	_Inout_ PPE_FILE pPeFile)
{
	DWORD headersOffset;
	headersOffset = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pPeFile->pNtHeaders->FileHeader.SizeOfOptionalHeader;
	pPeFile->pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPeFile->pNtHeaders + headersOffset);
	return 0;
}

DWORD
FaFromRva(
	_In_ PPE_FILE	pPeFile,
	_In_ DWORD		rvaAddress)
{
	DWORD i;
	DWORD offset;
	DWORD res;

	for (i = 0; i < pPeFile->pNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (rvaAddress >= pPeFile->pSectionHeaders[i].VirtualAddress
			&& rvaAddress < pPeFile->pSectionHeaders[i].VirtualAddress + pPeFile->pSectionHeaders[i].Misc.VirtualSize
			)
		{
			offset = rvaAddress - pPeFile->pSectionHeaders[i].VirtualAddress;
			res = pPeFile->pSectionHeaders[i].PointerToRawData + offset;
			return res;
		}
	}
	return 0;
}

PBYTE
OffsetFromRva(
	_In_ PPE_FILE	pPeFile,
	_In_ DWORD		rvaAddress
)
{
	DWORD faAddress;
	faAddress = FaFromRva(pPeFile, rvaAddress);
	if (0 == faAddress)
	{
		return NULL;
	}
	return pPeFile->pData + faAddress;
}




DWORD
PeFileInit(
	_Out_	PPE_FILE	pPeFile,
	_In_	PBYTE		pData,
	_In_	DWORD		cbSize)
{
	DWORD errorCode;

	if (NULL == pData || NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
	}

	__try{

		errorCode = 0;

		pPeFile->pData = pData;
		pPeFile->bcSize = cbSize;
		errorCode = LoadDosHeader(pPeFile);
		if (errorCode != 0)
		{
			return errorCode;
		}

		errorCode = LoadNtHeader(pPeFile);
		if (errorCode != 0)
		{
			return errorCode;
		}

		errorCode = LoadSectionHeaders(pPeFile);
		if (errorCode != 0)
		{
			return errorCode;
		}

		errorCode = loadExportDirectory(pPeFile);
		if (errorCode != 0)
		{
			return errorCode;
		}

		errorCode = loadImportDirectory(pPeFile);
		if (errorCode != 0)
		{
			return errorCode;
		}

		return 0;
	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return EXCEPTION_IN_PAGE_ERROR;
	}
}


DWORD processFileHeader(
	_In_ PPE_FILE pPeFile
	)
{

	DWORD status;
	WORD characteristics;
	

	status = ERROR_SUCCESS;


	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
		
	}

	__try{

		printf("EntryPoint: RVA: 0x%x, FA: 0x%x\n",
			pPeFile->pNtHeaders->OptionalHeader.AddressOfEntryPoint,
			FaFromRva(pPeFile, pPeFile->pNtHeaders->OptionalHeader.AddressOfEntryPoint)
			);


		printf("Machine: %d\n", pPeFile->pNtHeaders->FileHeader.Machine);
		printf("Number of sections: %d\n", pPeFile->pNtHeaders->FileHeader.NumberOfSections);

		characteristics = pPeFile->pNtHeaders->FileHeader.Characteristics;

		printf("Characteristics: %#X\n", characteristics);

		if (characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		{
			//printf("Relocation info stripped\n");
			printf("IMAGE_FILE_RELOCS_STRIPPED\n");
		}

		if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			//printf("Executable\n");
			printf("IMAGE_FILE_EXECUTABLE_IMAGE\n");
		}

		if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
		{
			//printf("Line numbers stripped\n");
			printf("IMAGE_FILE_LINE_NUMS_STRIPPED\n");
		}

		if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		{
			//printf("Local symbols stripped\n");
			printf("IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
		}

		if (characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
		{
			//printf("Aggresively trim working set, should be 0\n");
			printf("IMAGE_FILE_AGGRESIVE_WS_TRIM\n");
		}

		if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		{
			//printf("Application can handle >2GB addresses\n");
			printf("IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
		}
		if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
		{
			//printf("Bytes of machine word are reversed (low), deprecated, should be 0\n");
			printf("IMAGE_FILE_BYTES_REVERSED_LO\n");
		}
		if (characteristics & IMAGE_FILE_32BIT_MACHINE)
		{
			//printf("32 bit word machine\n");
			printf("IMAGE_FILE_32BIT_MACHINE\n");
		}
		if (characteristics & IMAGE_FILE_DEBUG_STRIPPED)
		{
			//printf("Debbuging information stripped\n");
			printf("IMAGE_FILE_DEBUG_STRIPPED\n");
		}
		if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		{
			//printf("If image is on removable media, copy and run from swap file\n");
			printf("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n");
		}
		if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
		{
			//printf("If image is on network media, copy and run from the swap file\n");
			printf("IMAGE_FILE_NET_RUN_FROM_SWAP\n");
		}
		if (characteristics & IMAGE_FILE_SYSTEM)
		{
			printf("IMAGE_FILE_SYSTEM\n");
		}
		if (characteristics & IMAGE_FILE_DLL)
		{
			printf("IMAGE_FILE_DLL\n");
		}
		if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
		{
			printf("IMAGE_FILE_UP_SYSTEM_ONLY\n");
		}
		if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
		{
			printf("IMAGE_FILE_BYTES_REVERSED_HI\n");
		}
		

	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		status =  EXCEPTION_IN_PAGE_ERROR;
	}
	return status;

}

DWORD processOptionalHeader(
	_In_ PPE_FILE pPeFile
	)

{
	DWORD status;
	status = ERROR_SUCCESS;


	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;

	}

	__try{
		//Image Base
		printf("Image Base: FA: %#X, RVA: %#X\n", FaFromRva(pPeFile, pPeFile->pNtHeaders->OptionalHeader.ImageBase), pPeFile->pNtHeaders->OptionalHeader.ImageBase);
		
		//Section Alignment
		printf("SectionAlignment: %#X\n", pPeFile->pNtHeaders->OptionalHeader.SectionAlignment);
		
		//File Alignment
		printf("FileAlignment: %#X\n", pPeFile->pNtHeaders->OptionalHeader.FileAlignment);


		//Subsystem
		printf("Subsystem: %#X ", pPeFile->pNtHeaders->OptionalHeader.Subsystem);

		if (pPeFile->pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN)
		{
			printf("IMAGE_SUBSYSTEM_UNKNOWN");
		}

		if (pPeFile->pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
		{
			printf("IMAGE_SUBSYSTEM_NATIVE");
		}

		if (pPeFile->pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
		{
			printf("IMAGE_SUBSYSTEM_WINDOWS_GUI");
		}

		if (pPeFile->pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
		{
			printf("IMAGE_SUBSYSTEM_WINDOWS_CUI");
		}

		if (pPeFile->pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION)
		{
			printf("IMAGE_SUBSYSTEM_EFI_APPLICATION");
		}

		printf("\n");

		//NumberOfRvaAndSizes

		printf("NumberOfRvaAndSizes: %d", pPeFile->pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);



	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		status=  EXCEPTION_IN_PAGE_ERROR;
	}
	return status;
}


DWORD processSectionHeaders(
	_In_ PPE_FILE pPeFile
	)

{
	DWORD status;
	WORD nrOfSections;
	WORD i, nameIndex;

	status = ERROR_SUCCESS;



	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;

	}

	__try{

		printf("Sections:\n");

		nrOfSections = pPeFile->pNtHeaders->FileHeader.NumberOfSections;
		for (i = 0; i < nrOfSections; i++)
		{
			//Name
			printf("Section name: ");
			//should handle longer names, something with a string table
			//or just %.8s
			nameIndex = 0;
			while (nameIndex < IMAGE_SIZEOF_SHORT_NAME && pPeFile->pSectionHeaders[i].Name[nameIndex] != '\0')
			{
				printf("%c", pPeFile->pSectionHeaders[i].Name[nameIndex]);
				nameIndex++;
			}

			printf("\n");

			//Virtual size
			printf("Virtual size: %#X\n", pPeFile->pSectionHeaders[i].Misc.VirtualSize);

			//Raw size
			printf("Raw size: %#X\n", pPeFile->pSectionHeaders[i].SizeOfRawData);

			//Virtual address

			fprintf(stdout, "Virtual address: RVA: %#X, FA: %#X\n", pPeFile->pSectionHeaders[i].VirtualAddress, FaFromRva(pPeFile, pPeFile->pSectionHeaders[i].VirtualAddress));

			//Raw address
			fprintf(stdout, "Raw address: %#X\n", pPeFile->pSectionHeaders[i].PointerToRawData);



		}
		


	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		status = EXCEPTION_IN_PAGE_ERROR;
	}
	return status;
}


static
DWORD loadExportDirectory(
	_In_ PPE_FILE pPeFile
	)
{
	DWORD status;
	DWORD RVAofExportDirectory;
	DWORD sizeOfExportDirectory;
	DWORD faOfExportDirectory;

	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
	}

	pPeFile->pExportDirectory = NULL;
	status = ERROR_SUCCESS;

	RVAofExportDirectory = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (0 == pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		goto CleanUp;
	}

	sizeOfExportDirectory = pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	faOfExportDirectory = FaFromRva(pPeFile, RVAofExportDirectory);

	if (0 == faOfExportDirectory)
	{
		status = ERROR_OUT_OF_FILE;
		goto CleanUp;
	}

	if (faOfExportDirectory + sizeOfExportDirectory >= pPeFile->bcSize)
	{
		status = ERROR_OUT_OF_FILE;
		goto CleanUp;
	}

	//more validate
	pPeFile->pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pPeFile->pData + faOfExportDirectory);

CleanUp:
	return status;

}

static
DWORD 
checkString(
_In_ PPE_FILE pPeFile,
DWORD offset
)
{




	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;

	}


	while (offset < pPeFile->bcSize && pPeFile->pData[offset] != '\0')
		offset++;

	if (offset >= pPeFile->bcSize)
		return ERROR_OUT_OF_FILE;
	
	return ERROR_SUCCESS;

}


DWORD 
processExportDirectory(
_In_ PPE_FILE pPeFile
)
{
	DWORD status;
	DWORD base;
	DWORD addrIndex;
	DWORD nrOfFunctions;
	DWORD* addressOfFunctions;		//pointer to function list
	DWORD* addressOfNames;			//pointer to name list
	WORD* addressOfNameOrdinals;	//pointer to array of nameOrdinals
	BOOL* isExportedByName;
	DWORD fileNameOffset;
	DWORD i;
	status = ERROR_SUCCESS;
	isExportedByName = NULL;


	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;

	}

	__try{

		if (NULL == pPeFile->pExportDirectory)
		{
			fprintf(stdout,"No export directory\n");
			return ERROR_SUCCESS;
		}

		base = pPeFile->pExportDirectory->Base;

		nrOfFunctions = pPeFile->pExportDirectory->NumberOfFunctions;

		fprintf(stdout,"\nExport directory\nNumber of exported functions:%d\n", pPeFile->pExportDirectory->NumberOfFunctions);

		if (0 == pPeFile->pExportDirectory->NumberOfFunctions)
		{
			goto CleanUp;
		}
		
		isExportedByName = malloc(sizeof(BOOL)* (pPeFile->pExportDirectory->NumberOfFunctions+1));
		if (NULL == isExportedByName)
		{
			status = ERROR_MALLOC_FAIL;
			goto CleanUp;
		}
		for (i = 0; i < pPeFile->pExportDirectory->NumberOfFunctions; i++)
			isExportedByName[i] = FALSE;

		//validate
		addressOfFunctions = (DWORD*)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfFunctions);

		if (NULL == addressOfFunctions)
		{
			status = ERROR_OUT_OF_FILE;
			goto CleanUp;
		}

		addressOfNames = (DWORD*)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfNames);
		if (NULL == addressOfNames)
		{
			status = ERROR_OUT_OF_FILE;
			goto CleanUp;
		}

		addressOfNameOrdinals = (WORD*)OffsetFromRva(pPeFile, pPeFile->pExportDirectory->AddressOfNameOrdinals);

		if (NULL == addressOfNameOrdinals)
		{
			status = ERROR_OUT_OF_FILE;
			goto CleanUp;
		}


		for (addrIndex = 0; addrIndex < pPeFile->pExportDirectory->NumberOfNames; addrIndex++)
		{


			//some validation needed

			

			fprintf(stdout, "\nOrdinal: %d, ", addressOfNameOrdinals[addrIndex] + base);
			//more validation
			fprintf(stdout, "Function address: RVA: %#X, FA: %#X, ", addressOfFunctions[addressOfNameOrdinals[addrIndex]], FaFromRva(pPeFile, addressOfFunctions[addressOfNameOrdinals[addrIndex]])); //more validation

			fileNameOffset = FaFromRva(pPeFile, addressOfNames[addrIndex]);
			status = checkString(pPeFile, fileNameOffset);
			
			if (status != ERROR_SUCCESS)
				goto CleanUp;

			fprintf(stdout, "Function name: %s", &pPeFile->pData[fileNameOffset]);

			isExportedByName[addressOfNameOrdinals[addrIndex]] = TRUE;

		}



		for (addrIndex = 0; addrIndex < nrOfFunctions; addrIndex++)
		{

			if (isExportedByName[addrIndex] == FALSE){
				fprintf(stdout, "\nOrdinal: %d\n", addrIndex + base);
				fprintf(stdout, "Function address: RVA: %#X, FA: %#X", addressOfFunctions[addrIndex], FaFromRva(pPeFile, addressOfFunctions[addrIndex]));
			}

		}





	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		status = EXCEPTION_IN_PAGE_ERROR;
	}

CleanUp:

	if (NULL != isExportedByName)
	{
		free(isExportedByName);
		isExportedByName = NULL;
	}

	return status;
}

static
DWORD
loadImportDirectory
(
_In_ PPE_FILE pPeFile
)
{
	DWORD status;
	DWORD faOfImportDirectory;

	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
	}

	pPeFile->pImportDescriptors = NULL;
	status = ERROR_SUCCESS;
	faOfImportDirectory = 0;

	faOfImportDirectory = FaFromRva(pPeFile, pPeFile->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (0 == faOfImportDirectory || faOfImportDirectory >= pPeFile->bcSize)
	{
		status = ERROR_OUT_OF_FILE;
		return status;
	}

	pPeFile->pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)(&(pPeFile->pData[faOfImportDirectory]));

	return status;
}


static
DWORD
loadNextImportDescriptor(
_In_ PPE_FILE pPeFile,
_In_ PIMAGE_IMPORT_DESCRIPTOR currentImportDescriptor,
_Out_ PIMAGE_IMPORT_DESCRIPTOR* nextImportDescriptor
)
{
	DWORD status;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

	status = ERROR_SUCCESS;
	importDescriptor = NULL;

	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if (NULL == nextImportDescriptor)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if ((PBYTE)currentImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR) < pPeFile->pData)	//comparing pointers, should be ok
	{
		//somehow next import descriptor begins before the peFile data, return error
		status = ERROR_OUT_OF_FILE;
		goto CleanUp;
	}

	if ((PBYTE)currentImportDescriptor + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) >= pPeFile->pData + pPeFile->bcSize)
	{
		status = ERROR_OUT_OF_FILE;
		goto CleanUp;
	}

	//next import descriptor should be inside the file now

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(currentImportDescriptor + 1); // should jump 1 struct to the right

	//check if last of ImportDescriptor Array
	if (
		importDescriptor->FirstThunk == 0 &&
		0 == importDescriptor->Characteristics &&
		0 == importDescriptor->ForwarderChain &&
		0 == importDescriptor->Name &&
		0 == importDescriptor->OriginalFirstThunk &&
		0 == importDescriptor->TimeDateStamp
		)
	{
		importDescriptor = NULL;
	}
	*nextImportDescriptor = importDescriptor;


CleanUp:
	return status;

}

DWORD
processImportDirectory(
_In_ PPE_FILE pPeFile
)
{
	DWORD status;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	PIMAGE_IMPORT_DESCRIPTOR nextImportDescriptor;
	DWORD moduleNameOffset;
	DWORD imageThunkDataOffset;
	DWORD functionNameOffset;

	status = ERROR_SUCCESS;
	importDescriptor = NULL;
	nextImportDescriptor = NULL;

	if (NULL == pPeFile)
	{
		return ERROR_INVALID_PARAMETER;
	}

	__try{

		importDescriptor = pPeFile->pImportDescriptors;

		while (NULL != importDescriptor)
		{


			//process descriptor


			moduleNameOffset = FaFromRva(pPeFile, importDescriptor->Name);

			if (0 == moduleNameOffset)
			{
				status = ERROR_OUT_OF_FILE;
				goto CleanUp;
			}

			status = checkString(pPeFile, moduleNameOffset);

			if (ERROR_SUCCESS != status)
			{
				goto CleanUp;
			}
			fprintf(stdout, "Name of module: %s\n", &(pPeFile->pData[moduleNameOffset]));


			if (0 != importDescriptor->OriginalFirstThunk)
			{

				imageThunkDataOffset = FaFromRva(pPeFile, importDescriptor->OriginalFirstThunk);
				if (0 == imageThunkDataOffset)
				{
					status = ERROR_OUT_OF_FILE;
					goto CleanUp;
				}
			}

			else
			{
				imageThunkDataOffset = FaFromRva(pPeFile, importDescriptor->FirstThunk);
				if (0 == imageThunkDataOffset)
				{
					status = ERROR_OUT_OF_FILE;
					goto CleanUp;
				}
			}
			while (imageThunkDataOffset + sizeof(IMAGE_THUNK_DATA) < pPeFile->bcSize  && pPeFile->pData[imageThunkDataOffset+sizeof(WORD)] != 0)
			{

				if (((PIMAGE_THUNK_DATA)(&(pPeFile->pData[imageThunkDataOffset])))->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					//imported by ordinal
					fprintf(stdout, "By ordinal: %d\n", ((PIMAGE_THUNK_DATA)(&(pPeFile->pData[imageThunkDataOffset])))->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32);
				}
				else
				{
					// by name

					functionNameOffset = FaFromRva(pPeFile, ((PIMAGE_THUNK_DATA)(&(pPeFile->pData[imageThunkDataOffset])))->u1.Function);

					if (0 == functionNameOffset)
					{
						status = ERROR_OUT_OF_FILE;
						goto CleanUp;
					}

					functionNameOffset += sizeof(WORD); //skip Hint

					status = checkString(pPeFile, functionNameOffset);

					if (ERROR_SUCCESS != status)
					{
						goto CleanUp;
					}

					fprintf(stdout, "By name: %s\n", &(pPeFile->pData[functionNameOffset]));

				}
				imageThunkDataOffset += sizeof(IMAGE_THUNK_DATA);
			}


			fprintf(stdout, "\n");


			status = loadNextImportDescriptor(pPeFile, importDescriptor, &nextImportDescriptor);

			if (status != ERROR_SUCCESS)
			{
				goto CleanUp;
			}

			importDescriptor = nextImportDescriptor;
		}


	}
	__except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		status = EXCEPTION_IN_PAGE_ERROR;
	}

CleanUp:
	return status;
}


DWORD
processPeFile
(
_In_ PPE_FILE pPeFile
)
{
	DWORD status;

	status = ERROR_SUCCESS;

	status=processFileHeader(pPeFile);

	if (ERROR_SUCCESS != status)
	{
		goto CleanUp;
	}

	status = processOptionalHeader(pPeFile);
	if (ERROR_SUCCESS != status)
	{
		goto CleanUp;
	}
	status = processSectionHeaders(pPeFile);
	if (ERROR_SUCCESS != status)
	{
		goto CleanUp;
	}

	status = processExportDirectory(pPeFile);
	if (ERROR_SUCCESS != status)
	{
		goto CleanUp;
	}

	status = processImportDirectory(pPeFile);
	if (ERROR_SUCCESS != status)
	{
		goto CleanUp;
	}
CleanUp:
	return status;
}