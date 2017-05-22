#include "FileMap.h"
#include "PeFile.h"
#include <stdio.h>

VOID
PrintUsage()
{
	printf("Parameters: <pefile>\n");
	printf("	<pefile>	- PE file to parse.\n");
}

DWORD
main(int argc, char **argv)
{
	DWORD error;
	FILE_MAP fileMap;
	BOOL bInitialized;
	PE_FILE peFile;
	FILE* file;

	file = NULL;

	if (argc < 2)
	{
		PrintUsage();
		return 1;
	}



	error = ERROR_SUCCESS;
	bInitialized = FALSE;
	
	error = FileMapPreinit(&fileMap);
	if (ERROR_SUCCESS != error)
	{
		printf("FileMapPreinit failed: %x\n", error);
		goto cleanup;
	}

	error = FileMapInit(&fileMap, argv[1], FALSE);
	if (ERROR_SUCCESS != error)
	{
		printf("FileMapInit failed: %x\n", error);
		goto cleanup;
	}
	bInitialized = TRUE;

	// Use mapping
	error = PeFileInit(
		&peFile,
		fileMap.pData,
		fileMap.bcSize
	);
	if (error != 0)
	{
		printf("PeFileInit failed: 0x%x.\n", error);
		goto cleanup;
	}


	
	error = processPeFile(&peFile);

	if (error != ERROR_SUCCESS)
	{
		printf("Error: %#x", error);
	}

cleanup:
	if (bInitialized)
	{
		FileMapDestroy(&fileMap);
	}
	return ERROR_SUCCESS;
}