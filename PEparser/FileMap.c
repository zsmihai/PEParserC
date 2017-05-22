#include "FileMap.h"
#include<stdio.h>
DWORD
FileMapPreinit(
	_Out_	PFILE_MAP	pFileMap)
{
	if (NULL == pFileMap)
	{
		return ERROR_INVALID_PARAMETER;
	}

	pFileMap->hFile = INVALID_HANDLE_VALUE;
	pFileMap->hMapping = NULL;
	pFileMap->pData = NULL;
	pFileMap->bcSize = 0;

	return ERROR_SUCCESS;
}

DWORD
FileMapInit(
	_Out_	PFILE_MAP	pFileMap,
	_In_	PCHAR		szFileName,
	_In_	BOOL		bWriteAccess)
{
	DWORD errorCode = ERROR_SUCCESS;
	DWORD fileAccess;
	DWORD flProtect;
	DWORD mappingAccess;

	if (bWriteAccess == FALSE) {
		fileAccess = GENERIC_READ;
		flProtect = PAGE_READONLY;
		mappingAccess = FILE_MAP_READ;
	}
	else {
		fileAccess = GENERIC_READ | GENERIC_WRITE;
		flProtect = PAGE_READWRITE;
		mappingAccess = FILE_MAP_ALL_ACCESS;
	}

	pFileMap->hFile = CreateFileA(
		szFileName,
		fileAccess,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (INVALID_HANDLE_VALUE == pFileMap->hFile) {
		errorCode = GetLastError();
		goto cleanup;
	}

	pFileMap->bcSize = GetFileSize(pFileMap->hFile, NULL);

	pFileMap->hMapping = CreateFileMapping(
		pFileMap->hFile,		//_In_     HAN                hFile,
		NULL,					//_In_opt_ LPSECURITY_ATTRIBUTES lpAttributes,
		flProtect,				//_In_     DWORD                 flProtect,
		0,						//_In_     DWORD                 dwMaximumSizeHigh,
		0,						//_In_     DWORD                 dwMaximumSizeLow,
		NULL					//_In_opt_ LPCTSTR               lpName
	);
	if (NULL == pFileMap->hMapping) {
		errorCode = GetLastError();
		goto cleanup;
	}

	pFileMap->pData = MapViewOfFile(
		pFileMap->hMapping,			//_In_ HANDLE hFileMappingObject,
		mappingAccess,				//_In_ DWORD  dwDesiredAccess,
		0,							//_In_ DWORD  dwFileOffsetHigh,
		0,							//_In_ DWORD  dwFileOffsetLow,
		0							//_In_ SIZE_T dwNumberOfBytesToMap
	);
	if (NULL == pFileMap->pData) {
		errorCode = GetLastError();
		goto cleanup;
	}

cleanup:
	if (errorCode == ERROR_SUCCESS) {
		return errorCode;
	}
	FileMapDestroy(pFileMap);
	return errorCode;
}

VOID
FileMapDestroy(
	_Inout_	PFILE_MAP	pFileMap)
{
	if (NULL != pFileMap->pData)
	{
		UnmapViewOfFile(pFileMap->pData);
		pFileMap->pData = NULL;
	}
	if (NULL != pFileMap->hMapping)
	{
		CloseHandle(pFileMap->hMapping);
		pFileMap->hMapping = NULL;
	}
	if (INVALID_HANDLE_VALUE != pFileMap->hFile)
	{
		CloseHandle(pFileMap->hFile);
		pFileMap->hFile = INVALID_HANDLE_VALUE;
	}
	pFileMap->bcSize = 0;
}