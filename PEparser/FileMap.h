#pragma once

#include <Windows.h>

typedef struct _FILE_MAP
{
	HANDLE hFile;
	HANDLE hMapping;
	BYTE *pData;
	DWORD bcSize;
} FILE_MAP, *PFILE_MAP;

DWORD
FileMapPreinit(
	_Out_	PFILE_MAP	pFileMap
);

DWORD
FileMapInit(
	_Out_	PFILE_MAP	pFileMap,
	_In_	PCHAR		szFileName,
	_In_	BOOL		bWriteAccess
);

VOID
FileMapDestroy(
	_Inout_	PFILE_MAP	pFileMap
);